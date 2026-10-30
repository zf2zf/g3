/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2：携带 body 的完整（非 preview）上报路径。
//!
//! 与 h1 版差异：上报的"HTTP 响应"由降级序列化（`serialize_for_adapter()`）
//! 的 h1 形式头 + chunked 重编码后的 h2 body 组成，因此 ICAP 请求的
//! `Encapsulated:` 偏移需按降级后各段实际字节长度计算：
//! `req-hdr=0, res-hdr=<请求头长度>, res-body=<请求头+响应头长度>`。
//!
//! 两个入口：
//! - [`H2ResponseAdapter::xfer_small_body`]：preview 场景下上游 body
//!   一次性全部到齐（小于预览上限），直接聚合成一个完整请求发出；
//! - [`H2ResponseAdapter::xfer_without_preview`]：不启用 preview 时，
//!   以双向流方式边收 h2 body 边以 chunked 写给 ICAP。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use h2::RecvStream;
use http::{Request, Response};

use g3_h2::{
    H2PreviewData, H2StreamToChunkedTransfer, H2StreamToChunkedTransferError, RequestExt,
    ResponseExt,
};
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse, H2RespmodAdaptationError,
    H2ResponseAdapter, H2SendResponseToClient, RespmodAdaptationEndState,
    RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> H2ResponseAdapter<I> {
    /// 构造"完整上报（含全部 body）"的 ICAP 请求头。
    ///
    /// 布局：ICAP 状态行+扩展头（本函数产物），随后依次是降级序列化的
    /// 请求头和响应头。偏移量以"消息体起点（空行后）"为 0 计算：
    /// req-hdr=0，res-hdr=请求头字节数，res-body=请求头+响应头字节数，
    /// 即 body 从降级头文本之后开始，且按 chunked 编码传输。
    fn build_forward_all_request(
        &self,
        http_req_hdr_len: usize,
        http_rsp_hdr_len: usize,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, res-hdr={http_req_hdr_len}, res-body={}\r\n",
            http_req_hdr_len + http_rsp_hdr_len
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 小 body 一次性上报：preview 阶段发现数据已读到结尾（结束帧且无
    /// trailer 待发），无需双向流，把已缓存的预览数据当作全部 body 直接
    /// 写入 ICAP 后等待最终响应。
    pub(super) async fn xfer_small_body<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &Request<()>,
        http_response: Response<()>,
        preview_data: H2PreviewData,
        ups_body: RecvStream,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        // 降级序列化：把 h2 的请求/响应头各自转成 HTTP/1.1 头部文本
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header =
            self.build_forward_all_request(http_req_header.len(), http_rsp_header.len());

        // 一次性发送 ICAP 头 + 封装的"HTTP 请求报文头 + HTTP 响应报文头"
        // （write_all_vectored 聚合多个 IoSlice，避免多次系统调用）
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
            ])
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;

        // body：已缓存的预览数据按 chunked 编码全部写出（含 0 长度终止块）
        preview_data
            .icap_write_all_as_chunked(icap_w)
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;
        // h2  trailer（若有）转成 chunked 的末尾 trailer 段发给 ICAP
        self.recv_send_trailer(ups_body).await?;
        self.icap_connection.mark_writer_finished();
        state.mark_ups_recv_all();

        // 等待并解析 ICAP 最终响应；本流程未声明 Preview，
        // 因此 204/206（预览相关状态码）都是非法应答
        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            204 | 206 => {
                return Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }

        match rsp.payload {
            // ICAP 只回了 200 却没有封装的 HTTP 响应：视为错误（由 recv_response 处理）
            IcapRespmodResponsePayload::NoPayload => {
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            // 改写后的响应头（无 body 或 body 为空）：直接转成 h2 发给客户端
            IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                self.handle_icap_http_response_without_body(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_send_response,
                )
                .await
            }
            // 改写后的响应带 body：本流程中 ICAP 请求已写完，从 ICAP 连接
            // 读完 chunked 响应体再重编码为 h2 发给客户端
            IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                self.handle_icap_http_response_with_body_after_transfer(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_send_response,
                )
                .await
            }
        }
    }

    /// body 数据已提前全部发完后，从 h2 上游 `RecvStream` 接收 trailer
    /// （若有）并改写成 chunked 末段的 trailer 形式发给 ICAP，同时做
    /// idle 检查。`without_data` 表示不再搬运任何数据块。
    async fn recv_send_trailer(
        &mut self,
        mut ups_body: RecvStream,
    ) -> Result<(), H2RespmodAdaptationError> {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        let mut trailer_transfer = H2StreamToChunkedTransfer::without_data(
            &mut ups_body,
            &mut self.icap_connection.writer,
        );

        loop {
            tokio::select! {
                biased;

                r = &mut trailer_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2RespmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvTrailerFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if trailer_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if trailer_transfer.no_cached_data() {
                                Err(H2RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H2RespmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        trailer_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// 不启用 preview 的全量上报：发送 ICAP 头与降级头后，以双向流方式
    /// 边从 h2 上游收数据帧、chunked 重编码写给 ICAP，边等 ICAP 返回响应
    /// （ICAP 通常收完才回 200，但允许其提前返回/提前出错）。
    pub(super) async fn xfer_without_preview<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &Request<()>,
        http_response: Response<()>,
        mut ups_body: RecvStream,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header =
            self.build_forward_all_request(http_req_header.len(), http_rsp_header.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
            ])
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;

        // 双向流上行：h2 数据帧 -> chunked 编码写入 ICAP（yield_size 控制
        // 每次分块大小，并集成 idle 检测）
        let mut body_transfer = H2StreamToChunkedTransfer::new(
            &mut ups_body,
            &mut self.icap_connection.writer,
            self.copy_config.yield_size(),
        );
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        // 并发：续传 body + 接收 ICAP 响应；若 ICAP 提前返回，body 可能未传完
        let rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        if body_transfer.finished() {
            state.mark_ups_recv_all();
        }

        match rsp.payload {
            // 无封装负载：ICAP 侧读取已完成，直接把连接标记结束并报错处理
            IcapRespmodResponsePayload::NoPayload => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            // 只有改写响应头：读完 ICAP 头即可把改写结果（无 body）发给客户端
            IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_response_without_body(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_send_response,
                )
                .await
            }
            IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    // 上游 body 已全部传给 ICAP：直接单向读取改写响应体
                    //（chunked -> h2）并发给客户端
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_response_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_send_response,
                    )
                    .await
                } else {
                    // ICAP 提前返回改写响应而上游 body 还没传完：进入
                    // 双向流阶段——一边续传剩余 h2 body 给 ICAP（chunked），
                    // 一边把 ICAP 的改写响应（chunked）解码成 h2 发给客户端
                    let mut bidirectional_transfer = BidirectionalRecvHttpResponse {
                        icap_reader: &mut self.icap_connection.reader,
                        copy_config: self.copy_config,
                        http_body_line_max_size: self.http_body_line_max_size,
                        http_trailer_max_size: self.http_trailer_max_size,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(state, &mut body_transfer, http_response, clt_send_response)
                        .await?;
                    let icap_read_finished = bidirectional_transfer.icap_read_finished;
                    // 只有上行写完且下行读完，ICAP 连接才干净，可回池复用
                    if body_transfer.finished() {
                        state.mark_ups_recv_all();
                        self.icap_connection.mark_writer_finished();
                        if icap_read_finished {
                            self.icap_connection.mark_reader_finished();
                            if rsp.keep_alive {
                                self.icap_client.save_connection(self.icap_connection);
                            }
                        }
                    }
                    Ok(r)
                }
            }
        }
    }
}
