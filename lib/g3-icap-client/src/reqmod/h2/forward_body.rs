/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 带 body 的 h2 REQMOD 上报（无 preview 全量 / 小体一次性两条路径）。
//!
//! 与 h1 版的差异：
//! - 封装的 HTTP 请求头同样由 h2 pseudo-header 降级序列化成 HTTP/1.1 头块，
//!   `Encapsulated: req-hdr=0, req-body=<len>` 中的 `<len>` 是这段**降级头块**
//!   的字节数，即 body 在封装对象中的起始偏移（`req-body` 指向 chunked 数据）；
//! - body 不是原始 TCP 流而是 h2 `RecvStream` 数据帧，需经
//!   `H2StreamToChunkedTransfer` 重编码为 chunked（末尾 `0\r\n` 终止块 +
//!   h2 trailer 转成 chunked trailer）后写入 ICAP 连接。
//!
//! 两条路径：
//! - `xfer_without_preview`：不启用 preview，上行 body
//!   与下行 ICAP 响应**并发**进行（双向流，见 `bidirectional.rs`）；
//! - `xfer_small_body`：preview 阶段发现 body 未达预览上限（已读完），
//!   于是把整段 body 一次性上报，无需等待 100-continue。

use std::io::{IoSlice, Write};

use bytes::{BufMut, Bytes};
use h2::RecvStream;
use h2::client::SendRequest;
use http::Request;

use g3_h2::{H2PreviewData, H2StreamToChunkedTransfer, H2StreamToChunkedTransferError, RequestExt};
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse, H2ReqmodAdaptationError,
    H2RequestAdapter, ReqmodAdaptationEndState, ReqmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::IcapReqmodResponsePayload;
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// 拼装"头 + body"全量上报的 ICAP 请求头区。
    ///
    /// `http_header_len` 为降级序列化后的 HTTP/1.1 头块字节数，用作
    /// `req-body` 的偏移量（相对于封装对象起始处，`req-hdr=0` 之后紧跟 body）。
    /// 注意此路径**不带** `Preview` 头，因此 ICAP 必须等收到完整请求才回响应。
    fn build_forward_all_request(&self, http_header_len: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        // 全量/小体路径的请求已被序列化取走，Extensions 无法再借用，故传 None
        self.push_extended_headers(&mut header, None);
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, req-body={http_header_len}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// preview 阶段就已读完整个 body（小于预览上限）时的"一次性上报"。
    ///
    /// 时序上等价于"无 preview 的全量上报"，但 body 数据已在 `preview_data`
    /// 内存中，因此可以直接写成 chunked 并结束写端，然后**串行**等待 ICAP
    /// 响应（无需双向流并发）。
    pub(super) async fn xfer_small_body(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
        preview_data: H2PreviewData,
        clt_body: RecvStream,
        ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 1) 降级序列化 h2 请求头，并以其长度作为 req-body 偏移
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_forward_all_request(http_header.len());

        // 2) ICAP 头 + 封装头一起写出
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;

        // 3) 已在内存中的整段 body 直接按 chunked 写出（含 `0\r\n` 终止块）
        preview_data
            .icap_write_all_as_chunked(icap_w)
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        // 4) body 数据虽已读完，h2 流仍可能有 trailer，需搬完才能宣告写端结束
        self.recv_send_trailer(clt_body).await?;
        self.icap_connection.mark_writer_finished();

        // 5) 串行等待并解析 ICAP 响应
        let mut rsp = ReqmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;
        let shared_headers = rsp.take_shared_headers();
        if !shared_headers.is_empty() {
            state.respond_shared_headers = Some(shared_headers);
        }

        match rsp.code {
            // 本路径未声明 Allow: 204/206，收到这两个码都属于非法响应
            204 | 206 => {
                return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }
        match rsp.payload {
            IcapReqmodResponsePayload::NoPayload => {
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            // 改写请求头，无 body：请求本身仍来自客户端原始 h2 流（body 已上报完）
            IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                self.handle_icap_http_request_without_body(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_send_request,
                )
                .await
            }
            // 改写请求 + chunked body：由于上行已写完，这里只需把 ICAP 的
            // body 单向解码到上游 h2 流
            IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                self.handle_icap_http_request_with_body_after_transfer(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_send_request,
                )
                .await
            }
            // ICAP 直接返回 HTTP 响应（拦截页）替代上游，无 body
            IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                .handle_icap_http_response_without_body(rsp, header_size)
                .await
                .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None)),
            // 同上但带 body：由调用方用 body_transfer 取完剩余 chunked 数据
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                .handle_icap_http_response_with_body(rsp, header_size)
                .await
                .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))),
        }
    }

    /// 只把 h2 流的 trailer 转成 chunked trailer 写给 ICAP（body 数据已写完）。
    ///
    /// `H2StreamToChunkedTransfer::without_data` 构造"无数据、仅 trailer"的
    /// 搬运器：h2 侧即使 END_STREAM 已到达，trailer HEADERS 帧仍可能晚到，
    /// 所以这里同样要做 idle 判定。
    async fn recv_send_trailer(
        &mut self,
        mut clt_body: RecvStream,
    ) -> Result<(), H2ReqmodAdaptationError> {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        let mut trailer_transfer = H2StreamToChunkedTransfer::without_data(
            &mut clt_body,
            &mut self.icap_connection.writer,
        );

        loop {
            tokio::select! {
                biased;

                // trailer 搬运结束即可返回，之后调用方 mark_writer_finished
                r = &mut trailer_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2ReqmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvTrailerFailed(e)),
                    };
                }
                // 缓存中无待写数据 => 卡在"等客户端 trailer"，否则卡在"写 ICAP"
                n = idle_interval.tick() => {
                    if trailer_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if trailer_transfer.no_cached_data() {
                                Err(H2ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H2ReqmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        trailer_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// 不启用 preview 的全量上报：边把 h2 body 重编码为 chunked 发给 ICAP，
    /// 边等 ICAP 响应（双向流）。
    ///
    /// 与 preview 路径的时序差别：ICAP 必须收到完整请求才能给出决策，但它
    /// 也可能提前（如判定拦截）就回响应，所以 `transfer_and_recv` 并发两者；
    /// 一旦上行 body 未搬完而 ICAP 已返回"带 body 的改写请求"，就进入
    /// `BidirectionalRecvHttpRequest` 的三向并发搬运。
    pub(super) async fn xfer_without_preview(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
        mut clt_body: RecvStream,
        ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 1) 降级序列化请求头 + 计算 req-body 偏移
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_forward_all_request(http_header.len());

        // 2) 写出 ICAP 头 + 封装头
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;

        // 3) 上行 body：h2 数据帧 -> chunked（yield_size 控制单次搬运块大小，
        //    保证与下行读取 ICAP 能公平轮转）
        let mut body_transfer = H2StreamToChunkedTransfer::new(
            &mut clt_body,
            &mut self.icap_connection.writer,
            self.copy_config.yield_size(),
        );
        // 4) 并发：继续搬 body，同时等 ICAP 响应头
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        let mut rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        let shared_headers = rsp.take_shared_headers();
        if !shared_headers.is_empty() {
            state.respond_shared_headers = Some(shared_headers);
        }

        match rsp.code {
            // 本路径不声明 Allow: 204/206：此时上行 body 可能仍在途，
            // 收到这两个码无法安全处置，按非法响应处理
            204 | 206 => {
                return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }
        match rsp.payload {
            IcapReqmodResponsePayload::NoPayload => {
                // 上行搬运若已结束才能安全宣告写端完成，否则直接丢弃连接
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_request_without_body(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_send_request,
                )
                .await
            }
            IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                if body_transfer.finished() {
                    // 上行已写完：只需把 ICAP 的 chunked body 单向解码到上游
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_request,
                        ups_send_request,
                    )
                    .await
                } else {
                    // 上行仍有 body、下行又开始了新 body：三条流并发搬运
                    let mut bidirectional_transfer = BidirectionalRecvHttpRequest {
                        icap_reader: &mut self.icap_connection.reader,
                        copy_config: self.copy_config,
                        http_body_line_max_size: self.http_body_line_max_size,
                        http_trailer_max_size: self.http_trailer_max_size,
                        http_rsp_head_recv_timeout: self.http_rsp_head_recv_timeout,
                        http_req_add_no_via_header: self.http_req_add_no_via_header,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(state, &mut body_transfer, http_request, ups_send_request)
                        .await?;

                    // 归还 ICAP 连接的条件：上行写完 + ICAP 侧（含改写 body）读完
                    let icap_read_finished = bidirectional_transfer.icap_read_finished;
                    if body_transfer.finished() {
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
            IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None))
            }
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                // 拦截响应带 body：ICAP 连接连同剩余 chunked 数据交给调用方继续读
                self.handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body)))
            }
        }
    }
}
