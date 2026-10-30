/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 带 body 的上报分支：把完整响应（头 + body）发给 ICAP 服务器。
//!
//! 本文件承担 RESPMOD 状态机里"body 已在手 / 可以一次性写完"的两条路径，以及
//! 完全不走 preview 的全量流式路径，与 `reqmod::h1::forward_body` 对称。
//! 三个入口的共同点：`Encapsulated` 用 `res-body=<偏移>` 声明封装响应 body 的位置，
//! 因此不发送 `Allow: 204`——既然已经把真实 body 交出去了，就不接受 ICAP 用 204
//! 表达"不改写"（204/206 会被判为非法响应）。
//!
//! ICAP 报文体布局（偏移量相对 ICAP 报文首字节，即 req-hdr 起点为 0）：
//! ```text
//! [0, req_len)                        封装的 HTTP 请求头
//! [req_len, req_len + rsp_len)        封装的 HTTP 响应头      ← res-hdr = req_len
//! [req_len + rsp_len, ...)            响应 body，chunked 重编码 ← res-body = req_len + rsp_len
//! ```
//!
//! chunked 重编码：上游 body 无论是 Content-Length、无长度（读到 EOF）还是 chunked，
//! 进入 ICAP 请求体时一律重新分块（`<hex 长度>\r\n<data>\r\n` … `0\r\n\r\n`），
//! 这样 ICAP 侧才能在不看被封装报文头的前提下确定报文边界。
//!
//! 三个入口：
//! - [`xfer_small_body`]：preview 阶段就把 body 全读完了 → 一次 vectored 写完；
//! - [`xfer_small_body_chunked`]：上游本身是 chunked 且数据读完，还需把 trailer
//!   转写给 ICAP（保持 trailer 语义）；
//! - [`xfer_without_preview`]：禁用 preview 或服务端不支持 → 边读上游边写 ICAP，
//!   并与读 ICAP 响应并发（见 `bidirectional.rs`）。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::{AsyncBufRead, AsyncWriteExt};

use g3_http::{H1BodyToChunkedTransfer, HttpBodyReader, HttpBodyType};
use g3_io_ext::{IdleCheck, LimitedWriteExt, StreamCopy, StreamCopyError};

use super::{
    BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse, H1RespmodAdaptationError,
    HttpResponseAdapter, HttpResponseClientWriter, HttpResponseForAdaptation,
    RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::h1::HttpRequestForAdaptation;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> HttpResponseAdapter<I> {
    /// 拼装"带 body 全量上报"的 ICAP 请求头块。
    ///
    /// 偏移量：`res-hdr` = 请求头字节数（响应头紧跟其后）；`res-body` =
    /// 请求头 + 响应头字节数（body 从响应头之后开始，实际数据按 chunked 分帧）。
    /// 注意这里不加 `Allow: 204`：body 已随请求上报，不接受 204 这种"空改写"。
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

    /// body 已全部读进内存（preview 读到了 EOF）：单次 vectored 写完整条 ICAP 请求。
    ///
    /// 写出顺序：ICAP 头 → 请求头 → 响应头 → chunk 起始行（body 长度的十六进制）
    /// → body 数据 → `\r\n0\r\n\r\n`（结束块 + 空行，标记报文结束）。
    /// 写完后直接同步等 ICAP 响应，无需再走双向流水线。
    pub(super) async fn xfer_small_body<R, H, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        ups_body: Vec<u8>,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header =
            self.build_forward_all_request(http_req_header.len(), http_rsp_header.len());

        // chunked 重编码：整个 body 作为一个 chunk 发出，长度用小写十六进制
        let chunk_start = format!("{:x}\r\n", ups_body.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
                IoSlice::new(chunk_start.as_bytes()),
                IoSlice::new(&ups_body),
                IoSlice::new(b"\r\n0\r\n\r\n"),
            ])
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

        self.handle_small_body_response(state, http_response, clt_writer)
            .await
    }

    /// 上游是 chunked 且数据已全部读完：还需把 trailer 原样转写给 ICAP。
    ///
    /// 与 [`Self::xfer_small_body`] 的区别只在结尾：这里只写到 `0\r\n`（结束块），
    /// 随后由 `trailer_reader` 把上游的 trailer 行继续拷进 ICAP 请求体，最后由
    /// 拷贝过程补上结束空行，从而保住 trailer 语义（ICAP 服务器可以看到它们）。
    pub(super) async fn xfer_small_body_chunked<R, H, UR, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        ups_body: Vec<u8>,
        mut trailer_reader: HttpBodyReader<'_, UR>,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        UR: AsyncBufRead + Unpin,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header =
            self.build_forward_all_request(http_req_header.len(), http_rsp_header.len());

        if ups_body.is_empty() {
            // 空 body：直接写结束块，等待后面的 trailer
            self.icap_connection
                .writer
                .write_all_vectored([
                    IoSlice::new(&icap_header),
                    IoSlice::new(&http_req_header),
                    IoSlice::new(&http_rsp_header),
                    IoSlice::new(b"0\r\n"),
                ])
                .await
                .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        } else {
            let chunk_start = format!("{:x}\r\n", ups_body.len());
            self.icap_connection
                .writer
                .write_all_vectored([
                    IoSlice::new(&icap_header),
                    IoSlice::new(&http_req_header),
                    IoSlice::new(&http_rsp_header),
                    IoSlice::new(chunk_start.as_bytes()),
                    IoSlice::new(&ups_body),
                    IoSlice::new(b"\r\n0\r\n"),
                ])
                .await
                .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        }

        self.recv_send_trailer(&mut trailer_reader).await?;

        state.mark_ups_recv_all();
        self.icap_connection.mark_writer_finished();

        self.handle_small_body_response(state, http_response, clt_writer)
            .await
    }

    /// 把上游残留的 chunked trailer 拷贝到 ICAP 请求体（带空闲保护）。
    ///
    /// trailer 由上游决定，可能迟迟不来，因此同样要受 idle_checker 约束：
    /// 无积压数据时报"读上游空闲"，否则报"写 ICAP 空闲"。
    async fn recv_send_trailer<UR>(
        &mut self,
        trailer_reader: &mut HttpBodyReader<'_, UR>,
    ) -> Result<(), H1RespmodAdaptationError>
    where
        UR: AsyncBufRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        let mut trailer_transfer = StreamCopy::new(
            trailer_reader,
            &mut self.icap_connection.writer,
            &self.copy_config,
        );
        loop {
            tokio::select! {
                biased;

                r = &mut trailer_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if trailer_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 没积压 → 等上游给 trailer；有积压 → ICAP 不读
                            return if trailer_transfer.no_cached_data() {
                                Err(H1RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        trailer_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// "body 已一次性写完"后的统一收尾：解析 ICAP 响应并按载荷分派。
    ///
    /// 状态码约束：本分支未声明 `Allow: 204`，且 body 已经完整交出，因此 204
    /// （不改写）与 206（只改写一部分）都视为非法响应；其余 2xx 按
    /// `Encapsulated` 载荷交给 `recv_response.rs` 的三个 handler。
    pub(super) async fn handle_small_body_response<H, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_response: &H,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;
        match rsp.code {
            204 | 206 => {
                return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }

        match rsp.payload {
            IcapRespmodResponsePayload::NoPayload => {
                // 2xx 无载荷：读端已到边界，但语义上必须改写（见 recv_response.rs）
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                // header_size：ICAP 封装响应头的字节数，body 偏移即 header_size
                self.handle_icap_http_response_without_body(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_writer,
                )
                .await
            }
            IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                self.handle_icap_http_response_with_body_after_transfer(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_writer,
                )
                .await
            }
        }
    }

    /// 不启用 preview：边读上游 body 边做 chunked 重编码写给 ICAP，同时等 ICAP 响应。
    ///
    /// 流程：
    /// 1. 序列化两份头 + 拼装 ICAP 头，先把头部写出（此时不 flush，让 body 的
    ///    chunk 数据与头部在同一个 socket 缓冲区里流出去）；
    /// 2. 用 [`H1BodyToChunkedTransfer`] 把上游各种形态的 body 转成 chunked 续写，
    ///    并与读 ICAP 响应并发（[`BidirectionalRecvIcapResponse::transfer_and_recv`]）；
    /// 3. ICAP 可能提前回包，所以还要区分"上行是否已写完"：
    ///    - 已写完 → 可以正常收尾并按 keep-alive 归还连接；
    ///    - 未写完且 ICAP 已回带 body 的改写响应 → 进入
    ///      [`BidirectionalRecvHttpResponse`]，上行继续灌给 ICAP、下行同时把改写
    ///      body 转给客户端，两个方向都干净收尾后才允许复用连接。
    ///
    /// 状态码约束：本分支不声明 `Allow: 204`（body 已经在传了），204/206 一律报错。
    pub(super) async fn xfer_without_preview<R, H, UR, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        ups_body_type: HttpBodyType,
        ups_body_io: &mut UR,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        UR: AsyncBufRead + Unpin,
        CW: HttpResponseClientWriter<H> + Unpin,
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
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;

        // 上游 body（Content-Length / 读到 EOF / chunked）统一 chunked 重编码后写入 ICAP
        let mut body_transfer = H1BodyToChunkedTransfer::new(
            ups_body_io,
            &mut self.icap_connection.writer,
            ups_body_type,
            self.http_body_line_max_size,
            self.copy_config,
        );
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        let rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        if body_transfer.finished() {
            state.mark_ups_recv_all();
        }

        match rsp.code {
            204 | 206 => {
                return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponseAfterContinue,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponseAfterContinue,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }
        match rsp.payload {
            IcapRespmodResponsePayload::NoPayload => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_response_without_body(
                    state,
                    rsp,
                    header_size,
                    http_response,
                    clt_writer,
                )
                .await
            }
            IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    // 上行已写完：直接走 recv_response.rs 的单向下行拷贝
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_response_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_writer,
                    )
                    .await
                } else {
                    // 上行未完：继续灌 ICAP，同时把 ICAP 的改写 body 转给客户端
                    let mut bidirectional_transfer = BidirectionalRecvHttpResponse {
                        http_body_line_max_size: self.http_body_line_max_size,
                        copy_config: self.copy_config,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(
                            state,
                            &mut body_transfer,
                            http_response,
                            &mut self.icap_connection.reader,
                            clt_writer,
                        )
                        .await?;
                    // 只有上、下行都到达边界，这条 ICAP 连接才可以被复用
                    if body_transfer.finished() {
                        state.mark_ups_recv_all();
                        self.icap_connection.mark_writer_finished();
                        if bidirectional_transfer.icap_read_finished {
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

