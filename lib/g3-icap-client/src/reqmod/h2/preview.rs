/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 带 preview 的 h2 REQMOD 上报：先只送一段"预览体"，等 ICAP 决策。
//!
//! 与 h1 版的差异同 `forward_body.rs`：封装的 HTTP 请求头由 h2
//! pseudo-header（`:method` / `:path`，`:authority` → `Host:`）降级序列化成
//! HTTP/1.1 头块；预览体来自 h2 `RecvStream` 数据帧，写入 ICAP 时按 chunked
//! 编码，并**提前**用 `0\r\n\r\n` 结束块（预览语义：告诉 ICAP"这一版请求到此
//! 为止"），真实剩余体要等 ICAP 回 100-continue 后才继续搬运。
//!
//! preview 时序（RFC 3507 §0.6）：
//! 1. 从 h2 流最多读 `Preview` 字节（多读的尾巴暂存于 `H2PreviewData::left`）；
//! 2. 若读到了 END_STREAM（body 比预览上限小）→ 走 `xfer_small_body`，
//!    当普通全量上报处理，无需 100-continue；
//! 3. 否则发送 ICAP 头（带 `Preview: <实际预览字节数>`）+ 降级头 + 预览体
//!    + `0\r\n\r\n`；
//! 4. ICAP 回 100-continue → 继续搬剩余 body（可能并发收到最终响应）；
//! 5. ICAP 回 204 → 原请求 + 预览体直接发上游，剩余 body 流式接续；
//!    回 2xx → 采纳 ICAP 的改写结果（此时不再发剩余 body）；
//!    回 206 → 本库未实现（改写预览体需要按偏移拼接，见 `NotImplemented`）。
//!
//! 注意：预览路径**不发** `Allow: 204, 206`（见 `build_preview_request` 内
//! 原有英文注释），因为收到 100-continue 之后再遇到 204/206 无法处置。

use std::io::{IoSlice, Write};

use bytes::{BufMut, Bytes};
use h2::RecvStream;
use h2::client::SendRequest;
use http::Request;
use tokio::io::AsyncWriteExt;

use g3_h2::{H2PreviewData, H2StreamToChunkedTransfer, RequestExt};
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse, H2ReqmodAdaptationError,
    H2RequestAdapter, ReqmodAdaptationEndState, ReqmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::IcapReqmodResponsePayload;
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// 拼装预览上报的 ICAP 请求头区。
    ///
    /// - `http_header_len`：降级序列化后的 HTTP/1.1 头块字节数，作为
    ///   `req-body` 的起始偏移（相对封装对象起始处，`req-hdr=0` 之后）；
    /// - `preview_size`：**实际发送**的预览字节数（可以小于服务声明的上限），
    ///   写入 `Preview:` 头，ICAP 据此知道"encapsulated 请求体被截断在此"。
    fn build_preview_request(&self, http_header_len: usize, preview_size: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        // 预览路径的请求已被序列化取走，无法再借用 Extensions，传 None
        self.push_extended_headers(&mut header, None);
        // do not send `Allow: 204, 206` as we don't want to accept 204/206 after 100-continue
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, req-body={http_header_len}\r\nPreview: {preview_size}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 带 preview 的上报入口。
    ///
    /// `max_preview_size` 来自服务 OPTIONS（`Preview` 值），实际预览量
    /// 可能更小（h2 数据帧边界不受我们控制，凑不满上限时就以已读到的为准）。
    pub(super) async fn xfer_with_preview(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
        mut clt_body: RecvStream,
        ups_send_request: SendRequest<Bytes>,
        max_preview_size: usize,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 步骤 1：从 h2 流读取最多 max_preview_size 字节（含 idle 检查）。
        // 若某个数据帧跨过了上限，多出的部分留在 preview_data.left 里，
        // 后续要么随 100-continue 一起补发，要么随原始请求发给上游。
        let mut preview_data = H2PreviewData::new(max_preview_size);
        preview_data
            .recv_all(&mut clt_body, &self.idle_checker)
            .await?;

        if preview_data.end_of_data() {
            // 步骤 2：body 比预览上限还小 => 已经全读完了，直接当全量上报
            return self
                .xfer_small_body(
                    state,
                    http_request,
                    preview_data,
                    clt_body,
                    ups_send_request,
                )
                .await;
        }

        // 步骤 3：发送 ICAP 预览请求头 + 降级 HTTP 头 + 预览体（chunked 结束块）
        let http_header = http_request.serialize_for_adapter();
        let icap_header =
            self.build_preview_request(http_header.len(), preview_data.preview_size());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        // 预览体写成**单个完整 chunk** 并以 `0\r\n\r\n` 收尾：
        // 这是 preview 的关键技巧 —— 用 chunked 终止块骗过 ICAP 的解析器，
        // 让它认为请求体已结束从而立刻给出决策
        preview_data
            .icap_write_preview_data(icap_w)
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;

        // 步骤 4：等待 ICAP 对预览的响应（100-continue / 204 / 206 / 2xx / 其它）
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
            100 => {
                // 100-continue：ICAP 要看完完整 body，继续搬剩余数据。
                // take_left() 取出"读预览时多读的尾巴"，用 with_chunk 作为
                // 下一个 chunk 先写出，避免这段数据丢失或重复
                let mut body_transfer = if let Some(left_data) = preview_data.take_left() {
                    H2StreamToChunkedTransfer::with_chunk(
                        &mut clt_body,
                        &mut self.icap_connection.writer,
                        self.copy_config.yield_size(),
                        left_data,
                    )
                } else {
                    H2StreamToChunkedTransfer::new(
                        &mut clt_body,
                        &mut self.icap_connection.writer,
                        self.copy_config.yield_size(),
                    )
                };

                // 剩余 body 上行与 ICAP 最终响应下行并发进行
                let bidirectional_transfer = BidirectionalRecvIcapResponse {
                    icap_client: &self.icap_client,
                    icap_reader: &mut self.icap_connection.reader,
                    idle_checker: &self.idle_checker,
                };
                let rsp = bidirectional_transfer
                    .transfer_and_recv(&mut body_transfer)
                    .await?;

                match rsp.code {
                    // 已收到 100-continue 后再出 204/206 无法安全处置（预览语义违规）
                    204 | 206 => {
                        return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                            IcapErrorReason::InvalidResponseAfterContinue,
                            rsp.code,
                            rsp.reason,
                        ));
                    }
                    n if (200..300).contains(&n) => {}
                    _ => {
                        return Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                            IcapErrorReason::UnknownResponseAfterContinue,
                            rsp.code,
                            rsp.reason,
                        ));
                    }
                }
                match rsp.payload {
                    IcapReqmodResponsePayload::NoPayload => {
                        // 上行搬运未结束时不能 mark_writer_finished，
                        // 否则会在 ICAP 连接上留下半截 chunked 数据
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
                            // 上行已完成：只需把 ICAP 的 chunked 改写体解码给上游
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
                            // 上行/下行同时有 body：进入三向并发搬运
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

                            // 仅当两侧都读写完毕才能安全归还 ICAP 连接到连接池
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
                        // ICAP 用 HTTP 响应替代上游（拦截页）
                        self.handle_icap_http_response_without_body(rsp, header_size)
                            .await
                            .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None))
                    }
                    IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                        }
                        // 拦截响应带 body：剩余 chunked 数据与 ICAP 连接一起交给调用方
                        self.handle_icap_http_response_with_body(rsp, header_size)
                            .await
                            .map(|(rsp, body)| {
                                ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))
                            })
                    }
                }
            }
            204 => {
                // 步骤 5a：预览即可放行 —— 不再向 ICAP 发剩余 body，
                // 改为把预览体 + 未读部分原样转发给上游（h2 流之间直拷）
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_request_with_body(
                    state,
                    rsp,
                    http_request,
                    preview_data,
                    clt_body,
                    ups_send_request,
                )
                .await
            }
            // 预览改写（只替换请求体的一部分）尚未实现
            206 => Err(H2ReqmodAdaptationError::NotImplemented("ICAP-REQMOD-206")),
            n if (200..300).contains(&n) => {
                // FIXME we should stop send the pending HTTP body to ICAP server?
                // 预览阶段就给出完整决策：直接丢弃客户端剩余 body（不再写 ICAP）
                self.icap_connection.mark_writer_finished();
                match rsp.payload {
                    IcapReqmodResponsePayload::NoPayload => {
                        self.icap_connection.mark_reader_finished();
                        self.handle_icap_ok_without_payload(rsp).await
                    }
                    // ICAP 返回的改写请求**不包含**未读的 body 部分，
                    // 因此这里只按改写头 + 改写体发送上游
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
                    IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                        .handle_icap_http_response_without_body(rsp, header_size)
                        .await
                        .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None)),
                    IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                        .handle_icap_http_response_with_body(rsp, header_size)
                        .await
                        .map(|(rsp, body)| {
                            ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))
                        }),
                }
            }
            _ => {
                // 预览请求收到未知响应码
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponseForPreview,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
