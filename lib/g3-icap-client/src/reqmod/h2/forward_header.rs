/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 只上报"请求头"的 h2 REQMOD 路径（无 body）。
//!
//! 与 h1 版的差异：被封装的 HTTP 报文头由 h2 pseudo-header（`:method` /
//! `:path`，`:authority` → `Host:`）+ 普通头**降级序列化**成
//! `METHOD path HTTP/1.1` 形式的请求行 + 头块（`serialize_for_adapter()`），
//! 因此 `Encapsulated` 中的偏移量 `null-body=<len>` 就是这段降级文本的字节数；
//! 由于没有 body，写完头 + 空行后即可 `mark_writer_finished`，
//! 不需要做 chunked 重编码。
//!
//! 两个入口：
//! - `xfer_without_body`：普通无 body 请求，ICAP 的决策在这里一路走到
//!   "发给上游 / 返回错误响应"；
//! - `xfer_connect`：CONNECT（隧道建立前）**只返回中间状态**
//!   [`ReqmodAdaptationMidState`]，隧道由调用方自己处理。

use std::io::{IoSlice, Write};

use bytes::{BufMut, Bytes};
use h2::client::SendRequest;
use http::Request;
use tokio::io::AsyncWriteExt;

use g3_h2::RequestExt;
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    H2ReqmodAdaptationError, H2RequestAdapter, ReqmodAdaptationEndState, ReqmodAdaptationMidState,
    ReqmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::response::ReqmodResponse;
use crate::reqmod::{IcapReqmodParseError, IcapReqmodResponsePayload};

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// 拼装"仅头"上报的 ICAP 请求头区（ICAP 请求行之后、空行之前）。
    ///
    /// `http_header_len` 是降级序列化后的 HTTP/1.1 头块字节数：因为无 body，
    /// `Encapsulated` 用 `null-body=<http_header_len>` 表示"头之后没有任何实体"，
    /// 偏移量从封装对象起始处（即 `req-hdr=0`）起算。
    ///
    /// `Allow: 204` 只在服务 OPTIONS 声明支持 204 时带上，告知 ICAP 可以
    /// 直接回 204 放行。
    fn build_header_only_request(
        &self,
        http_header_len: usize,
        http_request: &Request<()>,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        // 只有 header-only 路径才借用得到请求的 Extensions，
        // 据此把 :protocol pseudo-header 转成 X-HTTP-Upgrade 一并上报
        self.push_extended_headers(&mut header, Some(http_request.extensions()));
        if self.icap_options.support_204 {
            header.put_slice(b"Allow: 204\r\n");
        }
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, null-body={http_header_len}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 无 body 请求的完整上报流程：写 ICAP 头 + 降级 HTTP 头 → 等响应 → 分派。
    ///
    /// 分派规则（详见 `reqmod` 模块头的决策表）：
    /// - 204：原样把请求发给上游；
    /// - 2xx + `req-hdr`：用 ICAP 的改写请求发上游；
    /// - 2xx + `res-hdr`：直接用 ICAP 的 HTTP 响应回复客户端（不访问上游）；
    /// - 其它：报错，由上层按 bypass 配置决定放行或失败。
    pub(super) async fn xfer_without_body(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
        ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 1) h2 请求降级序列化成 HTTP/1.1 形式的头块
        let http_header = http_request.serialize_for_adapter();
        // 2) ICAP 头里的偏移量必须与实际写出的头块长度严格一致
        let icap_header = self.build_header_only_request(http_header.len(), &http_request);

        // 3) vectored 一次写出（ICAP 头 + 封装头），flush 后宣告写端结束
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

        // 4) 解析 ICAP 响应；共享头存入运行状态供调用方取用
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
            204 => {
                // 204 必须不含封装对象；若有残余数据则不能安全复用连接
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_request_without_body(
                    state,
                    rsp,
                    http_request,
                    ups_send_request,
                )
                .await
            }
            n if (200..300).contains(&n) => match rsp.payload {
                // 2xx 却没有任何封装内容：协议异常（见 recv_response.rs）
                IcapReqmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    self.handle_icap_ok_without_payload(rsp).await
                }
                // ICAP 改写请求头（无 body）；header_size = 封装头块字节数
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
                // ICAP 改写请求且带 body：其 chunked body 需解码回 h2 数据帧
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
                // ICAP 用 HTTP 响应代替上游（拦截页），无 body
                IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                    .handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None)),
                // 同上但带 body：返回续读句柄，由调用方搬到 h2 响应流上
                IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                    .handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))),
            },
            _ => {
                // 非 2xx/204（如 5xx）：确认无残余数据后按 keep-alive 归还连接
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }

    /// CONNECT 请求的上报：只把（降级序列化后的）请求头交给 ICAP 审查，
    /// 返回 [`ReqmodAdaptationMidState`]，由调用方决定是否建立隧道。
    ///
    /// 与 `xfer_without_body` 的区别：这里不向上游发送请求（CONNECT 的
    /// "上游"就是隧道本身），且 ICAP 若返回带 body 的改写请求会被判为
    /// 非法响应 —— CONNECT 按定义不能有 body。
    pub async fn xfer_connect(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
    ) -> Result<ReqmodAdaptationMidState, H2ReqmodAdaptationError> {
        // 与 header-only 流程一致：先降级序列化，偏移量与实际写出长度保持一致
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_header_only_request(http_header.len(), &http_request);

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H2ReqmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

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
            204 => {
                // 放行：原 CONNECT 交回调用方继续建隧道
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Ok(ReqmodAdaptationMidState::OriginalRequest(http_request))
            }
            n if (200..300).contains(&n) => match rsp.payload {
                // 200 无载荷：只接受共享头等元信息；handle_* 必定返回错误，
                // 这里的 `let _ = ...?` 保持原实现语义（错误直接上抛）
                IcapReqmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    let _ = self.handle_icap_ok_without_payload(rsp).await?;
                    Ok(ReqmodAdaptationMidState::OriginalRequest(http_request))
                }
                // 只接收改写头，不发送上游：CONNECT 的转发由调用方完成
                IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                    self.recv_icap_http_request_without_body(rsp, header_size, http_request)
                        .await
                }
                IcapReqmodResponsePayload::HttpRequestWithBody(_) => {
                    // just drop the icap connection
                    // CONNECT 不允许带 body：直接放弃这条 ICAP 连接（不归还连接池）
                    Err(H2ReqmodAdaptationError::InvalidIcapServerResponse(
                        IcapReqmodParseError::UnsupportedBody(
                            "no body should be set for CONNECT header",
                        ),
                    ))
                }
                IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                    .handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationMidState::HttpErrResponse(rsp, None)),
                IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                    .handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationMidState::HttpErrResponse(rsp, Some(body))),
            },
            _ => {
                // 未知响应码：无残余数据时按 keep-alive 归还连接，然后报错
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
