/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 只上报 HTTP 头的 REQMOD 分支（"无 body" 与 CONNECT）。
//!
//! 处于状态机的"请求没有 body"分支：整段封装内容只有请求头，因此用
//! `Encapsulated: req-hdr=0, null-body=<len>` 声明"封装内容到此结束"——
//! 这里的偏移量 len 依旧等于头部字节数，与 preview.rs 中 `req-body=<len>`
//! 的含义（body 起点偏移）不同，不要混淆。
//! 由于没有任何 body 要流式传输，本文件的流程是"写完就等响应"的同步一问一答：
//! - `xfer_without_body`：普通无 body 请求，结局直接是终态（转发/替代响应）；
//! - `xfer_connect`：CONNECT 请求专用，ICAP 只能改/不改头，因此返回中间态
//!   `ReqmodAdaptationMidState`，由调用方自己去建立隧道。
//!
//! 注意此路径可以带 `Allow: 204`（若 OPTIONS 协商支持），因为不存在
//! "100-continue 之后无法回退 body" 的问题。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::AsyncWriteExt;

use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    H1ReqmodAdaptationError, HttpRequestAdapter, HttpRequestForAdaptation,
    HttpRequestUpstreamWriter, ReqmodAdaptationEndState, ReqmodAdaptationMidState,
    ReqmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::response::ReqmodResponse;
use crate::reqmod::{IcapReqmodParseError, IcapReqmodResponsePayload};

impl<I: IdleCheck> HttpRequestAdapter<I> {
    /// 组装"仅头"上报的 ICAP 请求头。
    ///
    /// `null-body=<len>` 中 len = 封装内容里 HTTP 头的字节数，即封装到此为止；
    /// `Allow: 204` 只在服务支持时声明，避免收到我们无法接受的响应；
    /// `append_upgrade_header` 把 hop-by-hop 的 Upgrade 以 X-HTTP-Upgrade 透传。
    fn build_header_only_request<H>(&self, http_request: &H, http_header_len: usize) -> Vec<u8>
    where
        H: HttpRequestForAdaptation,
    {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        if self.icap_options.support_204 {
            header.put_slice(b"Allow: 204\r\n");
        }
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, null-body={http_header_len}\r\n",
        );
        http_request.append_upgrade_header(&mut header);
        header.put_slice(b"\r\n");
        header
    }

    /// 无 body 请求的完整上报流程：发头 → 等响应 → 按响应码决定转发方式。
    ///
    /// 写完立即 `mark_writer_finished()`，因为不会有后续写动作；204 走"原样转发"
    /// （只需把头写给上游），200 系列按 Encapsulated 载荷分派到 recv_request.rs /
    /// recv_response.rs 的处理函数。
    pub(super) async fn xfer_without_body<H, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_header_only_request(http_request, http_header.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
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
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_request_without_body(state, rsp, http_request, ups_writer)
                    .await
            }
            n if (200..300).contains(&n) => match rsp.payload {
                IcapReqmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    self.handle_icap_ok_without_payload(rsp).await
                }
                IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                    self.handle_icap_http_request_without_body(
                        state,
                        rsp,
                        header_size,
                        http_request,
                        ups_writer,
                    )
                    .await
                }
                // 原请求没有 body，改写结果也不该带 body（无法凭空产生要转发的数据）
                IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_request,
                        ups_writer,
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
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))),
            },
            _ => {
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }

    /// CONNECT 请求的"仅头"上报：结果以中间态返回，隧道建立由调用方完成。
    ///
    /// CONNECT 没有 body，改写后也只需要新的目标地址/认证头，隧道里的字节不经过
    /// ICAP，因此这里不写上游，只返回"原请求"或"改写后的请求"让调用方继续；
    /// 204 分支在读侧干净且 keep_alive 时立刻归还连接。
    /// HttpRequestWithBody 在这里被显式拒绝：隧道没有 HTTP body 可承载。
    pub async fn xfer_connect<H>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
    ) -> Result<ReqmodAdaptationMidState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
    {
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_header_only_request(http_request, http_header.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
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
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Ok(ReqmodAdaptationMidState::OriginalRequest)
            }
            n if (200..300).contains(&n) => match rsp.payload {
                IcapReqmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    let _ = self.handle_icap_ok_without_payload::<H>(rsp).await?;
                    Ok(ReqmodAdaptationMidState::OriginalRequest)
                }
                IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                    self.recv_icap_http_request_without_body(rsp, header_size, http_request)
                        .await
                }
                IcapReqmodResponsePayload::HttpRequestWithBody(_) => {
                    Err(H1ReqmodAdaptationError::InvalidIcapServerResponse(
                        IcapReqmodParseError::UnsupportedBody("no body is expected"),
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
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
