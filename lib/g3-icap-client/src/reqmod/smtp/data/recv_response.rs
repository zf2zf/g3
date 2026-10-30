/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应中"没有改写后的邮件"时的两类处理。
//!
//! 与 `recv_request`（200 返回替换邮件）相对，本文件处理：
//! - 响应 2xx 但**不带任何载荷**（`Encapsulated` 缺失或只有头没有体）：
//!   对 SMTP 而言这属于不符合约定的响应，直接按错误返回。
//! - 响应中封装的是一个**替代用的 HTTP 错误响应**，形如：
//!   ```text
//!   HTTP/1.1 403 Forbidden\r\n
//!   Content-Type: text/plain\r\n
//!   Content-Length: <n>\r\n
//!   \r\n
//!   <说明正文>
//!   ```
//!   SMTP 代理拿到它之后不会按 HTTP 语义转发，而是转成 SMTP 侧的拒绝响应
//!   （由上层 `ReqmodAdaptationEndState::HttpErrResponse` 承载）。
//!   带正文的版本会把 ICAP 连接连同"还剩多少正文要读"一起交给上层继续读取，
//!   因此不能提前归还连接。

use g3_io_ext::IdleCheck;

use super::{HttpAdapterErrorResponse, SmtpAdaptationError, SmtpMessageAdapter};
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodRecvHttpResponseBody};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> SmtpMessageAdapter<I> {
    /// 处理 2xx 但完全没有载荷的响应。
    ///
    /// SMTP 场景下 ICAP 至少要返回"原样请求"或"替代响应"，没有载荷无法继续，
    /// 故按错误处理。连接此刻已无数据待读，可以按 keep-alive 归还。
    pub(super) async fn handle_icap_ok_without_payload(
        self,
        icap_rsp: ReqmodResponse,
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError> {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(SmtpAdaptationError::IcapServerErrorResponse(
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 处理带正文的替代 HTTP 错误响应：只解析响应头，正文留给上层读取。
    ///
    /// 返回的 `ReqmodRecvHttpResponseBody` 持有了 ICAP 连接与 keep-alive 标志，
    /// 上层读完正文后才负责归还连接，所以这里**不能**提前标记读结束。
    pub(super) async fn handle_icap_http_response_with_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<(HttpAdapterErrorResponse, ReqmodRecvHttpResponseBody), SmtpAdaptationError> {
        let http_rsp =
            HttpAdapterErrorResponse::parse(&mut self.icap_connection.reader, http_header_size)
                .await?;
        let recv_body = ReqmodRecvHttpResponseBody {
            icap_client: self.icap_client,
            icap_keepalive: icap_rsp.keep_alive,
            icap_connection: self.icap_connection,
        };
        Ok((http_rsp, recv_body))
    }

    /// 处理不带正文的替代 HTTP 错误响应：读完即归还连接。
    pub(super) async fn handle_icap_http_response_without_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<HttpAdapterErrorResponse, SmtpAdaptationError> {
        let http_rsp =
            HttpAdapterErrorResponse::parse(&mut self.icap_connection.reader, http_header_size)
                .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        Ok(http_rsp)
    }
}
