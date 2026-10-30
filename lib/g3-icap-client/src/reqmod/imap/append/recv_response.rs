/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应中"没有改写后的邮件"时的两类处理。
//!
//! 与 `recv_request`（200 返回替换邮件）相对，本文件处理：
//! - 响应 2xx 但**不带任何载荷**（既无 res-body 也无 Encapsulated 指向的体）：
//!   对 IMAP 而言不符合约定，直接按错误返回。
//! - 响应中封装的是一个**替代用的 HTTP 错误响应**，形如：
//!   ```text
//!   HTTP/1.1 403 Forbidden\r\n
//!   Content-Type: text/plain\r\n
//!   Content-Length: <n>\r\n
//!   \r\n
//!   <说明正文>
//!   ```
//!   IMAP 代理拿到后不会按 HTTP 语义转发，而是转成 APPEND 失败的应答
//!   （由上层 `ReqmodAdaptationEndState::HttpErrResponse` 承载）。
//!   带正文的版本要把 ICAP 连接连同"剩余正文待读"这件事一起交给上层，
//!   因此绝不能在这里提前标记读结束或归还连接。

use g3_io_ext::IdleCheck;

use super::{HttpAdapterErrorResponse, ImapAdaptationError, ImapMessageAdapter};
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodRecvHttpResponseBody};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> ImapMessageAdapter<I> {
    /// 处理 2xx 但完全没有载荷的响应。
    ///
    /// IMAP 场景下 ICAP 至少要返回"原样请求（204）"或"替代响应"，
    /// 没有载荷就无法继续，故按错误处理；此刻已无数据待读，可归还连接。
    pub(super) async fn handle_icap_ok_without_payload(
        self,
        icap_rsp: ReqmodResponse,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError> {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(ImapAdaptationError::IcapServerErrorResponse(
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 处理带正文的替代 HTTP 错误响应：只解析响应头，正文留给上层读取。
    ///
    /// 返回的 `ReqmodRecvHttpResponseBody` 持有了 ICAP 连接与 keep-alive 标志，
    /// 上层读完正文后才负责归还连接。
    pub(super) async fn handle_icap_http_response_with_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<(HttpAdapterErrorResponse, ReqmodRecvHttpResponseBody), ImapAdaptationError> {
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
    ) -> Result<HttpAdapterErrorResponse, ImapAdaptationError> {
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
