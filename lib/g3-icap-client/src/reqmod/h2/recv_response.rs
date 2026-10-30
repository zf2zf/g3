/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 返回"替代 HTTP 响应"（拦截/拒绝页）时的收尾分支。
//!
//! 这些分支与 h1 版逻辑一致（响应报文本就是 HTTP/1.1 形式文本，由
//! `HttpAdapterErrorResponse::parse` 从 ICAP 连接读出），h2 侧的特殊之处是
//! **交付对象**：调用方拿到 [`HttpAdapterErrorResponse`] 后，需要自己建一条
//! h2 响应流（`send_response`），若响应带 body，则用
//! [`ReqmodRecvHttpResponseBody::body_transfer`] 把 ICAP 连接上剩余的 chunked
//! 流解码成 h2 数据帧写出。
//!
//! 因此本文件只处理"ICAP 连接的读取/归还"，不涉及 h2 流发送。

use g3_io_ext::IdleCheck;

use super::{
    H2ReqmodAdaptationError, H2RequestAdapter, HttpAdapterErrorResponse, ReqmodAdaptationEndState,
    ReqmodRecvHttpResponseBody,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// ICAP 回了 2xx 却不含任何封装内容 —— 属于协议异常，直接报错。
    ///
    /// 连接在此处已被上层标记读完并（按 keep-alive）归还，故不再返回它。
    pub(super) async fn handle_icap_ok_without_payload(
        self,
        icap_rsp: ReqmodResponse,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(H2ReqmodAdaptationError::IcapServerErrorResponse(
            IcapErrorReason::NoBodyFound,
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// ICAP 的替代响应**带 body**：只解析响应头，把 ICAP 连接连同剩余
    /// chunked 数据打包成 [`ReqmodRecvHttpResponseBody`] 交给调用方继续读。
    ///
    /// 关键点：这里既不能 `mark_reader_finished` 也不能归还连接 ——
    /// body 还挂在这条连接上，提前入池会让别的任务读到半截数据。
    pub(super) async fn handle_icap_http_response_with_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<(HttpAdapterErrorResponse, ReqmodRecvHttpResponseBody), H2ReqmodAdaptationError>
    {
        // http_header_size = Encapsulated 中 res-hdr 的字节数，即读取硬上限
        let http_rsp =
            HttpAdapterErrorResponse::parse(&mut self.icap_connection.reader, http_header_size)
                .await?;
        let recv_body = ReqmodRecvHttpResponseBody {
            icap_client: self.icap_client,
            icap_keepalive: icap_rsp.keep_alive,
            icap_connection: self.icap_connection,
            copy_config: self.copy_config,
            http_body_line_max_size: self.http_body_line_max_size,
            http_trailer_max_size: self.http_trailer_max_size,
        };
        Ok((http_rsp, recv_body))
    }

    /// ICAP 的替代响应无 body（`null-body` 偏移）：读完响应头即可结束，
    /// 并按 keep-alive 决定归还还是丢弃 ICAP 连接。
    pub(super) async fn handle_icap_http_response_without_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<HttpAdapterErrorResponse, H2ReqmodAdaptationError> {
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
