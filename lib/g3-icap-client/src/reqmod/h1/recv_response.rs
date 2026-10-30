/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 接收 ICAP 返回的"替代 HTTP 响应"（不再访问上游，直接回给客户端）。
//!
//! 对应 REQMOD 决策表中 `200 + res-hdr/res-body` 的分支：ICAP 服务认为这个请求
//! 不该继续（如内容拦截、策略拒绝），于是自己造一个 HTTP 响应交给代理转成客户端
//! 响应。三种情况：
//! - 替代响应无 body：把头读干净即可立刻归还连接（`without_body`）；
//! - 替代响应有 body：body 还在 ICAP 连接上，必须把读半端封装成
//!   [`ReqmodRecvHttpResponseBody`] 交给调用方流式取用，取用完后由调用方归还连接，
//!   并给响应补上 `Transfer-Encoding: chunked`（原 Content-Length 已不适用，
//!   因为长度未知且要边读边转）；
//! - 200 却没有任何载荷：属于服务实现错误，统一由 `handle_icap_ok_without_payload` 报错。

use g3_io_ext::IdleCheck;

use super::{
    H1ReqmodAdaptationError, HttpAdapterErrorResponse, HttpRequestAdapter,
    HttpRequestForAdaptation, ReqmodAdaptationEndState, ReqmodRecvHttpResponseBody,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> HttpRequestAdapter<I> {
    /// 200 系列但没有 Encapsulated 载荷：按 ICAP 服务错误上抛（REQMOD 必须给结论）。
    pub(super) async fn handle_icap_ok_without_payload<H>(
        self,
        icap_rsp: ReqmodResponse,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
            IcapErrorReason::NoBodyFound,
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 接收带 body 的替代响应：只读完响应头，body 留在连接上由调用方继续读。
    ///
    /// 返回的句柄"接管"了整条 ICAP 连接，所以此处绝不能 mark/归还连接，
    /// 否则调用方会读到下一条响应的数据。
    pub(super) async fn handle_icap_http_response_with_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<(HttpAdapterErrorResponse, ReqmodRecvHttpResponseBody), H1ReqmodAdaptationError>
    {
        let mut http_rsp =
            HttpAdapterErrorResponse::parse(&mut self.icap_connection.reader, http_header_size)
                .await?;
        // 封装的 body 是 chunked，转给客户端时也按 chunked 继续分块，
        // 因此必须把 Transfer-Encoding 改成 chunked（原 Content-Length 已在解析时被丢弃）
        http_rsp.set_chunked_encoding();
        let recv_body = ReqmodRecvHttpResponseBody {
            icap_client: self.icap_client,
            icap_keepalive: icap_rsp.keep_alive,
            icap_connection: self.icap_connection,
        };
        Ok((http_rsp, recv_body))
    }

    /// 接收不带 body 的替代响应：读完即连接干净，可按 keep_alive 回池。
    pub(super) async fn handle_icap_http_response_without_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<HttpAdapterErrorResponse, H1ReqmodAdaptationError> {
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
