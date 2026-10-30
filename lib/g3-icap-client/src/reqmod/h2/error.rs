/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! h2 REQMOD 适配器的统一错误类型。
//!
//! 与 `reqmod::h1::H1ReqmodAdaptationError` 结构对称，差异只在错误来源的
//! IO 类型：h2 侧的各方向都可能返回 `h2::Error`（流级错误），而 chunked
//! 编解码的失败统一由 `g3_h2` 的传输结构映射成"读/写方向的错误"，
//! 所以这里没有 h1 那种单独的 `InvalidHttpBodyFromIcapServer` 变体。
//! 错误串供上层日志/监控直接使用。
//!
//! 四个方向（http 客户端流、http 上游流、icap 读、icap 写）都可能因
//! idle 超时退出，因此 idle 相关错误单独成组，便于区分"是谁把链路拖死的"。

use std::io;

use thiserror::Error;

use g3_h2::H2PreviewError;
use g3_http::client::HttpResponseParseError;
use g3_http::server::HttpRequestParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reason::IcapErrorReason;
use crate::reqmod::IcapReqmodParseError;

/// REQMOD over h2 全流程（上报、接收 ICAP 响应、向上游转发）的错误汇总。
#[derive(Debug, Error)]
pub enum H2ReqmodAdaptationError {
    // ---- ICAP 连接方向 ----
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    // ICAP 响应本身非法（状态行/头/Encapsulated 解析失败）
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    // ICAP 返回的"替代 HTTP 响应报文"解析失败
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    // ICAP 返回的"改写后 HTTP 请求报文"解析失败
    #[error("invalid http request from icap server: {0}")]
    InvalidIcapServerHttpRequest(#[from] HttpRequestParseError),
    // ICAP 返回了不可处理的响应码（如 preview 后回 204/206）
    #[error("error response from icap server: {0} ({1} {2})")]
    IcapServerErrorResponse(IcapErrorReason, u16, String),
    // ---- 客户端 h2 流（上报数据的来源）----
    #[error("recv data from http client failed: {0}")]
    HttpClientRecvDataFailed(h2::Error),
    // trailer 是 chunked 重编码的一部分，单独区分便于定位"body 结束帧"问题
    #[error("recv trailer from http client failed: {0}")]
    HttpClientRecvTrailerFailed(h2::Error),
    // ---- 上游 h2 流（改写结果的去处）----
    #[error("send head to http upstream failed: {0}")]
    HttpUpstreamSendHeadFailed(h2::Error),
    // 发送端已不再处于可写状态（流被重置/连接关闭）
    #[error("upstream not in send state")]
    HttpUpstreamNotInSendState,
    #[error("send data to http upstream failed: {0}")]
    HttpUpstreamSendDataFailed(h2::Error),
    #[error("send trailer to http upstream failed: {0}")]
    HttpUpstreamSendTrailedFailed(h2::Error),
    #[error("recv response from http upstream failed: {0}")]
    HttpUpstreamRecvResponseFailed(h2::Error),
    // body 已发完，但响应头在 http_rsp_head_recv_timeout 内没到
    #[error("recv response from http upstream timeout")]
    HttpUpstreamRecvResponseTimeout,
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    // ---- idle 检查 ----
    // 由 idle 检查器主动要求退出（如全局熔断、连接配额）
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    #[error("idle while reading from http client")]
    HttpClientReadIdle,
    #[error("idle while writing to http upstream")]
    HttpUpstreamWriteIdle,
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    // 协议支持但本库尚未实现的能力（如 preview 后的 206 改写）
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}

impl From<H2PreviewError> for H2ReqmodAdaptationError {
    /// preview 阶段（只读客户端 h2 body 前若干字节）的错误归并到统一类型，
    /// 使 `preview.rs` 能用 `?` 直接向上抛。
    fn from(value: H2PreviewError) -> Self {
        match value {
            H2PreviewError::ReadDataFailed(e) => {
                H2ReqmodAdaptationError::HttpClientRecvDataFailed(e)
            }
            H2PreviewError::ReadIdle => H2ReqmodAdaptationError::HttpClientReadIdle,
            H2PreviewError::IdleForceQuit(r) => H2ReqmodAdaptationError::IdleForceQuit(r),
        }
    }
}
