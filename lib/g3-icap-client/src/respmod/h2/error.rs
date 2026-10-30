/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2 适配流程的统一错误类型。
//!
//! 与 h1 版 `H1RespmodAdaptationError` 对称，但按 h2 链路细分：ICAP 侧
//! 读写、h2 上游 `RecvStream` 收数据/trailer、h2 客户端 `SendStream`
//! 发头/发数据/trailer，以及 idle 超时与非法状态码等。上层可据此区分
//! 故障出在哪一跳，并映射为相应的 ICAP 错误原因。

use std::io;

use thiserror::Error;

use g3_h2::H2PreviewError;
use g3_http::client::HttpResponseParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reason::IcapErrorReason;
use crate::respmod::IcapRespmodParseError;

/// RESPMOD h2 适配全过程可能出现的错误集合（`thiserror` 派生，
/// 每个变体的 `#[error(...)]` 即展示给日志的文本）。
#[derive(Debug, Error)]
pub enum H2RespmodAdaptationError {
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    // ICAP 报文本身解析失败（状态行/头/Encapsulated 偏移非法），经 `?` 自动转换
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapRespmodParseError),
    // ICAP 封装的 HTTP 响应报文解析失败，经 `?` 自动转换
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    /// 错误响应来自 ICAP 服务器：附带错误原因、状态码与原因短语
    #[error("error response from icap server: {0} ({1} {2})")]
    IcapServerErrorResponse(IcapErrorReason, u16, String),
    // ---- h2 上游（后端）：从 RecvStream 接收数据帧/trailer 失败 ----
    #[error("recv data from http upstream failed: {0}")]
    HttpUpstreamRecvDataFailed(h2::Error),
    #[error("recv trailer from http upstream failed: {0}")]
    HttpUpstreamRecvTrailerFailed(h2::Error),
    // ---- h2 下游（客户端）：通过 SendStream 发送响应头/数据/trailer 失败 ----
    #[error("send head to http client failed: {0}")]
    HttpClientSendHeadFailed(h2::Error),
    #[error("client not in send state")]
    HttpClientNotInSendState,
    #[error("send data to http client failed: {0}")]
    HttpClientSendDataFailed(h2::Error),
    #[error("send trailer to http client failed: {0}")]
    HttpClientSendTrailerFailed(h2::Error),
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    // ---- 双向搬运时的 idle（空闲超时）检查失败 ----
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    #[error("idle while reading from http upstream")]
    HttpUpstreamReadIdle,
    #[error("idle while writing to http client")]
    HttpClientWriteIdle,
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}

/// preview 阶段错误到本错误类型的转换：h2 预览读取（`g3_h2::H2PreviewError`）
/// 只有"读数据失败 / 读空闲 / 强制退出"三种，均可一一映射。
impl From<H2PreviewError> for H2RespmodAdaptationError {
    fn from(value: H2PreviewError) -> Self {
        match value {
            H2PreviewError::ReadDataFailed(e) => {
                H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e)
            }
            H2PreviewError::ReadIdle => H2RespmodAdaptationError::HttpUpstreamReadIdle,
            H2PreviewError::IdleForceQuit(r) => H2RespmodAdaptationError::IdleForceQuit(r),
        }
    }
}
