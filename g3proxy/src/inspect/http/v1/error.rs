/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1 拦截检测专用错误类型。
//!
//! [`H1InterceptionError`] 覆盖检测循环（`do_intercept`）中连接级与解析级的失败：
//! 客户端/上游意外关闭、客户端应用层超时、请求头非法、上游数据异常、
//! 协议切换目标不合法等。它最终会被包装为 `InterceptionError::H1` 并映射到
//! 服务端任务错误。

use std::io;

use thiserror::Error;

use g3_http::server::HttpRequestParseError;
use g3_types::net::HttpUpgradeToken;

/// HTTP/1 拦截过程中的失败原因。
#[derive(Debug, Error)]
pub(crate) enum H1InterceptionError {
    /// 客户端在读到完整请求前关闭了连接
    #[error("closed by client")]
    ClosedByClient,
    /// 读取客户端请求时发生底层 IO 错误
    #[error("client read: {0:?}")]
    ClientReadFailed(io::Error),
    /// 客户端在应用层超时（如流水线空闲等待、请求头读取超时），参数为超时阶段描述
    #[error("client application timeout: {0}")]
    ClientAppTimeout(&'static str),
    /// 请求行/请求头解析失败（语法非法、超长等）
    #[error("invalid request: {0}")]
    InvalidRequestHeader(HttpRequestParseError),
    /// 上游在无在途请求时关闭了连接
    #[error("closed by upstream")]
    ClosedByUpstream,
    /// 无在途请求时上游却返回了数据，违反 HTTP 请求/响应配对假设
    #[error("unexpected data from upstream")]
    UnexpectedUpstreamData,
    /// 上游读取过程中发生底层 IO 错误后关闭
    #[error("upstream closed with error: {0:?}")]
    UpstreamClosedWithError(io::Error),
    /// 101 响应中的 Upgrade 协议不在允许切换的集合内（如残留的 h2 over TLS）
    #[error("invalid upgrade protocol: {0}")]
    InvalidUpgradeProtocol(HttpUpgradeToken),
}

impl From<HttpRequestParseError> for H1InterceptionError {
    /// 区分"连接层面的终结事件"（关闭/IO 错误）与"请求本身非法"：
    /// 前者保留为对应的连接变体，其余解析错误统一归入 [`Self::InvalidRequestHeader`]。
    fn from(e: HttpRequestParseError) -> Self {
        match e {
            HttpRequestParseError::ClientClosed => H1InterceptionError::ClosedByClient,
            HttpRequestParseError::IoFailed(e) => H1InterceptionError::ClientReadFailed(e),
            _ => H1InterceptionError::InvalidRequestHeader(e),
        }
    }
}
