/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 邮件正文 REQMOD 适配过程中的错误类型。
//!
//! 错误按"链路上的哪一段出了问题"分类，便于 SMTP 代理据此决定如何回复客户端：
//! - `IcapServer*`：与 ICAP 服务器之间的读写、响应合法性问题
//! - `SmtpClient*` / `SmtpUpstream*`：与 SMTP 客户端 / 上游服务器之间的问题
//! - `*Idle` / `IdleForceQuit`：传输长时间无进展导致的超时/强制终止
//! - `NotImplemented`：使用了尚未支持的能力（例如 preview 机制）

use std::io;

use thiserror::Error;

use g3_http::client::HttpResponseParseError;
use g3_http::server::HttpRequestParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reqmod::IcapReqmodParseError;

/// SMTP 适配（伪 HTTP 报文封装 + ICAP 收发）过程中的所有可预期错误。
#[derive(Debug, Error)]
pub enum SmtpAdaptationError {
    /// 向 ICAP 服务器写出数据失败（例如连接被重置、正文 chunked 写出出错）
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    /// 从 ICAP 服务器读取数据失败
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    /// ICAP 服务器在响应完成前关闭了连接
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    /// ICAP 响应头本身无法解析（状态行/Encapsulated 等字段非法）
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    /// ICAP 响应中封装的"替代 HTTP 错误响应"无法解析
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    /// ICAP 响应中封装的"改写后的伪 HTTP 请求"无法解析
    #[error("invalid http request from icap server: {0}")]
    InvalidIcapServerHttpRequest(#[from] HttpRequestParseError),
    /// ICAP 服务器返回了非 2xx 或明确拒绝的状态码（如 204/206/500）
    #[error("error response from icap server: {0} {1}")]
    IcapServerErrorResponse(u16, String),
    /// 从 SMTP 客户端读取邮件正文失败
    #[error("read from smtp client failed: {0:?}")]
    SmtpClientReadFailed(io::Error),
    /// SMTP 客户端送来的邮件正文本身非法（例如点转义行不符合协议规则）
    #[error("invalid smtp client message")]
    InvalidSmtpClientMessage,
    /// 向 SMTP 上游写出（可能被改写过的）邮件正文失败
    #[error("write to smtp upstream failed: {0:?}")]
    SmtpUpstreamWriteFailed(io::Error),
    /// 库内部逻辑错误，通常意味着调用方式或代码本身有 bug
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    /// 空闲检查器要求强制终止本次传输
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    /// 从 SMTP 客户端读取正文时长时间空闲
    #[error("idle while reading from smtp client")]
    SmtpClientReadIdle,
    /// 向 SMTP 上游写出正文时长时间空闲
    #[error("idle while writing to smtp upstream")]
    SmtpUpstreamWriteIdle,
    /// 从 ICAP 服务器读取响应时长时间空闲
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    /// 向 ICAP 服务器写出正文时长时间空闲
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    /// 请求了尚未实现的功能，参数为功能名
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}
