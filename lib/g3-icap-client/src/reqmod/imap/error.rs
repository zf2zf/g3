/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP APPEND 邮件 REQMOD 适配过程中的错误类型。
//!
//! 分类方式与 SMTP 场景一致，按"链路哪一段出问题"划分：
//! - `IcapServer*`：与 ICAP 服务器之间的读写与响应合法性问题
//! - `ImapClient*` / `ImapUpstream*`：与 IMAP 客户端 / 上游服务器之间的问题
//! - `*Idle` / `IdleForceQuit`：传输长时间无进展导致的超时或强制终止
//! - `MessageSizeNotMatch`：IMAP 特有——literal 长度是已知的，因此改写后的邮件
//!   长度必须与之核对，不一致即视为异常
//! - `NotImplemented`：使用了尚未支持的能力（例如 preview）

use std::io;

use thiserror::Error;

use g3_http::client::HttpResponseParseError;
use g3_http::server::HttpRequestParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reqmod::IcapReqmodParseError;

/// IMAP 适配（literal 封装为伪 HTTP 报文 + ICAP 收发）过程中的所有可预期错误。
#[derive(Debug, Error)]
pub enum ImapAdaptationError {
    /// 向 ICAP 服务器写出数据失败（ICAP 头、chunked 块头或 literal 正文写出出错）
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    /// 从 ICAP 服务器读取数据失败
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    /// ICAP 服务器在响应完成前关闭了连接
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    /// ICAP 响应头本身无法解析
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    /// ICAP 响应中封装的"替代 HTTP 错误响应"无法解析
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    /// ICAP 响应中封装的"改写后的伪 HTTP 请求"无法解析
    #[error("invalid http request from icap server: {0}")]
    InvalidIcapServerHttpRequest(#[from] HttpRequestParseError),
    /// ICAP 服务器返回了非 2xx 或明确拒绝的状态码（如 206/500）
    #[error("error response from icap server: {0} {1}")]
    IcapServerErrorResponse(u16, String),
    /// 从 IMAP 客户端读取剩余 literal 数据失败
    #[error("read from imap client failed: {0:?}")]
    ImapClientReadFailed(io::Error),
    /// 向 IMAP 上游写出（可能被改写过的）literal 邮件失败
    #[error("write to imap upstream failed: {0:?}")]
    ImapUpstreamWriteFailed(io::Error),
    /// 库内部逻辑错误，通常意味着调用方式或代码本身有 bug
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    /// 空闲检查器要求强制终止本次传输
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    /// 从 IMAP 客户端读取 literal 时长时间空闲
    #[error("idle while reading from imap client")]
    ImapClientReadIdle,
    /// 向 IMAP 上游写出 literal 时长时间空闲
    #[error("idle while writing to imap upstream")]
    ImapUpstreamWriteIdle,
    /// 从 ICAP 服务器读取响应时长时间空闲
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    /// 向 ICAP 服务器写出 literal 时长时间空闲
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    /// ICAP 返回的邮件长度与原始 literal 长度不一致。
    /// IMAP 的 literal 长度在 `{<n>}` 中就已确定，因此可以做严格核对；
    /// 出现该错误说明 ICAP 侧的改写结果不符合预期，不能继续写入上游。
    #[error("message size from icap server not match original")]
    MessageSizeNotMatch,
    /// 请求了尚未实现的功能，参数为功能名
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}
