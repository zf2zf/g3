/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD over HTTP/1.1 的统一错误类型。
//!
//! 与 `reqmod::h1::H1ReqmodAdaptationError` 对称，区别只在数据方向：REQMOD 是
//! "读客户端请求 / 写上游"，RESPMOD 是"读上游响应 / 写客户端"，因此这里的变体是
//! `HttpUpstreamRead*` + `HttpClientWrite*`，而 REQMOD 侧对应 `HttpClientRead*` +
//! `HttpUpstreamWrite*`。
//!
//! 错误按"卡在哪个端点"分组，方便上层按方向做不同处置（重试 / 记录 / 断连）：
//! - ICAP 服务器侧：写失败、读失败、连接被关闭、响应语义非法；
//! - HTTP 上游侧：读 body 失败、body 编码非法、读取空闲超时；
//! - HTTP 客户端侧：写失败、写入空闲超时；
//! - 全局：空闲强制退出、不支持的特性。
//! 多数变体只包原始 `io::Error`（用 `{0:?}` Debug 输出），避免逐层包装噪声。

use std::io;

use thiserror::Error;

use g3_http::client::HttpResponseParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reason::IcapErrorReason;
use crate::respmod::IcapRespmodParseError;

/// HTTP/1.1 RESPMOD 适配全过程可能出现的错误。
///
/// 由 [`crate::respmod::h1::HttpResponseAdapter::xfer`] 直接返回；上层通常
/// 根据变体决定：ICAP 侧错误一般丢弃连接，客户端侧错误一般中止整个会话。
#[derive(Debug, Error)]
pub enum H1RespmodAdaptationError {
    // ---------- ICAP 服务器方向 ----------
    /// 向 ICAP 服务器写入上报数据失败（连接已不可信，须丢弃）。
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    /// 从 ICAP 服务器读取响应失败。
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    /// ICAP 服务器在完成一次适配前关闭了连接（通常是服务端超时回收）。
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    /// ICAP 响应本身不合法：状态行/头解析失败或 `Encapsulated` 偏移无法识别。
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapRespmodParseError),
    /// ICAP 响应中封装的"改写后 HTTP 响应头"解析失败。
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    /// ICAP 响应中封装的 body 与声明不符：如声明 Content-Length=0 却带 body，
    /// 或解码后的长度与 Content-Length 不一致。
    #[error("invalid http body from icap server: {0:?}")]
    InvalidHttpBodyFromIcapServer(anyhow::Error),
    /// ICAP 返回了非 2xx 的错误响应；携带语义化原因、状态码与 reason 短语。
    #[error("error response from icap server: {0} ({1} {2})")]
    IcapServerErrorResponse(IcapErrorReason, u16, String),
    // ---------- HTTP 上游方向（被适配的响应来源） ----------
    /// 读取上游响应 body 失败。
    #[error("read from http upstream failed: {0:?}")]
    HttpUpstreamReadFailed(io::Error),
    /// 上游响应 body 的传输编码非法（chunked 分块行解析失败等）。
    #[error("invalid body in http upstream response")]
    InvalidHttpUpstreamResponseBody,
    // ---------- HTTP 客户端方向（适配结果去向） ----------
    /// 向客户端写响应头或 body 失败（客户端已断开）。
    #[error("write to http client failed: {0:?}")]
    HttpClientWriteFailed(io::Error),
    /// 内部逻辑错误：状态机走到了不该出现的分支。
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    // ---------- 空闲保护 ----------
    /// 空闲检查器要求强制退出整个会话（如全局超时/会话被主动关闭）。
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    /// 读上游 body 长时间无进展。
    #[error("idle while reading from http upstream")]
    HttpUpstreamReadIdle,
    /// 写客户端长时间无进展（客户端不消费数据）。
    #[error("idle while writing to http client")]
    HttpClientWriteIdle,
    /// 读 ICAP 响应长时间无进展。
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    /// 写 ICAP 长时间无进展（ICAP 服务器不读数据）。
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    // ---------- 能力限制 ----------
    /// 命中本库未实现的能力，例如 ICAP 返回 206（仅部分改写）。
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}
