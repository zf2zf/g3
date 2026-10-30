/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 REQMOD 上报流程的统一错误类型。
//!
//! 一次 xfer() 涉及三方 IO（客户端、ICAP 服务、真实上游）与多种协议解析，
//! 任何一步失败都归一为 [`H1ReqmodAdaptationError`]，其中"哪一侧、读还是写"
//! 的区分很有必要：调用方（g3proxy）需要据此判断
//! - 失败发生在给上游发数据之前还是之后（决定能否重试/换路）；
//! - 是否是 ICAP 服务侧问题（决定是否触发 bypass 策略、以及能否复用连接池）。
//! 各类 `*Idle` / `IdleForceQuit` 变体则来自 idle_checker 的空闲检测。

use std::io;

use thiserror::Error;

use g3_http::client::HttpResponseParseError;
use g3_http::server::HttpRequestParseError;
use g3_io_ext::IdleForceQuitReason;

use crate::reason::IcapErrorReason;
use crate::reqmod::IcapReqmodParseError;

/// REQMOD h1 适配流程可能出现的错误。
#[derive(Debug, Error)]
pub enum H1ReqmodAdaptationError {
    /// 写 ICAP 连接失败（上报头/preview/body 时）。
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    /// 读 ICAP 连接失败（等待响应时）。
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    /// ICAP 服务在对端关闭了连接：连接池中的连接可能已被服务端回收。
    #[error("connection closed by icap server")]
    IcapServerConnectionClosed,
    /// ICAP 响应本身不合法（状态行/头部/Encapsulated 偏移解析失败）。
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    /// ICAP 封装返回的替代 HTTP 响应不合法。
    #[error("invalid http error response from icap server: {0}")]
    InvalidIcapServerHttpResponse(#[from] HttpResponseParseError),
    /// ICAP 封装返回的改写 HTTP 请求不合法。
    #[error("invalid http request from icap server: {0}")]
    InvalidIcapServerHttpRequest(#[from] HttpRequestParseError),
    /// ICAP 返回的 body 不合法（如 Content-Length 与 chunked 解码长度不一致）。
    #[error("invalid http body from icap server: {0:?}")]
    InvalidHttpBodyFromIcapServer(anyhow::Error),
    /// ICAP 返回了不可处理的响应码（4xx/5xx，或 preview 后的非法 204/206 等）。
    #[error("error response from icap server: {0} ({1} {2})")]
    IcapServerErrorResponse(IcapErrorReason, u16, String),
    /// 从客户端连接读取失败。
    #[error("read from http client failed: {0:?}")]
    HttpClientReadFailed(io::Error),
    /// 客户端请求的 body 不合法。
    #[error("invalid body in http client request")]
    InvalidHttpClientRequestBody,
    /// 写真实上游失败。
    #[error("write to http upstream failed: {0:?}")]
    HttpUpstreamWriteFailed(io::Error),
    /// 适配器内部逻辑错误（多为调用方用法不对，而非网络问题）。
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    /// idle_checker 要求强制退出整个任务。
    #[error("force quit from idle checker: {0:?}")]
    IdleForceQuit(IdleForceQuitReason),
    /// 读客户端空闲超时。
    #[error("idle while reading from http client")]
    HttpClientReadIdle,
    /// 写上游空闲超时。
    #[error("idle while writing to http upstream")]
    HttpUpstreamWriteIdle,
    /// 读 ICAP 空闲超时。
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    /// 写 ICAP 空闲超时。
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    /// 本协议路径暂未实现的 ICAP 特性（如 REQMOD 206 响应）。
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}
