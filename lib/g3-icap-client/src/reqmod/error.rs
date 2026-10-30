/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! REQMOD 响应解析错误类型。
//!
//! 各协议适配器在解析 ICAP 响应（状态行、头部、Encapsulated 载荷描述）时，
//! 统一以 [`IcapReqmodParseError`] 报告失败原因，便于上层区分
//! "网络层失败（可重试/bypass）"与"协议语义错误（响应非法）"。

use std::io;

use thiserror::Error;

use crate::parse::IcapLineParseError;

/// REQMOD 解析 ICAP 响应过程中可能出现的错误。
#[derive(Debug, Error)]
pub enum IcapReqmodParseError {
    /// 对端在读完头部之前提前关闭连接（读到 EOF，未找到行结束符）。
    #[error("remote closed")]
    RemoteClosed,
    /// 头部总长度超过配置上限 `max_header_size`，防止恶意/异常大头部耗尽内存。
    #[error("too large header, should be less than {0}")]
    TooLargeHeader(usize),
    /// ICAP 状态行（如 "ICAP/1.0 200 OK"）格式非法。
    #[error("invalid status line: {0}")]
    InvalidStatusLine(IcapLineParseError),
    /// ICAP 服务返回了非 2xx 的业务失败响应，携带状态码与原因短语。
    #[error("request failed: {0} {1}")]
    RequestFailed(u16, String),
    /// 某个头部行（"Name: value"）格式非法。
    #[error("invalid header line: {0}")]
    InvalidHeaderLine(IcapLineParseError),
    /// 响应缺少必需的 ISTag（ICAP 服务标签）头。
    #[error("no ISTag set")]
    NoServiceTagSet,
    /// Encapsulated 头描述了本客户端不支持的 body 类型/偏移组合。
    #[error("unsupported body: {0}")]
    UnsupportedBody(&'static str),
    /// 指定头部（如 Encapsulated）的取值非法。
    #[error("invalid value for header {0}")]
    InvalidHeaderValue(&'static str),
    /// 底层 IO 错误（读取 ICAP 连接失败），可由 `?` 自动转换。
    #[error("io failed: {0:?}")]
    IoFailed(#[from] io::Error),
}
