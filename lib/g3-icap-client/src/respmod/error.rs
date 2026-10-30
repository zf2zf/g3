/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD 响应解析错误类型。
//!
//! 汇总解析 ICAP RESPMOD 响应（状态行、头字段、Encapsulated 封装体）
//! 过程中可能出现的所有失败，供上层（h1/h2 适配器）区分"连接不可复用"
//! 与"仅数据非法"两类场景。

use std::io;

use thiserror::Error;

use crate::parse::IcapLineParseError;

/// ICAP RESPMOD 响应解析失败的统一错误枚举。
#[derive(Debug, Error)]
pub enum IcapRespmodParseError {
    /// 对端（ICAP 服务器）在读完完整响应之前关闭了连接：
    /// 连接已不可复用，必须丢弃。
    #[error("remote closed")]
    RemoteClosed,
    /// 响应头总长度超过配置上限（携带上限值便于排查）。
    /// 防御恶意 / 异常服务器用超长头耗尽内存。
    #[error("too large header, should be less than {0}")]
    TooLargeHeader(usize),
    /// 状态行（`ICAP/1.0 200 OK`）语法非法，无法识别协议版本或状态码。
    #[error("invalid status line: {0}")]
    InvalidStatusLine(IcapLineParseError),
    /// ICAP 服务器返回了非 2xx 的最终状态（参数为状态码 + 原因短语），
    /// 表示本次 RESPMOD 审计被服务端明确拒绝。
    #[error("request failed: {0} {1}")]
    RequestFailed(u16, String),
    /// 某个头字段行语法非法（缺少冒号、折行错误等）。
    #[error("invalid header line: {0}")]
    InvalidHeaderLine(IcapLineParseError),
    /// 响应缺少必需的 `ISTag` 头（RFC 3507 要求），
    /// 无法确认对端确实是目标 ICAP 服务，连接不可信。
    #[error("no ISTag set")]
    NoServiceTagSet,
    /// `Encapsulated` 头声明了本实现不支持的封装体布局
    /// （如 res-body 出现在 res-hdr 之前、字节偏移非法等）。
    #[error("unsupported body: {0}")]
    UnsupportedBody(&'static str),
    /// 指定头字段的取值非法（参数为头名）。
    #[error("invalid value for header {0}")]
    InvalidHeaderValue(&'static str),
    /// 读取底层连接时发生 IO 错误。
    #[error("io failed: {0:?}")]
    IoFailed(#[from] io::Error),
}
