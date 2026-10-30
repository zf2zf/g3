/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 单行解析错误类型 `IcapLineParseError`，供 `StatusLine` / `HeaderLine` 返回；
//! 上层（options、reqmod、respmod）会将它包装进各自的错误枚举。

use std::str::Utf8Error;

use thiserror::Error;

/// ICAP 状态行/头部行解析失败的原因。
#[derive(Debug, Error)]
pub enum IcapLineParseError {
    /// 输入字节数不足以构成一条合法行
    #[error("not long enough")]
    NotLongEnough,
    /// 找不到期望的分隔符（如头部行的 ':'）
    #[error("no delimiter '{0}' found")]
    NoDelimiterFound(char),
    /// 头部行以 ':' 开头，缺少头部名
    #[error("missing header name")]
    MissingHeaderName,
    /// 行内容不是合法 UTF-8（自动从 Utf8Error 转换）
    #[error("invalid utf8 encoding: {0}")]
    InvalidUtf8Encoding(#[from] Utf8Error),
    /// 状态行前缀不是 "ICAP/1.0 "
    #[error("invalid icap version")]
    InvalidIcapVersion,
    /// 状态码不是三位数字或不在 100..600 范围内
    #[error("invalid status code")]
    InvalidStatusCode,
    #[error("invalid header name")]
    InvalidHeaderName,
    #[error("invalid header value")]
    InvalidHeaderValue,
}
