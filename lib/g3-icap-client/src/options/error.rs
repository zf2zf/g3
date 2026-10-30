/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! OPTIONS 响应解析过程中的错误类型 `IcapOptionsParseError`。

use std::io;

use thiserror::Error;

use crate::parse::IcapLineParseError;

/// 发送 OPTIONS 请求并解析响应全过程可能出现的失败原因。
#[derive(Debug, Error)]
pub(crate) enum IcapOptionsParseError {
    /// 读取头部时连接被远端提前关闭（未读到完整行）
    #[error("remote closed")]
    RemoteClosed,
    /// 响应头部总长度超过上限，判定为异常/恶意响应
    #[error("too large header, should be less than {0}")]
    TooLargeHeader(usize),
    /// 状态行本身格式非法（版本、长度、编码问题）
    #[error("invalid status line: {0}")]
    InvalidStatusLine(IcapLineParseError),
    /// 服务端返回非 2xx 状态码，携带 (code, message)
    #[error("request failed: {0} {1}")]
    RequestFailed(u16, String),
    /// 某条头部行格式非法（缺 ':'、非 UTF-8 等）
    #[error("invalid header line: {0}")]
    InvalidHeaderLine(IcapLineParseError),
    /// Methods 头中不包含本服务配置的方法（如 RESPMOD）
    #[error("method not match")]
    MethodNotMatch,
    /// 响应缺少必需的 ISTag 头（无法做会话一致性校验）
    #[error("no ISTag set")]
    NoServiceTagSet,
    /// 服务返回了本客户端不支持的 opt-body 类型
    #[error("unsupported body")]
    UnsupportedBody(String),
    /// 某个具名头的值无法解析（如 Preview、Options-TTL 不是数字）
    #[error("invalid value for header {0}")]
    InvalidHeaderValue(&'static str),
    /// 底层读写失败
    #[error("io failed: {0:?}")]
    IoFailed(#[from] io::Error),
}
