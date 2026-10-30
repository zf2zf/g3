/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 检测/拦截过程的统一错误类型。
//!
//! 定义 `InterceptionError`：聚合各协议（TLS、StartTLS、HTTP/1、HTTP/2）
//! 在拦截/检测阶段失败的错误。当某个检测任务（`StreamInspection` 状态机）
//! 无法继续转移或被策略拦截而终止时，最终以该错误经
//! `into_server_task_error` 包装为 `ServerTaskError` 返回给 serve 层，
//! 由上层统一记录审计并释放连接。

use thiserror::Error;

use g3_dpi::Protocol;

use crate::serve::ServerTaskError;

/// 检测/拦截过程错误：按发生阶段区分协议来源
#[derive(Debug, Error)]
pub(crate) enum InterceptionError {
    /// 普通 TLS（现代版本）拦截阶段的错误
    #[error("tls: {0}")]
    Tls(super::tls::TlsInterceptionError),
    /// StartTLS（先明文协商再升级为 TLS）拦截阶段的错误
    #[error("start tls: {0}")]
    StartTls(super::tls::TlsInterceptionError),
    /// HTTP/1 检测阶段的错误
    #[error("http1: {0}")]
    H1(super::http::H1InterceptionError),
    /// HTTP/2 检测阶段的错误
    #[error("http2: {0}")]
    H2(super::http::H2InterceptionError),
}

impl InterceptionError {
    /// 转换为 serve 层的任务错误，附带出错时正在检测的协议标识
    ///
    /// `protocol` 用于在审计/统计中标记是哪一种协议的拦截失败。
    pub(super) fn into_server_task_error(self, protocol: Protocol) -> ServerTaskError {
        ServerTaskError::InterceptionError(protocol, self)
    }
}
