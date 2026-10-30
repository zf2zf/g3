/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! TLS 中间人拦截阶段的错误类型。
//!
//! `TlsInterceptionError` 覆盖 TLS 拦截状态机的关键失败点：ClientHello 读取、
//! 上游 TLS 握手、假证书（fake cert）签发。被 `InterceptionError::Tls` 包装后
//! 终止整条检测流水线。

use thiserror::Error;

/// TLS 拦截过程错误
#[derive(Debug, Error)]
pub(crate) enum TlsInterceptionError {
    /// 本地 OpenSSL 内部错误：创建 SSL 状态、设置假证书/私钥、构造 acceptor 等失败
    #[error("internal openssl server error: {0}")]
    InternalOpensslServerError(anyhow::Error),
    /// 客户端未完成 TLS 握手（读取 ClientHello/接受握手超时）
    #[error("client handshake timeout")]
    ClientHandshakeTimeout,
    /// 客户端 TLS 握手失败（ClientHello 解析或协商出错）
    #[error("client handshake failed: {0:?}")]
    ClientHandshakeFailed(anyhow::Error),
    /// 与上游建连前的准备失败：构造上游 SSL 上下文、SslConnector 出错
    #[error("upstream prepare failed: {0:?}")]
    UpstreamPrepareFailed(anyhow::Error),
    /// 上游 TLS 握手超时
    #[error("upstream handshake timeout")]
    UpstreamHandshakeTimeout,
    /// 上游 TLS 握手失败（证书校验/协议协商出错）
    #[error("upstream handshake failed: {0:?}")]
    UpstreamHandshakeFailed(anyhow::Error),
    /// 未能生成为客户端伪造的上游证书（cert agent 签发失败或拿不到上游证书）
    #[error("no fake cert generated: {0:?}")]
    NoFakeCertGenerated(anyhow::Error),
}
