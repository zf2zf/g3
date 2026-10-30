/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP 代理子任务模块总览：每个进入的 HTTP 请求会根据方法/协议被分派到一个
//! 具体任务类型（CONNECT / FORWARD / FTP / UNTRUSTED），字节流搬运统一由
//! pipeline 读写任务完成；各任务共享 CommonTaskContext 提供的上下文。

use super::HttpProxyServerStats;
use crate::config::server::http_proxy::HttpProxyServerConfig;

/// http_proxy 任务的公共上下文（服务器配置、出口选择器、客户端信息等），
/// 由各具体任务类型共享持有。
mod common;
pub(super) use common::CommonTaskContext;

/// HTTP 报文解析/读写的协议层封装（受限大小的客户端读写器、请求封装）。
mod protocol;

/// CONNECT 方法任务：为客户端与目标服务器建立隧道转发。
mod connect;
/// 普通 HTTP 请求的转发任务：经访问控制与出口选择后将请求发往上游并回传响应。
mod forward;
/// 通过 HTTP 隧道承载的 FTP 任务。
mod ftp;
/// 流水线任务：将客户端与上游之间的字节流拆分为读/写两个子任务并发搬运。
mod pipeline;
/// 非可信网络请求任务：处理未通过代理认证进来的请求（限制读取并回 407 错误）。
mod untrusted;

// 以下为各子任务实现的内部入口类型，由上层请求分发循环按需实例化。
use connect::HttpProxyConnectTask;
use forward::HttpProxyForwardTask;
use ftp::FtpOverHttpTask;
pub(super) use pipeline::{
    HttpProxyPipelineReaderTask, HttpProxyPipelineStats, HttpProxyPipelineWriterTask,
};
use untrusted::HttpProxyUntrustedTask;
