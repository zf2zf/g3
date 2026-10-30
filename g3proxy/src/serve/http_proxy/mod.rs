/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

mod stats;
use stats::{
    FtpOverHttpTaskAliveGuard, HttpConnectTaskAliveGuard, HttpForwardTaskAliveGuard,
    HttpProxyServerStats, HttpUntrustedTaskAliveGuard,
};

mod task; // 各类代理任务（connect/forward/ftp-over-http/untrusted）的读写流水线实现

mod server; // HttpProxyServer：TCP/QUIC 监听、TLS 终结与任务分发
pub(crate) use server::HttpProxyServer;
