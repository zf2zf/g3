/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

// CONNECT 隧道的客户端侧流量统计子模块

use super::HttpProxyServerStats;

mod wrapper;

// 包装后同时上报到服务器统计、任务统计与用户流量统计的读写计数器
pub(super) use wrapper::TcpConnectTaskCltWrapperStats;
