/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

// HTTP CONNECT 隧道任务子模块：
// task.rs 负责任务主体（握手、ACL、上游连接、双向转发），
// stats/ 负责客户端侧读写流量在"服务器/任务/用户"三层统计上的同步累加。
use super::{CommonTaskContext, HttpProxyServerStats, protocol};

mod task;
// 供上层 HTTP 连接循环创建并驱动 CONNECT 任务
pub(super) use task::HttpProxyConnectTask;

mod stats;
use stats::TcpConnectTaskCltWrapperStats;
