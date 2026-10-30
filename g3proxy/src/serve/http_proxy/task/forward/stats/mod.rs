/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use super::HttpProxyServerStats;

// 转发任务的统计子模块：
// task.rs 定义单任务的原始字节数统计；
// wrapper.rs 定义客户端侧读写器的统计回调（同时累加到服务器/用户级别指标）。
mod task;
mod wrapper;

pub(super) use task::HttpForwardTaskStats;
pub(super) use wrapper::{HttpForwardTaskCltWrapperStats, HttpsForwardTaskCltWrapperStats};
