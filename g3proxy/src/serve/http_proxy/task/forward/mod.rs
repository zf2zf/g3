/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use super::{CommonTaskContext, HttpProxyServerStats, protocol};

// 正向 HTTP 转发任务：处理客户端 GET/POST 等方法的代理请求，
// 将请求（含请求体）经上游连接转发到目标服务器，并把响应流式回传给客户端。
mod task;
pub(super) use task::HttpProxyForwardTask;

// 单个转发任务的流量统计与客户端侧 IO 统计回调（用于限速/计费）。
mod stats;
use stats::{
    HttpForwardTaskCltWrapperStats, HttpForwardTaskStats, HttpsForwardTaskCltWrapperStats,
};
