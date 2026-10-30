/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 非可信请求任务子模块：处理来自非可信网段、未携带（或通过）代理认证请求的
//! HTTP 任务，见 task.rs 中的 HttpProxyUntrustedTask。

use super::{CommonTaskContext, HttpProxyServerStats, protocol};

/// 非可信请求任务的具体实现
mod task;

pub(super) use task::HttpProxyUntrustedTask;

/// 非可信上行读取的流量统计适配
mod stats;
use stats::UntrustedCltReadWrapperStats;
