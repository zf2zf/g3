/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 客户端连接的 HTTP 流水线（pipeline）实现。
//!
//! 一条客户端连接被拆成两个任务：reader（[HttpProxyPipelineReaderTask]）负责从
//! socket 解析出一条条 HTTP 请求，通过 mpsc channel 投递给 writer
//! （[HttpProxyPipelineWriterTask]）；writer 为每个请求分发具体的转发子任务
//! （forward / connect / ftp-over-http / untrusted），并把响应写回客户端。

use super::{
    CommonTaskContext, FtpOverHttpTask, HttpProxyConnectTask, HttpProxyForwardTask,
    HttpProxyServerStats, HttpProxyUntrustedTask, protocol,
};

mod reader;
mod writer;

pub(crate) use reader::HttpProxyPipelineReaderTask;
pub(crate) use writer::HttpProxyPipelineWriterTask;

mod stats;
use stats::HttpProxyCltWrapperStats;
pub(crate) use stats::HttpProxyPipelineStats;
