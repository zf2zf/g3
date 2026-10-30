/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 流水线（pipeline）请求读取模块。
//!
//! 将"从客户端读并解析请求"与"主循环分派处理请求"解耦：
//! [`HttpRequestForwarder`] 在后台任务中连续解析请求并经 mpsc channel 发送，
//! [`HttpRequestAcceptor`] 在主循环端接收；[`PipelineStats`] 记录在途任务数以
//! 支撑空闲超时决策。channel 容量即配置的 pipeline_size，形成天然背压。

use std::sync::Arc;

use tokio::io::AsyncRead;
use tokio::sync::mpsc;

use super::{H1InterceptionError, HttpRequestIo};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;

mod stats;
pub(super) use stats::PipelineStats;

mod request;
pub(super) use request::{HttpRecvRequest, HttpRequest};
use request::{HttpRequestAcceptor, HttpRequestForwarder};

/// 创建配对的请求读取器：返回（后台解析转发任务, 主循环接收端）。
/// channel 容量取自 H1 拦截配置的 pipeline_size，转发任务需被 spawn 后才开始工作。
pub(super) fn new_request_handler<SC, R>(
    ctx: StreamInspectContext<SC>,
    req_io: HttpRequestIo<R>,
    stats: Arc<PipelineStats>,
) -> (HttpRequestForwarder<SC, R>, HttpRequestAcceptor<R>)
where
    SC: ServerConfig,
    R: AsyncRead + Unpin,
{
    let (send_request, recv_request) = mpsc::channel(ctx.h1_interception().pipeline_size.get());

    let forwarder = HttpRequestForwarder::new(ctx, req_io, send_request, stats);
    let acceptor = HttpRequestAcceptor::new(recv_request);

    (forwarder, acceptor)
}
