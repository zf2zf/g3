/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025 ByteDance and/or its affiliates.
 */

//! H2 连接级 PING 保活任务。
//!
//! [`H2PingTask`] 作为后台 tokio 任务运行：按配置的 `ping_interval` 周期性
//! 向源站发送 PING 帧并等待 ACK，同时记录 RTT 与子任务数供审计日志使用；
//! 连接关闭或 PING 失败时通过 quit 通道/错误退出循环。

use std::sync::Arc;

use h2::{Ping, PingPong};
use tokio::sync::oneshot;

use g3_slog_types::{LtDuration, LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use super::H2ConcurrencyStats;
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;

/// 以 "H2Ping" 为拦截类型输出周期保活日志，附带本轮 PING 的 RTT 与
/// 连接子任务计数。未配置检测日志器时不输出。
macro_rules! periodical_log {
    ($obj:tt, $rtt:expr, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2Ping",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "rtt" => LtDuration($rtt),
                "total_sub_task" => $obj.stats.get_total_task(),
                "alive_sub_task" => $obj.stats.get_alive_task(),
            );
        }
    };
}

/// 后台 PING 保活任务：持有检测上下文以便读取 ping_interval 并输出日志。
pub(super) struct H2PingTask<SC: ServerConfig> {
    /// 检测上下文，提供 h2 拦截配置与日志器
    ctx: StreamInspectContext<SC>,
    /// 连接级子任务计数，随 PING 日志一并输出
    stats: Arc<H2ConcurrencyStats>,
    /// 目的源站地址，仅用于日志标注
    upstream: UpstreamAddr,
}

impl<SC: ServerConfig> H2PingTask<SC> {
    /// 创建 PING 任务，随后需交给 into_running 在后台任务中执行。
    pub(super) fn new(
        ctx: StreamInspectContext<SC>,
        stats: Arc<H2ConcurrencyStats>,
        upstream: UpstreamAddr,
    ) -> Self {
        H2PingTask {
            ctx,
            stats,
            upstream,
        }
    }

    /// 运行 PING 循环，直到收到退出通知或 PING 失败。
    /// 收到 quit_receiver 信号表示上层连接正在收尾，属于正常退出；
    /// PING 帧发送/ACK 失败则说明源站连接已不可用，直接结束循环。
    pub(super) async fn into_running(
        self,
        mut ping: PingPong,
        mut quit_receiver: oneshot::Receiver<()>,
    ) {
        let mut ping_interval = tokio::time::interval(self.ctx.h2_interception().ping_interval);
        loop {
            tokio::select! {
                _ = &mut quit_receiver => {
                    break;
                }
                time = ping_interval.tick() => {
                    // opaque PING 不要求特定载荷；await 直到源站回 ACK，
                    // time.elapsed() 即本轮 RTT
                    match ping.ping(Ping::opaque()).await {
                        Ok(_) => {
                            periodical_log!(self, time.elapsed(), "ok");
                        }
                        Err(e) => {
                            periodical_log!(self, time.elapsed(), "{e}");
                            break;
                        }
                    }
                }
            }
        }
    }
}
