/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy server statistics.
//!
//! FTP 代理服务器的运行统计：只覆盖控制通道的收发字节，
//! 数据通道的流量不在此统计范围内。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use arc_swap::ArcSwapOption;
use g3_types::metrics::{MetricTagMap, NodeName};
use g3_types::stats::{StatId, TcpIoSnapshot, TcpIoStats};

use crate::serve::{ServerForbiddenSnapshot, ServerForbiddenStats, ServerStats};

/// FTP 代理服务器的统计信息聚合体。
///
/// 全部计数均为原子变量，可在多个监听线程与任务之间无锁共享。
pub(crate) struct FtpProxyServerStats {
    /// 服务器节点名，用于指标标签
    name: NodeName,
    /// 本服务器的唯一统计 ID
    id: StatId,
    /// 额外的指标标签，配置热加载时可原地替换
    extra_metrics_tags: Arc<ArcSwapOption<MetricTagMap>>,

    /// 监听实例是否在线（+1 上线 / -1 下线）
    online: std::sync::atomic::AtomicIsize,
    /// 当前存活的控制通道任务数，同时作为 `is_online` 的判据
    task_alive_control: AtomicI32,
    /// 历史累计任务/连接总数
    task_total: AtomicU64,

    /// 控制通道（命令/应答）的收发字节统计
    tcp_control: TcpIoStats,

    /// 因管控策略被禁止的流量统计
    pub(crate) forbidden: ServerForbiddenStats,
}

impl FtpProxyServerStats {
    /// 按服务器名创建一份全新的统计对象
    pub(crate) fn new(name: &NodeName) -> Arc<Self> {
        Arc::new(FtpProxyServerStats {
            name: name.clone(),
            id: StatId::new_unique(),
            extra_metrics_tags: Arc::new(ArcSwapOption::new(None)),
            online: std::sync::atomic::AtomicIsize::new(0),
            task_alive_control: AtomicI32::new(0),
            task_total: AtomicU64::new(0),
            tcp_control: TcpIoStats::default(),
            forbidden: ServerForbiddenStats::default(),
        })
    }

    /// 监听实例上线：在线计数 +1
    pub(crate) fn set_online(&self) {
        self.online
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 监听实例下线（退出或热加载替换）：在线计数 -1
    pub(crate) fn set_offline(&self) {
        self.online
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 设置额外的指标标签（配置热加载时调用）
    pub(crate) fn set_extra_tags(&self, tags: Option<Arc<MetricTagMap>>) {
        self.extra_metrics_tags.store(tags);
    }

    /// 累加客户端 -> 上游方向（入向）的控制通道字节数
    #[inline]
    pub(crate) fn add_control_in_bytes(&self, size: u64) {
        self.tcp_control.add_in_bytes(size);
    }

    /// 累加上游 -> 客户端方向的控制通道字节数
    #[inline]
    pub(crate) fn add_control_out_bytes(&self, size: u64) {
        self.tcp_control.add_out_bytes(size);
    }

    /// 登记一个新的控制通道任务，返回 RAII 守卫。
    /// 守卫被 drop 时自动把存活任务数 -1，用于优雅退出时等待任务收敛。
    #[must_use]
    pub(crate) fn add_control_task(self: &Arc<Self>) -> FtpProxyControlTaskAliveGuard {
        self.task_total.fetch_add(1, Ordering::Relaxed);
        self.task_alive_control.fetch_add(1, Ordering::Relaxed);
        FtpProxyControlTaskAliveGuard(self.clone())
    }

    /// 登记一次 TCP accept。
    pub(crate) fn add_conn(&self, _addr: SocketAddr) {
        // FTP proxy: one TCP control connection per incoming TCP accept.
        // FTP 代理中每一次 accept 对应一条控制连接，因此只累加总数，不累加存活数。
        self.task_total.fetch_add(1, Ordering::Relaxed);
    }
}

/// 控制通道任务的存活守卫：持有统计信息的强引用，drop 时递减存活计数。
pub(crate) struct FtpProxyControlTaskAliveGuard(Arc<FtpProxyServerStats>);

impl Drop for FtpProxyControlTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_alive_control.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServerStats for FtpProxyServerStats {
    #[inline]
    fn name(&self) -> &NodeName {
        &self.name
    }

    #[inline]
    fn stat_id(&self) -> StatId {
        self.id
    }

    #[inline]
    fn load_extra_tags(&self) -> Option<Arc<MetricTagMap>> {
        self.extra_metrics_tags.load_full()
    }

    #[inline]
    fn share_extra_tags(&self) -> &Arc<ArcSwapOption<MetricTagMap>> {
        &self.extra_metrics_tags
    }

    fn is_online(&self) -> bool {
        // 只要还有存活的控制通道任务就视为“在线”
        self.task_alive_control.load(Ordering::Relaxed) > 0
    }

    fn get_conn_total(&self) -> u64 {
        // FTP 的一条连接就是一条控制连接，与任务总数相同
        self.task_total.load(Ordering::Relaxed)
    }

    fn get_task_total(&self) -> u64 {
        self.task_total.load(Ordering::Relaxed)
    }

    fn get_alive_count(&self) -> i32 {
        self.task_alive_control.load(Ordering::Relaxed)
    }

    fn tcp_io_snapshot(&self) -> Option<TcpIoSnapshot> {
        // Combine control and upload channel stats — sum in/out bytes
        // 目前仅导出控制通道的快照；数据通道流量未纳入此处统计。
        let ctrl = self.tcp_control.snapshot();
        Some(ctrl)
    }

    #[inline]
    fn forbidden_stats(&self) -> ServerForbiddenSnapshot {
        self.forbidden.snapshot()
    }
}
