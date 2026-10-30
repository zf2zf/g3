/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};

use arc_swap::ArcSwapOption;

use g3_types::metrics::{MetricTagMap, NodeName};
use g3_types::stats::{StatId, TcpIoSnapshot, TcpIoStats};

use crate::serve::{
    ServerForbiddenSnapshot, ServerForbiddenStats, ServerPerTaskStats, ServerStats,
};
use crate::stat::types::UntrustedTaskStatsSnapshot;

/// HTTP 代理服务器的统计信息：连接数、各任务类型的数量/存活数与各类 IO 字节数。
/// 服务器实例在 reload 间共享同一份统计对象，因此计数跨版本累计。
pub(crate) struct HttpProxyServerStats {
    name: NodeName, // 服务器名，用于指标输出
    id: StatId,     // 全局唯一的统计对象 ID

    extra_metrics_tags: Arc<ArcSwapOption<MetricTagMap>>, // 附加到指标上的额外标签，可热更新

    online: AtomicIsize,   // 在线的监听运行时数量，>0 视为在线
    conn_total: AtomicU64, // 累计接收的客户端连接数

    pub forbidden: ServerForbiddenStats, // 被 ACL/策略禁止的访问统计

    task_http_untrusted: ServerPerTaskStats, // 不可信（无认证）HTTP 转发任务计数
    task_http_connect: ServerPerTaskStats,   // CONNECT 隧道任务计数
    task_http_forward: ServerPerTaskStats,   // HTTP forward 任务计数
    task_ftp_over_http: ServerPerTaskStats,  // FTP-over-HTTP 任务计数

    pub io_http: TcpIoStats, // HTTP 流水线客户端侧收发字节（forward/ftp/untrusted 等共用）
    pub io_connect: TcpIoStats, // CONNECT 隧道任务的 IO 流量
    pub io_untrusted: TcpIoStats, // 不可信任务的入站流量（单独统计，不并入总 IO）
}

impl HttpProxyServerStats {
    /// 按服务器名创建一份初始（全零）统计对象。
    pub(super) fn new(name: &NodeName) -> Self {
        HttpProxyServerStats {
            name: name.clone(),
            id: StatId::new_unique(),
            extra_metrics_tags: Arc::new(ArcSwapOption::new(None)),
            online: AtomicIsize::new(0),
            conn_total: AtomicU64::new(0),
            forbidden: Default::default(),
            task_http_untrusted: Default::default(),
            task_http_connect: Default::default(),
            task_http_forward: Default::default(),
            task_ftp_over_http: Default::default(),
            io_http: Default::default(),
            io_connect: Default::default(),
            io_untrusted: Default::default(),
        }
    }

    // online 是在监听运行时的引用计数（同一服务器可有多个监听实例），并非布尔开关

    pub(super) fn set_online(&self) {
        self.online.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn set_offline(&self) {
        self.online.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn set_extra_tags(&self, tags: Option<Arc<MetricTagMap>>) {
        self.extra_metrics_tags.store(tags);
    }

    pub(super) fn add_conn(&self, _addr: SocketAddr) {
        self.conn_total.fetch_add(1, Ordering::Relaxed);
    }

    // 以下 add_*_task 方法：累计任务总数并递增存活计数，
    // 返回对应类型的存活守卫（guard），守卫 drop 时自动递减存活计数

    pub(super) fn add_http_forward_task(self: &Arc<Self>) -> HttpForwardTaskAliveGuard {
        self.task_http_forward.add_task();
        self.task_http_forward.inc_alive_task();
        HttpForwardTaskAliveGuard(self.clone())
    }

    pub(super) fn add_http_connect_task(self: &Arc<Self>) -> HttpConnectTaskAliveGuard {
        self.task_http_connect.add_task();
        self.task_http_connect.inc_alive_task();
        HttpConnectTaskAliveGuard(self.clone())
    }

    pub(super) fn add_ftp_over_http_task(self: &Arc<Self>) -> FtpOverHttpTaskAliveGuard {
        self.task_ftp_over_http.add_task();
        self.task_ftp_over_http.inc_alive_task();
        FtpOverHttpTaskAliveGuard(self.clone())
    }

    pub(super) fn add_http_untrusted_task(self: &Arc<Self>) -> HttpUntrustedTaskAliveGuard {
        self.task_http_untrusted.add_task();
        self.task_http_untrusted.inc_alive_task();
        HttpUntrustedTaskAliveGuard(self.clone())
    }
}

/// HTTP forward 任务的存活计数守卫：任务结束（guard drop）时递减存活任务数。
pub(super) struct HttpForwardTaskAliveGuard(Arc<HttpProxyServerStats>);

/// drop 时递减 forward 任务的存活计数。
impl Drop for HttpForwardTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_http_forward.dec_alive_task();
    }
}

/// CONNECT 隧道任务的存活计数守卫。
pub(super) struct HttpConnectTaskAliveGuard(Arc<HttpProxyServerStats>);

/// drop 时递减 CONNECT 任务的存活计数。
impl Drop for HttpConnectTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_http_connect.dec_alive_task();
    }
}

/// FTP-over-HTTP 任务的存活计数守卫。
pub(super) struct FtpOverHttpTaskAliveGuard(Arc<HttpProxyServerStats>);

/// drop 时递减 FTP-over-HTTP 任务的存活计数。
impl Drop for FtpOverHttpTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_ftp_over_http.dec_alive_task();
    }
}

/// 不可信（未认证）HTTP 任务的存活计数守卫。
pub(super) struct HttpUntrustedTaskAliveGuard(Arc<HttpProxyServerStats>);

/// drop 时递减不可信任务的存活计数。
impl Drop for HttpUntrustedTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_http_untrusted.dec_alive_task();
    }
}

/// 对接统一的服务器统计接口：不可信（untrusted）任务不计入总任务/存活/IO 指标，
/// 而是通过 untrusted_snapshot 单独上报。
impl ServerStats for HttpProxyServerStats {
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
        self.online.load(Ordering::Relaxed) > 0
    }

    fn get_conn_total(&self) -> u64 {
        self.conn_total.load(Ordering::Relaxed)
    }

    fn get_task_total(&self) -> u64 {
        // untrusted stats is not counted in
        self.task_http_connect.get_task_total()
            + self.task_http_forward.get_task_total()
            + self.task_ftp_over_http.get_task_total()
    }

    fn get_alive_count(&self) -> i32 {
        // untrusted stats is not counted in
        self.task_http_connect.get_alive_count()
            + self.task_http_forward.get_alive_count()
            + self.task_ftp_over_http.get_alive_count()
    }

    fn tcp_io_snapshot(&self) -> Option<TcpIoSnapshot> {
        // the untrusted read stats is collected as buffer stats,
        // which has been contained in io_http
        Some(self.io_http.snapshot() + self.io_connect.snapshot())
    }

    #[inline]
    fn forbidden_stats(&self) -> ServerForbiddenSnapshot {
        self.forbidden.snapshot()
    }

    /// 不可信任务的独立快照：任务总数、存活数与入站字节数（不计入常规指标）。
    fn untrusted_snapshot(&self) -> Option<UntrustedTaskStatsSnapshot> {
        Some(UntrustedTaskStatsSnapshot {
            task_total: self.task_http_untrusted.get_task_total(),
            task_alive: self.task_http_untrusted.get_alive_count(),
            in_bytes: self.io_untrusted.get_in_bytes(),
        })
    }
}
