/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use g3_io_ext::{
    ArcLimitedReaderStats, ArcLimitedWriterStats, LimitedReaderStats, LimitedWriterStats,
};

use super::{HttpForwardTaskStats, HttpProxyServerStats};
use crate::auth::UserTrafficStats;

/// 用户流量统计的适配接口：把客户端侧读写字节数按 http / https 转发分别累加，
/// 由各具体统计类型（如 UserTrafficStats）实现，供下面两个 wrapper 以动态分发方式调用。
trait HttpForwardTaskCltStatsWrapper {
    fn add_http_read_bytes(&self, size: u64);
    fn add_http_write_bytes(&self, size: u64);
    fn add_https_read_bytes(&self, size: u64);
    fn add_https_write_bytes(&self, size: u64);
}

type ArcHttpForwardTaskCltStatsWrapper = Arc<dyn HttpForwardTaskCltStatsWrapper + Send + Sync>;

/// 把用户级流量统计接入转发任务的客户端 IO 统计回调。
impl HttpForwardTaskCltStatsWrapper for UserTrafficStats {
    fn add_http_read_bytes(&self, size: u64) {
        self.io.http_forward.add_in_bytes(size);
    }

    fn add_http_write_bytes(&self, size: u64) {
        self.io.http_forward.add_out_bytes(size);
    }

    fn add_https_read_bytes(&self, size: u64) {
        self.io.https_forward.add_in_bytes(size);
    }

    fn add_https_write_bytes(&self, size: u64) {
        self.io.https_forward.add_out_bytes(size);
    }
}

/// 明文 HTTP 转发任务的客户端侧读写统计回调：
/// 每次读写时同时累加任务级、服务器级（仅写方向）与用户级（http_forward）流量计数。
/// 作为 LimitedReader/LimitedWriter 的 stats 挂到客户端连接上。
#[derive(Clone)]
pub(crate) struct HttpForwardTaskCltWrapperStats {
    server: Arc<HttpProxyServerStats>,              // 服务器级统计
    task: Arc<HttpForwardTaskStats>,                // 本任务级统计
    others: Vec<ArcHttpForwardTaskCltStatsWrapper>, // 用户级等附加统计
}

impl HttpForwardTaskCltWrapperStats {
    pub(crate) fn new(
        server: &Arc<HttpProxyServerStats>,
        task: &Arc<HttpForwardTaskStats>,
    ) -> Self {
        HttpForwardTaskCltWrapperStats {
            server: Arc::clone(server),
            task: Arc::clone(task),
            others: Vec::with_capacity(2),
        }
    }

    pub(crate) fn push_user_io_stats(&mut self, all: Vec<Arc<UserTrafficStats>>) {
        for s in all {
            self.others.push(s);
        }
    }

    /// 拆分为读/写两个统计句柄：内部同一份 Arc 数据，分别挂到客户端读器和写器上。
    pub(crate) fn split(self) -> (ArcLimitedReaderStats, ArcLimitedWriterStats) {
        let s = Arc::new(self);
        (s.clone(), s)
    }
}

/// 客户端读方向统计：累加任务级读字节与用户级 http_forward 入流量。
impl LimitedReaderStats for HttpForwardTaskCltWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.read.add_bytes(size);
        // DO NOT add server read stats, as the server stats is added in as direct stats
        // （服务器级读统计由直连统计累加，这里不重复计数）
        self.others.iter().for_each(|s| s.add_http_read_bytes(size));
    }
}

/// 客户端写方向统计：累加任务级、服务器级（io_http 出流量）与用户级 http_forward 流量。
impl LimitedWriterStats for HttpForwardTaskCltWrapperStats {
    fn add_write_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.write.add_bytes(size);
        self.server.io_http.add_out_bytes(size);
        self.others
            .iter()
            .for_each(|s| s.add_http_write_bytes(size));
    }
}

/// HTTPS 转发任务的客户端侧读写统计回调：结构与 HttpForwardTaskCltWrapperStats 相同，
/// 区别是用户级流量累加到 https_forward 计数（https 请求体经代理透传，读写均为密文）。
#[derive(Clone)]
pub(crate) struct HttpsForwardTaskCltWrapperStats {
    server: Arc<HttpProxyServerStats>,              // 服务器级统计
    task: Arc<HttpForwardTaskStats>,                // 本任务级统计
    others: Vec<ArcHttpForwardTaskCltStatsWrapper>, // 用户级等附加统计
}

impl HttpsForwardTaskCltWrapperStats {
    pub(crate) fn new(
        server: &Arc<HttpProxyServerStats>,
        task: &Arc<HttpForwardTaskStats>,
    ) -> Self {
        HttpsForwardTaskCltWrapperStats {
            server: Arc::clone(server),
            task: Arc::clone(task),
            others: Vec::with_capacity(2),
        }
    }

    pub(crate) fn push_user_io_stats(&mut self, all: Vec<Arc<UserTrafficStats>>) {
        for s in all {
            self.others.push(s as ArcHttpForwardTaskCltStatsWrapper);
        }
    }

    /// 拆分为读/写两个统计句柄：内部同一份 Arc 数据，分别挂到客户端读器和写器上。
    pub(crate) fn split(self) -> (ArcLimitedReaderStats, ArcLimitedWriterStats) {
        let s = Arc::new(self);
        (s.clone(), s)
    }
}

/// 客户端读方向统计：累加任务级读字节与用户级 https_forward 入流量。
impl LimitedReaderStats for HttpsForwardTaskCltWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.read.add_bytes(size);
        // DO NOT add server read stats, as the server stats is added in as direct stats
        self.others
            .iter()
            .for_each(|s| s.add_https_read_bytes(size));
    }
}

/// 客户端写方向统计：累加任务级、服务器级（io_http 出流量，https 转发复用同一服务器计数）
/// 与用户级 https_forward 流量。
impl LimitedWriterStats for HttpsForwardTaskCltWrapperStats {
    fn add_write_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.write.add_bytes(size);
        self.server.io_http.add_out_bytes(size);
        self.others
            .iter()
            .for_each(|s| s.add_https_write_bytes(size));
    }
}
