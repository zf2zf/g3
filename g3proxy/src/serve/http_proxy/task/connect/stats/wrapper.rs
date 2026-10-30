/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use g3_daemon::stat::task::TcpStreamTaskStats;
use g3_io_ext::{LimitedReaderStats, LimitedWriterStats};

use super::HttpProxyServerStats;
use crate::auth::UserTrafficStats;

/// 把一次字节数累加转发到"其它"统计对象（本文件里即用户流量统计）的统一接口，
/// 用于让 `TcpConnectTaskCltWrapperStats` 以 vec 形式持有任意数量的下游统计。
trait TcpConnectTaskCltStatsWrapper {
    // 从客户端读到的字节（上行）
    fn add_read_bytes(&self, size: u64);
    // 写给客户端的字节（下行）
    fn add_write_bytes(&self, size: u64);
}

type ArcTcpConnectTaskCltStatsWrapper = Arc<dyn TcpConnectTaskCltStatsWrapper + Send + Sync>;

// 用户维度：CONNECT 隧道的上下行计入该用户的 http_connect 流量桶
impl TcpConnectTaskCltStatsWrapper for UserTrafficStats {
    fn add_read_bytes(&self, size: u64) {
        self.io.http_connect.add_in_bytes(size);
    }

    fn add_write_bytes(&self, size: u64) {
        self.io.http_connect.add_out_bytes(size);
    }
}

/// CONNECT 任务客户端侧的流量统计包装器。
/// 每次读写都会同时累加到三层：本任务、所属服务器、以及（可能多个）用户流量统计。
/// 作为 `LimitedReader`/`LimitedWriter` 的统计回调使用。
#[derive(Clone)]
pub(crate) struct TcpConnectTaskCltWrapperStats {
    server: Arc<HttpProxyServerStats>,
    task: Arc<TcpStreamTaskStats>,
    // 额外的下游统计（同一用户跨多个服务共享的流量统计）
    others: Vec<ArcTcpConnectTaskCltStatsWrapper>,
}

impl TcpConnectTaskCltWrapperStats {
    pub(crate) fn new(server: &Arc<HttpProxyServerStats>, task: &Arc<TcpStreamTaskStats>) -> Self {
        TcpConnectTaskCltWrapperStats {
            server: Arc::clone(server),
            task: Arc::clone(task),
            others: Vec::with_capacity(2),
        }
    }

    /// 追加需要联动更新的用户流量统计
    pub(crate) fn push_user_io_stats(&mut self, all: Vec<Arc<UserTrafficStats>>) {
        for s in all {
            self.others.push(s);
        }
    }
}

// 客户端读方向（上行）：任务读计数 -> 服务器 CONNECT 入流量 -> 各用户流量统计
impl LimitedReaderStats for TcpConnectTaskCltWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.read.add_bytes(size);
        self.server.io_connect.add_in_bytes(size);
        self.others.iter().for_each(|s| s.add_read_bytes(size));
    }
}

// 客户端写方向（下行）：任务写计数 -> 服务器 CONNECT 出流量 -> 各用户流量统计
impl LimitedWriterStats for TcpConnectTaskCltWrapperStats {
    fn add_write_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.clt.write.add_bytes(size);
        self.server.io_connect.add_out_bytes(size);
        self.others.iter().for_each(|s| s.add_write_bytes(size));
    }
}
