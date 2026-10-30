/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use g3_io_ext::{
    ArcLimitedReaderStats, ArcLimitedWriterStats, LimitedReaderStats, LimitedWriterStats,
};

use super::HttpProxyServerStats;

/// 单条客户端连接的流水线统计（reader 与 writer 任务共享）。
/// alive_task 表示已投递但尚未处理完的请求数，reader 用它判断是否值得继续保活。
pub(crate) struct HttpProxyPipelineStats {
    total_task: AtomicU64, // 本连接累计解析出的请求数
    alive_task: AtomicI32, // 在途（未处理完）的请求数
}

/// 初始计数为 0。
impl Default for HttpProxyPipelineStats {
    fn default() -> Self {
        HttpProxyPipelineStats {
            total_task: AtomicU64::new(0),
            alive_task: AtomicI32::new(0),
        }
    }
}

/// 流水线计数的增减（reader 投递成功时 add，writer 处理完时 del）。
impl HttpProxyPipelineStats {
    /// reader 每成功投递一条请求就 +1。
    pub(super) fn add_task(&self) {
        self.total_task.fetch_add(1, Ordering::Relaxed);
        self.alive_task.fetch_add(1, Ordering::Relaxed);
    }

    /// writer 处理完一条请求后 -1。
    pub(super) fn del_task(&self) {
        self.alive_task.fetch_sub(1, Ordering::Relaxed);
    }

    /// 当前在途请求数；<=0 说明 writer 已不处理任何请求。
    pub(super) fn get_alive_task(&self) -> i32 {
        self.alive_task.load(Ordering::Relaxed)
    }
}

/// 把限速读写器（LimitedBufReader / LimitedWriter）的字节数回调接到
/// HTTP 代理服务器统计上的薄包装，实现 g3_io_ext 的统计 trait。
#[derive(Clone)]
pub(crate) struct HttpProxyCltWrapperStats {
    server: Arc<HttpProxyServerStats>,
}

/// 构造入口：分别生成读端 / 写端所需的 Arc 统计包装。
impl HttpProxyCltWrapperStats {
    pub(crate) fn new_for_reader(server: &Arc<HttpProxyServerStats>) -> ArcLimitedReaderStats {
        let s = HttpProxyCltWrapperStats {
            server: Arc::clone(server),
        };
        Arc::new(s)
    }

    pub(crate) fn new_for_writer(server: &Arc<HttpProxyServerStats>) -> ArcLimitedWriterStats {
        let s = HttpProxyCltWrapperStats {
            server: Arc::clone(server),
        };
        Arc::new(s)
    }
}

/// 读端字节数计入服务器 HTTP 入流量。
impl LimitedReaderStats for HttpProxyCltWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        let size = size as u64;
        self.server.io_http.add_in_bytes(size);
    }
}

/// 写端字节数计入服务器 HTTP 出流量。
impl LimitedWriterStats for HttpProxyCltWrapperStats {
    fn add_write_bytes(&self, size: usize) {
        let size = size as u64;
        self.server.io_http.add_out_bytes(size);
    }
}
