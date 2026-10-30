/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use g3_io_ext::{LimitedReaderStats, LimitedWriterStats};

use super::{FtpOverHttpTaskStats, HttpProxyServerStats};
use crate::auth::UserTrafficStats;

/// 客户端流量的第三方统计回调抽象（如用户级流量统计），供包装器统一转发。
trait FtpOverHttpTaskCltStatsWrapper {
    fn add_read_bytes(&self, size: u64);
    fn add_write_bytes(&self, size: u64);
}

type ArcFtpOverHttpTaskCltStatsWrapper = Arc<dyn FtpOverHttpTaskCltStatsWrapper + Send + Sync>;

/// 用户流量统计适配：按 FTP-over-HTTP 协议类别累加用户的入/出流量。
impl FtpOverHttpTaskCltStatsWrapper for UserTrafficStats {
    fn add_read_bytes(&self, size: u64) {
        self.io.ftp_over_http.add_in_bytes(size);
    }

    fn add_write_bytes(&self, size: u64) {
        self.io.ftp_over_http.add_out_bytes(size);
    }
}

/// 挂在客户端 HTTP 读写流上的统计包装器：一次字节收发同时累加到
/// 任务统计、服务器统计以及若干用户统计，避免在业务代码里手工记录。
#[derive(Clone)]
pub(crate) struct FtpOverHttpTaskCltWrapperStats {
    server: Arc<HttpProxyServerStats>,
    task: Arc<FtpOverHttpTaskStats>,
    // 关联的用户级统计（可能一个请求命中多个用户，如共享账号）
    others: Vec<ArcFtpOverHttpTaskCltStatsWrapper>,
}

impl FtpOverHttpTaskCltWrapperStats {
    pub(crate) fn new(
        server: &Arc<HttpProxyServerStats>,
        task: &Arc<FtpOverHttpTaskStats>,
    ) -> Self {
        FtpOverHttpTaskCltWrapperStats {
            server: Arc::clone(server),
            task: Arc::clone(task),
            others: Vec::with_capacity(2),
        }
    }

    /// 追加需要联动统计的用户流量对象
    pub(crate) fn push_user_io_stats(&mut self, all: Vec<Arc<UserTrafficStats>>) {
        for s in all {
            self.others.push(s);
        }
    }
}

/// 从客户端读到字节（即客户端上行/请求数据）时的统计回调。
impl LimitedReaderStats for FtpOverHttpTaskCltWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.http_client.read.add_bytes(size);
        // DO NOT add server read stats, as the server stats is added in as direct stats
        // （服务器侧读统计由其它路径直接累加，这里不重复计入）
        self.others.iter().for_each(|s| s.add_read_bytes(size));
    }
}

/// 向客户端写出字节（响应数据）时的统计回调。
impl LimitedWriterStats for FtpOverHttpTaskCltWrapperStats {
    fn add_write_bytes(&self, size: usize) {
        let size = size as u64;
        self.task.http_client.write.add_bytes(size);
        self.server.io_http.add_out_bytes(size);
        self.others.iter().for_each(|s| s.add_write_bytes(size));
    }
}
