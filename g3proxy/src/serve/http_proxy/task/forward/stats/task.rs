/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use g3_daemon::stat::task::TcpStreamConnectionStats;

use crate::module::http_forward::HttpForwardTaskRemoteStats;

/// 单个 HTTP 转发任务的字节统计：分别记录客户端侧与上游侧的 TCP 读写字节数。
#[derive(Default)]
pub(crate) struct HttpForwardTaskStats {
    pub(crate) clt: TcpStreamConnectionStats, // 与客户端之间连接的读写统计
    pub(crate) ups: TcpStreamConnectionStats, // 与上游服务器之间连接的读写统计
    /// 本次请求的上传审计因并发名额用尽被跳过
    pub(crate) upload_audit_skipped: AtomicBool,
    /// 旁路审计上报的请求体字节数
    pub(crate) upload_audit_bytes: AtomicU64,
}

impl HttpForwardTaskStats {
    /// 标记本次任务的上传审计被跳过
    pub(crate) fn mark_upload_audit_skipped(&self) {
        self.upload_audit_skipped.store(true, Ordering::Relaxed);
    }

    /// 记录旁路审计上报的字节数
    pub(crate) fn add_upload_audit_bytes(&self, bytes: u64) {
        self.upload_audit_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 本次任务的上传审计是否因并发名额用尽被跳过
    pub(crate) fn upload_audit_skipped(&self) -> bool {
        self.upload_audit_skipped.load(Ordering::Relaxed)
    }

    /// 本次任务已通过旁路管线上报的请求体字节数
    pub(crate) fn upload_audit_bytes(&self) -> u64 {
        self.upload_audit_bytes.load(Ordering::Relaxed)
    }
}

/// 供上游连接（HttpForward 模块）回调，把上游侧读写字节数累加进本任务统计。
impl HttpForwardTaskRemoteStats for HttpForwardTaskStats {
    fn add_read_bytes(&self, size: u64) {
        self.ups.read.add_bytes(size);
    }

    fn add_write_bytes(&self, size: u64) {
        self.ups.write.add_bytes(size);
    }
}
