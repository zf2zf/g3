/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use g3_daemon::stat::task::TcpStreamConnectionStats;

use crate::module::http_forward::HttpForwardTaskRemoteStats;

/// 单个 HTTP 转发任务的字节统计：分别记录客户端侧与上游侧的 TCP 读写字节数。
#[derive(Default)]
pub(crate) struct HttpForwardTaskStats {
    pub(crate) clt: TcpStreamConnectionStats, // 与客户端之间连接的读写统计
    pub(crate) ups: TcpStreamConnectionStats, // 与上游服务器之间连接的读写统计
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
