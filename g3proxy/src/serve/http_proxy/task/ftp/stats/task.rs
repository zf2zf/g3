/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use g3_daemon::stat::task::{TcpStreamConnectionStats, TcpStreamHalfConnectionStats};

use crate::module::ftp_over_http::{FtpTaskRemoteControlStats, FtpTaskRemoteTransferStats};

/// 单任务视角下、与上游 FTP 服务器四类通道的字节统计。
#[derive(Default)]
pub(crate) struct FtpOverHttpServerStats {
    // 控制连接（FTP 命令通道）读/写：读=收到 FTP 应答，写=发出 FTP 命令
    pub(crate) control_read: TcpStreamHalfConnectionStats,
    pub(crate) control_write: TcpStreamHalfConnectionStats,
    // 数据连接（传输通道）读/写：以代理视角，read=从 FTP 服务器拉取数据，write=推送上传数据
    pub(crate) transfer_read: TcpStreamHalfConnectionStats,
    pub(crate) transfer_write: TcpStreamHalfConnectionStats,
}

/// 单个 FTP-over-HTTP 任务的字节统计：面向下（HTTP 客户端）与面向上（FTP 服务器）。
#[derive(Default)]
pub(crate) struct FtpOverHttpTaskStats {
    // 客户端侧 HTTP 隧道连接的读/写字节数（含请求头，见 setup_clt_limit_and_stats）
    pub(crate) http_client: TcpStreamConnectionStats,
    pub(crate) ftp_server: FtpOverHttpServerStats,
}

/// FTP 客户端库统计接口：把控制连接的收发字节记入本任务统计。
impl FtpTaskRemoteControlStats for FtpOverHttpTaskStats {
    fn add_read_bytes(&self, size: u64) {
        self.ftp_server.control_read.add_bytes(size);
    }

    fn add_write_bytes(&self, size: u64) {
        self.ftp_server.control_write.add_bytes(size);
    }
}

/// FTP 客户端库统计接口：把数据连接（传输）的收发字节记入本任务统计。
impl FtpTaskRemoteTransferStats for FtpOverHttpTaskStats {
    fn add_read_bytes(&self, size: u64) {
        self.ftp_server.transfer_read.add_bytes(size);
    }

    fn add_write_bytes(&self, size: u64) {
        self.ftp_server.transfer_write.add_bytes(size);
    }
}
