/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use async_trait::async_trait;

use g3_ftp_client::FtpConnectionProvider;
use g3_types::net::UpstreamAddr;

use super::FtpOverHttpTaskStats;
use crate::module::ftp_over_http::{BoxFtpConnectContext, BoxFtpRemoteConnection};
use crate::module::tcp_connect::{TcpConnectError, TcpConnectTaskConf};
use crate::serve::ServerTaskNotes;

/// FTP-over-HTTP 任务的连接提供者。
///
/// g3-ftp-client 在建连（控制连接/数据连接）时通过该 trait 回调向代理请求 socket；
/// 本实现把请求转交给 tcp_connect 模块的 FTP 连接上下文（即经由 HTTP 隧道建立到
/// 上游 FTP 服务器的连接），并附带本任务的字节统计。
pub(super) struct HttpProxyFtpConnectionProvider {
    task_stats: Arc<FtpOverHttpTaskStats>,
    // 由 escaper 模块创建, 携带到上游 FTP 服务器的实际建连能力（TCP 隧道/直连）
    connect_context: BoxFtpConnectContext,
}

impl HttpProxyFtpConnectionProvider {
    pub(super) fn new(
        task_stats: &Arc<FtpOverHttpTaskStats>,
        connect_context: BoxFtpConnectContext,
    ) -> Self {
        HttpProxyFtpConnectionProvider {
            task_stats: Arc::clone(task_stats),
            connect_context,
        }
    }

    /// 返回底层连接上下文，用于读取控制/数据连接的 TCP 备注信息（如上游地址、耗时）
    #[inline]
    pub(super) fn connect_context(&self) -> &BoxFtpConnectContext {
        &self.connect_context
    }
}

/// 实现 g3-ftp-client 的建连接口：由 FTP 客户端库在需要控制/数据连接时调用。
#[async_trait]
impl FtpConnectionProvider<BoxFtpRemoteConnection, TcpConnectError, ServerTaskNotes>
    for HttpProxyFtpConnectionProvider
{
    /// 建立到上游 FTP 服务器的控制连接（21 端口命令通道）
    async fn new_control_connection(
        &mut self,
        upstream: &UpstreamAddr,
        task_notes: &ServerTaskNotes,
    ) -> Result<BoxFtpRemoteConnection, TcpConnectError> {
        let task_conf = TcpConnectTaskConf { upstream };
        self.connect_context
            .new_control_connection(&task_conf, task_notes, self.task_stats.clone())
            .await
    }

    /// 建立数据连接（LIST/RETR/STOR 使用的传输通道）。
    /// server_addr 是解析（并可能改写）FTP PORT/EPSV 响应后得到的数据端点地址。
    async fn new_data_connection(
        &mut self,
        server_addr: &UpstreamAddr,
        task_notes: &ServerTaskNotes,
    ) -> Result<BoxFtpRemoteConnection, TcpConnectError> {
        let task_conf = TcpConnectTaskConf {
            upstream: server_addr,
        };
        self.connect_context
            .new_transfer_connection(&task_conf, task_notes, self.task_stats.clone())
            .await
    }
}
