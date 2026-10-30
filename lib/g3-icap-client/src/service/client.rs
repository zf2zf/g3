/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 服务对外客户端。
//!
//! 每个 [`IcapServiceClient`] 关联一个 ICAP 服务配置，负责：
//! - 生成并缓存"可复用的请求头前缀"（`partial_request_header`）；
//! - 从后台连接池 [`IcapServicePool`] 拉取/归还连接；
//! - 池空或拉取失败时，通过 [`IcapConnector`] 现场新建连接，并立即发送 OPTIONS
//!   请求获取 [`IcapServiceOptions`]（服务能力信息）。
//!
//! 连接生命周期由本文件与 `pool.rs` 协同完成：
//! `new()` → 后台跑 pool → 上层调用 `fetch_connection()` 拿到连接 →
//! 使用完毕后调用 `save_connection()` 回池；池里空闲连接被后台 EOF 探测或
//! idle 超时淘汰后，pool 会自动补建新连接。

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::sync::oneshot;

use super::{
    IcapClientConnection, IcapConnector, IcapServiceClientCommand, IcapServiceConfig,
    IcapServicePool,
};
use crate::options::{IcapOptionsRequest, IcapServiceOptions};

/// ICAP 服务客户端：ICAP 上层 API 的唯一入口。
///
/// 每个 ICAP 服务实例对应一个 `IcapServiceClient`，内部通过 `kanal` 单向命令通道
/// 与后台 [`IcapServicePool`] 任务交互，实现连接复用。
pub struct IcapServiceClient {
    pub(crate) config: Arc<IcapServiceConfig>,
    // 请求头前缀（请求行 + Host + User-Agent + Authorization）：所有 REQMOD/RESPMOD
    // 请求共享，协议适配器只需在其后追加扩展头 + 空行即可。
    pub(crate) partial_request_header: Vec<u8>,
    cmd_sender: kanal::AsyncSender<IcapServiceClientCommand>,
    conn_creator: Arc<IcapConnector>,
}

impl IcapServiceClient {
    /// 基于给定 [`IcapServiceConfig`] 创建服务客户端。
    ///
    /// 会同步启动一个后台 tokio 任务 [`IcapServicePool`]：负责连接池维护、
    /// OPTIONS 刷新、按需扩缩容。
    pub fn new(config: Arc<IcapServiceConfig>) -> anyhow::Result<Self> {
        let (cmd_sender, cmd_receiver) = kanal::unbounded_async();
        let conn_creator = IcapConnector::new(config.clone())?;
        let conn_creator = Arc::new(conn_creator);
        let pool = IcapServicePool::new(config.clone(), cmd_receiver, conn_creator.clone());
        tokio::spawn(pool.into_running());
        let partial_request_header = config.build_request_header();
        Ok(IcapServiceClient {
            config,
            partial_request_header,
            cmd_sender,
            conn_creator,
        })
    }

    /// 从后台连接池获取一个空闲连接：通过 `oneshot` 通道向 pool 发送
    /// `FetchConnection` 命令，pool 在 select 到空闲连接后会把连接 + options
    /// 一起回传。
    ///
    /// 为什么要加超时：池里连接可能已被后台 EOF poller 退出但请求还未被处理，
    /// 此时 fetch 会永远挂住；5 秒超时保证调用方能回退到"直接新建连接"。
    async fn fetch_from_pool(&self) -> Option<(IcapClientConnection, Arc<IcapServiceOptions>)> {
        let (rsp_sender, rsp_receiver) = oneshot::channel();
        let cmd = IcapServiceClientCommand::FetchConnection(rsp_sender);
        if self.cmd_sender.send(cmd).await.is_ok() {
            // Timeout: pool may have stale connections whose pollers already
            // exited. Without this, fetch_from_pool could hang indefinitely.
            match tokio::time::timeout(Duration::from_secs(5), rsp_receiver).await {
                Ok(Ok(conn)) => Some(conn),
                _ => None,
            }
        } else {
            None
        }
    }

    /// 对外接口：获取一个可用的连接 + 该连接对应的服务能力信息。
    ///
    /// 流程：先尝试从连接池取；失败则新建 TCP/TLS 连接，立即发送 OPTIONS
    /// 拿到服务能力（`IcapServiceOptions`）。OPTIONS 完成后连接已经"干净"，
    /// 调用方可继续使用或显式回池。
    pub async fn fetch_connection(
        &self,
    ) -> anyhow::Result<(IcapClientConnection, Arc<IcapServiceOptions>)> {
        if let Some(conn) = self.fetch_from_pool().await {
            return Ok(conn);
        }

        let mut conn = self
            .conn_creator
            .create()
            .await
            .map_err(|e| anyhow!("create new connection failed: {e:?}"))?;
        let options_req = IcapOptionsRequest::new(self.config.as_ref());

        // 标记 IO 正在被使用：OPTIONS 请求结束后会再次标记 in-use，让 poller
        // 不要误判该连接已"干净"回池（此时读写两端都被 caller 拿走）。
        conn.mark_io_inuse();
        let options = options_req
            .get_options(&mut conn, self.config.icap_max_header_size)
            .await
            .map_err(|e| anyhow!("failed to get icap service options: {e}"))?;

        conn.mark_io_inuse();
        Ok((conn, Arc::new(options)))
    }

    /// 用完后将连接归还到池。
    ///
    /// 仅当 `reader_clean && writer_clean`（即上一次 ICAP 事务收发都已完整结束）
    /// 时才回池；否则直接丢弃，避免把"半截事务"的连接交给下一个请求。
    pub fn save_connection(&self, conn: IcapClientConnection) {
        if conn.reusable() {
            let pool_sender = self.cmd_sender.clone();
            tokio::spawn(async move {
                let _ = pool_sender
                    .send(IcapServiceClientCommand::SaveConnection(conn))
                    .await;
            });
        }
    }
}
