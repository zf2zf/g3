/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 连接池后台任务。
//!
//! 每个 [`IcapServicePool`] 实例对应一个 ICAP 服务，与 [`super::IcapServiceClient`]
//! 通过 `kanal::AsyncSender/Receiver` 通信，承担以下职责：
//! - 维护一定数量的空闲连接（`min_idle_count` / `max_idle_count`），按
//!   `idle_timeout` 淘汰过久的空闲连接；
//! - 周期检查（`check_interval`）缓存的 [`IcapServiceOptions`] 是否过期，
//!   必要时新建连接发送 OPTIONS 刷新；
//! - 处理 client 侧的 `FetchConnection` / `SaveConnection` 命令。
//!
//! 关键设计：
//! - `pool_cmd_*` 通道用于后台任务（OPTIONS 刷新/建连/回池）向主循环投递内部命令；
//! - `conn_req_*` 通道用于主循环把 fetch 请求"广播"给当前所有空闲 poller；
//! - `idle_conn_count` 用原子计数，poller 退出时通过 fetch_sub 递减并触发补连。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;

use super::{
    IcapClientConnection, IcapConnectionEofPoller, IcapConnectionPollRequest, IcapConnector,
    IcapServiceConfig,
};
use crate::options::{IcapOptionsRequest, IcapServiceOptions};

/// 主循环命令通道深度：池内部命令量很小，16 已绰绰有余。
const POOL_CMD_CHANNEL_SIZE: usize = 16;

/// client 侧发给 pool 的命令：取连接 / 还连接。
///
/// `FetchConnection` 携带 `oneshot` sender：pool 在确实拿到空闲连接后，把
/// (连接, options) 通过该 sender 回传给 client；client 侧有 5s 超时兜底。
pub(super) enum IcapServiceClientCommand {
    FetchConnection(oneshot::Sender<(IcapClientConnection, Arc<IcapServiceOptions>)>),
    SaveConnection(IcapClientConnection),
}

/// pool 主循环处理的内部命令（区别于 client 命令）。
///
/// - `UpdateOptions`：OPTIONS 刷新协程完成新 options 后回传；
/// - `SaveConnection`：来自 client 或建连协程，把连接回收入池；
/// - `CreateConnection`：空闲连接跌破 min_idle_count 时由 poller 触发补建。
enum IcapServicePoolCommand {
    UpdateOptions(IcapServiceOptions),
    SaveConnection(IcapClientConnection),
    CreateConnection,
}

/// ICAP 服务连接池：后台协程，被 `IcapServiceClient` 启动并持有其命令发送端。
pub(super) struct IcapServicePool {
    config: Arc<IcapServiceConfig>,
    options: Arc<IcapServiceOptions>,
    connector: Arc<IcapConnector>,
    check_interval: Interval,
    client_cmd_receiver: kanal::AsyncReceiver<IcapServiceClientCommand>,
    pool_cmd_sender: mpsc::Sender<IcapServicePoolCommand>,
    pool_cmd_receiver: mpsc::Receiver<IcapServicePoolCommand>,
    conn_req_sender: kanal::AsyncSender<IcapConnectionPollRequest>,
    conn_req_receiver: kanal::AsyncReceiver<IcapConnectionPollRequest>,
    idle_conn_count: Arc<AtomicUsize>,
}

impl IcapServicePool {
    /// 构造 pool。初始 options 标记为"已过期"，确保第一次 `check()` 一定会触发
    /// OPTIONS 刷新（即池启动后会自动建一条连接并拉取服务能力）。
    pub(super) fn new(
        config: Arc<IcapServiceConfig>,
        client_cmd_receiver: kanal::AsyncReceiver<IcapServiceClientCommand>,
        connector: Arc<IcapConnector>,
    ) -> Self {
        let options = Arc::new(IcapServiceOptions::new_expired(config.method));
        let check_interval = tokio::time::interval(config.connection_pool.check_interval());
        let (pool_cmd_sender, pool_cmd_receiver) = mpsc::channel(POOL_CMD_CHANNEL_SIZE);
        // 通道深度 = max_idle_count：fetch 请求数量不会超过空闲连接数，背压可控。
        let (conn_req_sender, conn_req_receiver) =
            kanal::bounded_async(config.connection_pool.max_idle_count());
        IcapServicePool {
            config,
            options,
            connector,
            check_interval,
            client_cmd_receiver,
            pool_cmd_sender,
            pool_cmd_receiver,
            conn_req_sender,
            conn_req_receiver,
            idle_conn_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn idle_conn_count(&self) -> usize {
        self.idle_conn_count.load(Ordering::Relaxed)
    }

    /// 主循环：biased `tokio::select!` 处理三类事件——定时检查 / client 命令 /
    /// pool 内部命令。任一 client 命令通道关闭即认为整个 client 已 drop，退出。
    pub(super) async fn into_running(mut self) {
        loop {
            tokio::select! {
                biased;

                _ = self.check_interval.tick() => {
                    self.check();
                }
                r = self.client_cmd_receiver.recv() => {
                    match r {
                        Ok(cmd) => self.handle_client_cmd(cmd),
                        Err(_) => break,
                    }
                }
                r = self.pool_cmd_receiver.recv() => {
                    match r {
                        Some(cmd) => self.handle_pool_cmd(cmd),
                        None => unreachable!(),
                    }
                }
            }
        }
    }

    /// 周期任务：① 若 options 过期则后台拉取新 options；② 若空闲连接少于
    /// `min_idle_count`，主动补足（每个差额一条）。
    fn check(&mut self) {
        if self.options.expired() {
            let pool_sender = self.pool_cmd_sender.clone();
            let conn_creator = self.connector.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = conn_creator.create().await {
                    conn.mark_io_inuse();
                    let req = IcapOptionsRequest::new(config.as_ref());
                    // 注意：先 UpdateOptions 再 SaveConnection——避免 pool 内
                    // 旧 options 被新连接错误携带。
                    if let Ok(options) = req
                        .get_options(&mut conn, config.icap_max_header_size)
                        .await
                        && pool_sender
                            .send(IcapServicePoolCommand::UpdateOptions(options))
                            .await
                            .is_ok()
                    {
                        let _ = pool_sender
                            .send(IcapServicePoolCommand::SaveConnection(conn))
                            .await;
                    }
                }
            });
        }

        let current_idle_count = self.idle_conn_count();
        let min_idle_count = self.config.connection_pool.min_idle_count();
        if current_idle_count < min_idle_count {
            for _i in current_idle_count..min_idle_count {
                self.do_create();
            }
        }
    }

    /// 处理 client 侧命令。
    ///
    /// - `FetchConnection`：若有空闲连接，则把请求广播给所有 poller 由其"抢"；
    ///   否则直接现场新建一条（注意：新建的连接不含 options，由 caller 自行拉
    ///   OPTIONS；这里只把"裸"连接回传给 client 触发后续流程）。
    ///   注释里"there maybe race condition"指：idle 计数与实际 poller 状态可能
    ///   瞬时不一致（poller 刚 EOF 退出但还没 fetch_sub），所以 client 侧 5s
    ///   超时是兜底。
    /// - `SaveConnection`：仅在未超 max_idle_count 时回池，避免池膨胀。
    fn handle_client_cmd(&mut self, cmd: IcapServiceClientCommand) {
        match cmd {
            IcapServiceClientCommand::FetchConnection(sender) => {
                if self.idle_conn_count() > 0 {
                    // there maybe race condition, so we have fallback at client side
                    let req_sender = self.conn_req_sender.clone();
                    let options = self.options.clone();
                    tokio::spawn(async move {
                        let _ = req_sender
                            .send(IcapConnectionPollRequest::new(sender, options))
                            .await;
                    });
                } else {
                    let conn_creator = self.connector.clone();
                    let options = self.options.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = conn_creator.create().await {
                            let _ = sender.send((conn, options));
                        }
                    });
                }
            }
            IcapServiceClientCommand::SaveConnection(conn) => {
                if self.idle_conn_count() <= self.config.connection_pool.max_idle_count() {
                    self.save_connection(conn);
                }
            }
        }
    }

    /// 处理 pool 内部命令（来自 OPTIONS 刷新协程 / poller 退出补建）。
    fn handle_pool_cmd(&mut self, cmd: IcapServicePoolCommand) {
        match cmd {
            IcapServicePoolCommand::SaveConnection(conn) => self.save_connection(conn),
            IcapServicePoolCommand::UpdateOptions(options) => self.options = Arc::new(options),
            IcapServicePoolCommand::CreateConnection => self.create(),
        }
    }

    /// 受 max_idle_count 约束的建连：超限直接丢弃请求。
    fn create(&mut self) {
        let max_idle_count = self.config.connection_pool.max_idle_count();
        if self.idle_conn_count() < max_idle_count {
            self.do_create()
        }
    }

    /// 异步新建一条连接并在完成后通过内部命令回收到池。
    fn do_create(&mut self) {
        let pool_sender = self.pool_cmd_sender.clone();
        let conn_creator = self.connector.clone();
        tokio::spawn(async move {
            if let Ok(conn) = conn_creator.create().await {
                let _ = pool_sender
                    .send(IcapServicePoolCommand::SaveConnection(conn))
                    .await;
            }
        });
    }

    /// 回收入池：启动 [`IcapConnectionEofPoller`] 协程，idle_conn_count +1。
    /// poller 退出时 fetch_sub -1，若仍低于 min_idle_count 则补一条。
    ///
    /// 注意 `fetch_sub` 返回的是**减前**的旧值：因此比较用 `< min_idle_count`
    /// 即可表达"减之前就已不足"，避免减后再读造成多算。
    fn save_connection(&mut self, conn: IcapClientConnection) {
        let Some(eof_poller) = IcapConnectionEofPoller::new(conn, &self.conn_req_receiver) else {
            return;
        };

        let idle_count = self.idle_conn_count.clone();
        let min_idle_count = self.config.connection_pool.min_idle_count();

        idle_count.fetch_add(1, Ordering::Relaxed);

        let idle_timeout = self.config.connection_pool.idle_timeout();
        let pool_sender = self.pool_cmd_sender.clone();
        tokio::spawn(async move {
            eof_poller.into_running(idle_timeout).await;
            if idle_count.fetch_sub(1, Ordering::Relaxed) < min_idle_count {
                let _ = pool_sender
                    .send(IcapServicePoolCommand::CreateConnection)
                    .await;
            }
        });
    }
}
