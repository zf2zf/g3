/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use tokio::sync::mpsc;

use g3_types::net::ConnectionPoolConfig;
use g3_types::stats::ConnectionPoolStats;

use super::{StreamDetourConnector, StreamDetourRequest};

// 引流服务的 QUIC 连接池：以 tokio 任务形式在后台运行，
// 负责（1）竞争消费各任务的取流请求，（2）把活跃连接数维持在配置的最小空闲水平。
//
// 注意所有连接共用同一个请求接收端（kanal receiver 的克隆），
// 因此一条请求只会被其中一条空闲连接取走，天然形成负载均衡。

const CMD_CHANNEL_SIZE: usize = 16;

enum PoolCommand {
    NewConnection, // 请求新建一条连接，来自"取流队列拥挤"的提示
}

/// 连接池的外部控制句柄：池任务随句柄全部 drop 而退出（命令通道关闭即停止循环）。
pub(super) struct StreamDetourPoolHandle {
    cmd_sender: mpsc::Sender<PoolCommand>,
}

impl StreamDetourPoolHandle {
    /// 提示池建立新连接。通道满或池已退出时忽略（后续定时检查会补足连接数）。
    pub(super) fn request_new_connection(&self) {
        let _ = self.cmd_sender.try_send(PoolCommand::NewConnection);
    }
}

pub(super) struct StreamDetourPool {
    config: ConnectionPoolConfig,
    connector: Arc<StreamDetourConnector>, // 建连方式，各连接任务共享
    stats: Arc<ConnectionPoolStats>,       // 活跃连接计数，供连接任务通过守卫维护

    client_req_receiver: kanal::AsyncReceiver<StreamDetourRequest>, // 被克隆给每条连接，竞争消费取流请求

    connection_id: u64, // 递增的连接序号，仅用于回捞通知时区分连接
    connection_close_receiver: mpsc::Receiver<u64>, // 收到即表示某条连接已退出，需要检查是否补足
    connection_close_sender: mpsc::Sender<u64>,
}

impl StreamDetourPool {
    fn new(
        config: ConnectionPoolConfig,
        client_req_receiver: kanal::AsyncReceiver<StreamDetourRequest>,
        connector: Arc<StreamDetourConnector>,
    ) -> Self {
        // 关闭通知通道容量为 1 且使用 try_send：极端并发下可能丢通知，
        // 由 check_interval 的定时检查兜底补足连接
        let (connection_close_sender, connection_close_receiver) = mpsc::channel(1);
        StreamDetourPool {
            config,
            connector,
            stats: Arc::new(ConnectionPoolStats::default()),
            client_req_receiver,
            connection_id: 0,
            connection_close_receiver,
            connection_close_sender,
        }
    }

    /// 创建并 spawn 池任务，返回控制句柄。
    ///
    /// 池任务不持有 JoinHandle：无法显式停止，只能靠句柄 drop 后自然结束。
    pub(super) fn spawn(
        config: ConnectionPoolConfig,
        client_cmd_receiver: kanal::AsyncReceiver<StreamDetourRequest>,
        connector: Arc<StreamDetourConnector>,
    ) -> StreamDetourPoolHandle {
        let pool = StreamDetourPool::new(config, client_cmd_receiver, connector);
        let (cmd_sender, cmd_receiver) = mpsc::channel(CMD_CHANNEL_SIZE);
        tokio::spawn(async move {
            pool.into_running(cmd_receiver).await;
        });
        StreamDetourPoolHandle { cmd_sender }
    }

    /// 池主循环：命令通道关闭（句柄全部释放）时退出。
    ///
    /// 三类事件：
    /// - 扩容命令：立即新建一条连接；
    /// - 连接退出通知、定时检查：都只做一次"够不够"的判断，
    ///   把活跃连接数收敛到 min_idle_count。
    async fn into_running(mut self, mut cmd_receiver: mpsc::Receiver<PoolCommand>) {
        let mut connection_check_interval = tokio::time::interval(self.config.check_interval());

        loop {
            tokio::select! {
                r = cmd_receiver.recv() => {
                    let Some(cmd) = r else {
                        break;
                    };

                    match cmd {
                        PoolCommand::NewConnection => self.create_connection(),
                    }
                }
                _ = self.connection_close_receiver.recv() => {
                    self.check_create_connection(self.stats.alive_count(), self.config.min_idle_count());
                }
                _ = connection_check_interval.tick() => {
                    self.check_create_connection(self.stats.alive_count(), self.config.min_idle_count());
                }
            }
        }
    }

    /// 活跃连接不足时批量补齐到 target。
    fn check_create_connection(&mut self, alive: usize, target: usize) {
        if alive < target {
            for _ in alive..target {
                self.create_connection();
            }
        }
    }

    /// spawn 一条连接的任务：连接内部自行消费取流请求，
    /// 直到达到复用上限、空闲超时或对端关闭后才返回，随后通知池补足连接。
    fn create_connection(&mut self) {
        self.connection_id += 1;
        let connector = self.connector.clone();
        let connection_id = self.connection_id;
        // 克隆接收端：所有连接共享同一请求队列，谁先 recv 到就由谁承载该次检测
        let client_req_receiver = self.client_req_receiver.clone();
        let connection_close_sender = self.connection_close_sender.clone();
        let pool_stats = self.stats.clone();
        let idle_timeout = self.config.idle_timeout();
        tokio::spawn(async move {
            // 守卫在连接任务整个生命周期内计入活跃数，drop 时自动减一
            let alive_guard = pool_stats.add_connection();
            connector
                .run_new_connection(client_req_receiver, idle_timeout)
                .await;
            drop(alive_guard);
            let _ = connection_close_sender.try_send(connection_id);
        });
    }
}
