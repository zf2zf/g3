/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use log::{debug, trace};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, TokioRuntime, TransportConfig, VarInt,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use g3_types::net::RustlsQuicClientConfig;

use super::StreamDetourStream;
use crate::config::audit::AuditStreamDetourConfig;

// 与引流服务之间的 QUIC 连接：如何建立（new_connection）、
// 如何在一条连接上按请求分配流（run_new_connection / handle_req）、
// 以及连接如何退出（复用上限用满、空闲超时、被强制下线）。

/// 一次取流请求：池中的空闲连接通过其中的 oneshot 把可用的流回送给请求方。
pub(super) struct StreamDetourRequest(pub(super) oneshot::Sender<StreamDetourStream>);

/// 连接器：持有可复用的 TLS/传输配置，每次建连只做 DNS + 握手。
pub(super) struct StreamDetourConnector {
    config: Arc<AuditStreamDetourConfig>,
    tls_client: RustlsQuicClientConfig,
    quic_transport: Arc<TransportConfig>, // Arc 以便每条连接共享同一份传输参数
}

impl StreamDetourConnector {
    pub(super) fn new(config: Arc<AuditStreamDetourConfig>) -> anyhow::Result<Self> {
        let tls_client = config.tls_client.build_quic()?;
        let quic_transport = config.quic_transport.build_for_client();
        Ok(StreamDetourConnector {
            config,
            tls_client,
            quic_transport: Arc::new(quic_transport),
        })
    }

    /// 建立一条到引流服务的 QUIC 连接。
    ///
    /// 先自建并 connect 一个 UDP socket（这样路由/源地址由 socket 层决定，
    /// 也能套用 socket buffer 等配置），再交给 quinn Endpoint 承载。
    async fn new_connection(&self) -> anyhow::Result<Connection> {
        let mut peers = tokio::net::lookup_host(self.config.peer_addr.to_string())
            .await
            .map_err(|e| anyhow!("failed to resolve {}: {e}", self.config.peer_addr))?;

        let Some(peer) = peers.next() else {
            return Err(anyhow!("no host resolved for {}", self.config.peer_addr));
        };

        let socket = g3_socket::udp::new_std_socket_to(
            peer,
            &Default::default(),
            self.config.socket_buffer,
            Default::default(),
        )
        .map_err(|e| anyhow!("failed to setup local udp socket: {e}"))?;
        socket
            .connect(peer)
            .map_err(|e| anyhow!("failed to connect local udp socket to {peer}: {e}"))?;

        let endpoint = Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime))
            .map_err(|e| anyhow!("failed to create quic endpoint: {e}"))?;

        let mut client_config = ClientConfig::new(self.tls_client.driver.clone());
        client_config.transport_config(self.quic_transport.clone());
        // TLS 认证域名：优先用配置的 tls_name，未配置时以字符串形式的对端 IP 兜底
        let tls_name = self
            .config
            .tls_name
            .as_ref()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(peer.ip().to_string()));
        let client_connect = endpoint
            .connect_with(client_config, peer, &tls_name)
            .map_err(|e| anyhow!("failed to create quic client: {e}"))?;

        tokio::time::timeout(self.tls_client.handshake_timeout, client_connect)
            .await
            .map_err(|_| anyhow!("quic connect to peer {peer} time out"))?
            .map_err(|e| anyhow!("quic connect to peer {peer} failed: {e}"))
    }

    /// 一条连接的完整生命周期：建连 -> 在本连接上按请求开流 -> 满足退出条件后收尾。
    ///
    /// 退出条件有三类，处理方式不同：
    /// - 连接被对端关闭：直接 return，已无连接可关，不需要收尾；
    /// - 复用上限用满 / 空闲超时 / 开流失败：break 后进入下面的收尾分支，
    ///   等本连接上已下发的流自然结束再关闭。
    pub(super) async fn run_new_connection(
        &self,
        req_receiver: kanal::AsyncReceiver<StreamDetourRequest>,
        idle_timeout: Duration,
    ) {
        let mut connection = match self.new_connection().await {
            Ok(c) => c,
            Err(e) => {
                debug!("failed to connect to detour server: {e:?}");
                return;
            }
        };

        let mut count = 0;
        // 容量等于复用上限：本连接上同时存在的每条流都能发出强制下线信号而不阻塞
        let (force_quit_sender, mut force_quit_receiver) =
            mpsc::channel(self.config.connection_reuse_limit.get());

        let mut idle_sleep = Box::pin(tokio::time::sleep(idle_timeout));
        while count < self.config.connection_reuse_limit.get() {
            tokio::select! {
                e = connection.closed() => {
                    debug!("detour connection closed unexpectedly: {e}");
                    return;
                }
                r = req_receiver.recv() => {
                    // 每次取到请求都重置空闲计时；请求队列整体被消费完时本分支自然不触发
                    idle_sleep.as_mut().reset(Instant::now() + idle_timeout);
                    match r {
                        Ok(req) => {
                            // match_id 与检测服务约定：随 PPv2 头发出，响应里回显，用于确认响应属于本次请求
                            let match_id = (count & 0xFFFF) as u16;
                            if let Err(e) = self.handle_req(req, &mut connection, force_quit_sender.clone(), match_id).await {
                                debug!("error when handle new detour request: {e}");
                                break;
                            }
                            count += 1;
                        }
                        // Err：客户端对象已释放（所有请求发送端 drop），本连接没有存在的意义
                        Err(_) => break,
                    }
                }
                _ = &mut idle_sleep => {
                    // 主动交出请求接收端，本连接不再接新请求
                    drop(req_receiver);
                    break;
                }
            }
        }

        // 收尾：本函数返回后原始的 sender 会 drop，因此 receiver 只有在
        // 所有已下发的流都结束（各自的 sender 克隆也随之 drop）时才返回 None。
        // 即：这里等待在用任务自然结束，既不会被提前关闭，也不会漏掉强制下线信号。
        tokio::spawn(async move {
            tokio::select! {
                e = connection.closed() => {
                    debug!("detour connection closed unexpectedly: {e}");
                }
                r = force_quit_receiver.recv() => {
                    match r {
                        Some(_) => {
                            // 任务因服务器下线主动放弃：立即关闭，不必再等其它流
                            trace!("detour connection force quit");
                            connection.close(VarInt::from_u32(0), b"force-quit");
                        }
                        None => {
                            trace!("detour connection finished, close it");
                            connection.close(VarInt::from_u32(0), b"finished");
                        }
                    }
                    connection.closed().await;
                    trace!("detour connection closed");
                }
            }
        });
    }

    /// 为一次请求在本连接上开两条双向流，并通过 oneshot 回送给请求方。
    ///
    /// 两条流按方向分工（见 StreamDetourStream）：north 走客户端侧数据，south 走上游侧数据。
    /// 回送用 `let _ =`：请求方可能已超时放弃，此时丢弃这两条流即可。
    async fn handle_req(
        &self,
        req: StreamDetourRequest,
        connection: &mut Connection,
        force_quit_sender: mpsc::Sender<()>,
        match_id: u16,
    ) -> Result<(), ConnectionError> {
        // 双向流各自带一个发送端与接收端，这里各开两条凑成完整的收发通道
        let c_stream = connection.open_bi().await?;
        let s_stream = connection.open_bi().await?;

        let stream = StreamDetourStream {
            north_send: c_stream.0,
            north_recv: c_stream.1,
            south_send: s_stream.0,
            south_recv: s_stream.1,
            force_quit_sender,
            match_id,
        };
        let _ = req.0.send(stream);
        Ok(())
    }
}
