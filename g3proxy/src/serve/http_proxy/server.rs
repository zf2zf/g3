/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use log::debug;
#[cfg(feature = "quic")]
use quinn::Connection;
use slog::Logger;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use g3_daemon::listen::{AcceptQuicServer, AcceptTcpServer, ListenStats, ListenTcpRuntime};
use g3_daemon::server::{BaseServer, ClientConnectionInfo, ServerReloadCommand};
use g3_io_ext::{AsyncStream, IdleWheel};
use g3_openssl::SslStream;
use g3_types::acl::{AclAction, AclNetworkRule};
use g3_types::acl_set::AclDstHostRuleSet;
use g3_types::metrics::NodeName;
use g3_types::net::{
    AlpnProtocol, OpensslClientConfig, OpensslTicketKey, RollingTicketer, RustlsServerConnectionExt,
};

use super::HttpProxyServerStats;
use super::task::{
    CommonTaskContext, HttpProxyPipelineReaderTask, HttpProxyPipelineStats,
    HttpProxyPipelineWriterTask,
};
use crate::audit::{AuditContext, AuditHandle};
use crate::auth::UserGroup;
use crate::config::server::http_proxy::HttpProxyServerConfig;
use crate::config::server::{AnyServerConfig, ServerConfig};
use crate::escape::ArcEscaper;
use crate::serve::{
    ArcServer, ArcServerInternal, ArcServerStats, Server, ServerInternal, ServerQuitPolicy,
    ServerRegistry, ServerStats, WrapArcServer,
};

/// HTTP 代理服务器实例：负责监听 TCP/QUIC、终结 TLS、按 ACL 过滤入站连接，
/// 并将每条客户端连接拆分为 reader/writer 流水线任务来处理各类代理请求。
pub(crate) struct HttpProxyServer {
    config: Arc<HttpProxyServerConfig>,
    server_stats: Arc<HttpProxyServerStats>,
    listen_stats: Arc<ListenStats>,
    tls_rolling_ticketer: Option<Arc<RollingTicketer<OpensslTicketKey>>>, // TLS 会话票证的滚动密钥，用于 session resumption
    tls_acceptor: Option<TlsAcceptor>, // 为 None 表示该服务器以明文 HTTP 监听
    tls_accept_timeout: Duration,
    tls_client_config: Arc<OpensslClientConfig>, // 代理向源站发起 TLS 连接时使用的客户端配置
    ingress_net_filter: Option<AclNetworkRule>,  // 入站客户端源地址 ACL，不通过则提前丢弃
    dst_host_filter: Option<Arc<AclDstHostRuleSet>>, // 目标主机名 ACL，供任务层检查
    reload_sender: broadcast::Sender<ServerReloadCommand>, // 向监听运行时广播 reload/quit 命令
    task_logger: Option<Logger>,

    escaper: ArcSwap<ArcEscaper>, // 域名逃逸（直连例外）策略，可原地热更新
    user_group: ArcSwapOption<UserGroup>, // 认证用户组，可原地热更新
    audit_handle: ArcSwapOption<AuditHandle>, // 审计日志句柄，可原地热更新
    quit_policy: Arc<ServerQuitPolicy>,
    idle_wheel: Arc<IdleWheel>, // 全局空闲定时器，用于任务超时检测
    reload_version: usize,      // 配置版本号，每次 reload 递增
}

impl HttpProxyServer {
    /// 从已解析的配置构造服务器实例：构建 TLS 服务端/客户端配置、ACL 过滤器，
    /// 并启动空闲定时器 wheel。`version` 为当前 reload 版本号。
    fn new(
        config: Arc<HttpProxyServerConfig>,
        server_stats: Arc<HttpProxyServerStats>,
        listen_stats: Arc<ListenStats>,
        tls_rolling_ticketer: Option<Arc<RollingTicketer<OpensslTicketKey>>>,
        version: usize,
    ) -> anyhow::Result<HttpProxyServer> {
        let reload_sender = crate::serve::new_reload_notify_channel();

        let mut tls_accept_timeout = Duration::from_secs(10);
        let tls_acceptor = if let Some(tls_config_builder) = &config.server_tls_config {
            let tls_server_config = tls_config_builder
                .build_with_alpn_protocols(
                    Some(vec![AlpnProtocol::Http11, AlpnProtocol::Http10]),
                    tls_rolling_ticketer.clone(),
                )
                .context("failed to build tls server config")?;
            tls_accept_timeout = tls_server_config.accept_timeout;
            Some(TlsAcceptor::from(tls_server_config.driver))
        } else {
            None
        };

        let tls_client_config = config
            .client_tls_config
            .build()
            .context("failed to build tls client config")?;

        let ingress_net_filter = config
            .ingress_net_filter
            .as_ref()
            .map(|builder| builder.build());

        let dst_host_filter = config
            .dst_host_filter
            .as_ref()
            .map(|builder| Arc::new(builder.build()));

        let task_logger = config.get_task_logger();
        let idle_wheel = IdleWheel::spawn(config.task_idle_check_interval);

        // always update extra metrics tags
        server_stats.set_extra_tags(config.extra_metrics_tags.clone());

        let escaper = Arc::new(crate::escape::get_or_insert_default(config.escaper()));
        let user_group = config.get_user_group().map(Arc::new);
        let audit_handle = config.get_audit_handle()?;

        let server = HttpProxyServer {
            config,
            server_stats,
            listen_stats,
            tls_rolling_ticketer,
            tls_acceptor,
            tls_accept_timeout,
            tls_client_config: Arc::new(tls_client_config),
            ingress_net_filter,
            dst_host_filter,
            reload_sender,
            task_logger,
            escaper: ArcSwap::new(escaper),
            user_group: ArcSwapOption::new(user_group),
            audit_handle: ArcSwapOption::new(audit_handle),
            quit_policy: Arc::new(ServerQuitPolicy::default()),
            idle_wheel,
            reload_version: version,
        };

        Ok(server)
    }

    /// 首次启动时创建服务器实例（reload 版本号为 1），并按需启动 TLS 票证滚动更新任务。
    pub(crate) fn prepare_initial(
        config: HttpProxyServerConfig,
    ) -> anyhow::Result<ArcServerInternal> {
        let config = Arc::new(config);
        let server_stats = Arc::new(HttpProxyServerStats::new(config.name()));
        let listen_stats = Arc::new(ListenStats::new(config.name()));

        let tls_rolling_ticketer = if let Some(c) = &config.tls_ticketer {
            let ticketer = c
                .build_and_spawn_updater()
                .context("failed to create tls rolling ticketer")?;
            Some(ticketer)
        } else {
            None
        };

        let server =
            HttpProxyServer::new(config, server_stats, listen_stats, tls_rolling_ticketer, 1)?;
        Ok(Arc::new(server))
    }

    /// 用新配置构造下一代服务器实例：复用同一份服务器/监听统计对象，版本号加一。
    fn prepare_reload(&self, config: AnyServerConfig) -> anyhow::Result<HttpProxyServer> {
        if let AnyServerConfig::HttpProxy(config) = config {
            let config = Arc::new(config);
            let server_stats = Arc::clone(&self.server_stats);
            let listen_stats = Arc::clone(&self.listen_stats);

            // ticketer 配置未变化时直接复用旧实例，避免重建密钥滚动任务
            let tls_rolling_ticketer = if self.config.tls_ticketer.eq(&config.tls_ticketer) {
                self.tls_rolling_ticketer.clone()
            } else if let Some(c) = &config.tls_ticketer {
                let ticketer = c
                    .build_and_spawn_updater()
                    .context("failed to create tls rolling ticketer")?;
                Some(ticketer)
            } else {
                None
            };

            let server = HttpProxyServer::new(
                config,
                server_stats,
                listen_stats,
                tls_rolling_ticketer,
                self.reload_version + 1,
            )?;
            Ok(server)
        } else {
            Err(anyhow!(
                "config type mismatch: expect {}, actual {}",
                self.config.r#type(),
                config.r#type()
            ))
        }
    }

    /// 为单条客户端连接组装任务公共上下文；escaper 等可热更新组件在此取当前快照。
    fn get_common_task_context(&self, cc_info: ClientConnectionInfo) -> Arc<CommonTaskContext> {
        Arc::new(CommonTaskContext {
            server_config: self.config.clone(),
            server_stats: self.server_stats.clone(),
            server_quit_policy: self.quit_policy.clone(),
            idle_wheel: self.idle_wheel.clone(),
            escaper: self.escaper.load().as_ref().clone(),
            cc_info,
            tls_client_config: self.tls_client_config.clone(),
            task_logger: self.task_logger.clone(),
            dst_host_filter: self.dst_host_filter.clone(),
        })
    }

    /// 检查客户端源地址是否被入站 ACL 禁止；命中禁止规则时计一次丢弃并返回 true，
    /// 调用方据此在建立任何任务前直接关闭连接（提前丢弃）。
    fn drop_early(&self, client_addr: SocketAddr) -> bool {
        if let Some(ingress_net_filter) = &self.ingress_net_filter {
            let (_, action) = ingress_net_filter.check(client_addr.ip());
            match action {
                AclAction::Permit | AclAction::PermitAndLog => {}
                AclAction::Forbid | AclAction::ForbidAndLog => {
                    self.listen_stats.add_dropped();
                    return true;
                }
            }
        }

        // TODO add cps limit

        false
    }

    /// 为单条流水线创建审计上下文，快照当前（可热更新的）审计句柄。
    fn audit_context(&self) -> AuditContext {
        AuditContext::new(self.audit_handle.load_full())
    }

    /// 将一条完成 TLS 终结（或明文）的双向流拆分为读写两半：
    /// reader 任务解析 HTTP 请求并通过 channel 派发子任务，writer 任务串行写回响应。
    /// reader 以后台任务运行，writer 在当前协程中 await，直至流水线结束。
    async fn spawn_stream_task<T>(&self, stream: T, cc_info: ClientConnectionInfo)
    where
        T: AsyncStream,
        T::R: AsyncRead + Send + Sync + Unpin + 'static,
        T::W: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let ctx = self.get_common_task_context(cc_info);
        let pipeline_stats = Arc::new(HttpProxyPipelineStats::default());
        // channel 容量即流水线深度：允许同时有 pipeline_size 个请求在处理中
        let (task_sender, task_receiver) = mpsc::channel(ctx.server_config.pipeline_size.get());

        // NOTE tls underlying traffic is not counted in (server/task/user) stats

        let (clt_r, clt_w) = stream.into_split();
        let r_task = HttpProxyPipelineReaderTask::new(&ctx, task_sender, clt_r, &pipeline_stats);
        let w_task = HttpProxyPipelineWriterTask::new(
            &ctx,
            self.audit_context(),
            self.user_group.load_full(),
            task_receiver,
            clt_w,
            &pipeline_stats,
        );

        // reader 后台运行，writer 在当前任务中等待至连接结束
        tokio::spawn(r_task.into_running());
        w_task.into_running().await
    }

    /// QUIC 版本的流水线：QUIC 双向流的收发半本身相互独立，
    /// 因此 reader 与 writer 两个任务都以后台任务 spawn，本函数立即返回。
    #[cfg(feature = "quic")]
    fn spawn_quic_stream_task(
        &self,
        send_stream: quinn::SendStream,
        recv_stream: quinn::RecvStream,
        cc_info: ClientConnectionInfo,
    ) {
        let ctx = self.get_common_task_context(cc_info);
        let pipeline_stats = Arc::new(HttpProxyPipelineStats::default());
        let (task_sender, task_receiver) = mpsc::channel(ctx.server_config.pipeline_size.get());

        let r_task =
            HttpProxyPipelineReaderTask::new(&ctx, task_sender, recv_stream, &pipeline_stats);
        tokio::spawn(r_task.into_running());

        let w_task = HttpProxyPipelineWriterTask::new(
            &ctx,
            self.audit_context(),
            self.user_group.load_full(),
            task_receiver,
            send_stream,
            &pipeline_stats,
        );
        tokio::spawn(w_task.into_running());
    }
}

/// 服务器内部生命周期接口：配置克隆、依赖关系、热更新（reload）与运行时的启动/中止。
impl ServerInternal for HttpProxyServer {
    fn _clone_config(&self) -> AnyServerConfig {
        AnyServerConfig::HttpProxy(self.config.as_ref().clone())
    }

    fn _depend_on_server(&self, _name: &NodeName) -> bool {
        false
    }

    fn _reload_config_notify_runtime(&self) {
        let cmd = ServerReloadCommand::ReloadVersion(self.reload_version);
        let _ = self.reload_sender.send(cmd);
    }

    fn _update_next_servers_in_place(&self) {} // http_proxy 无下游服务器依赖，空实现

    /// escaper / user_group / audit_handle 这类不依赖监听运行时的组件，
    /// 通过 ArcSwap 在新旧实例间共享地原地替换，无需重建服务器。
    fn _update_escaper_in_place(&self) {
        let escaper = crate::escape::get_or_insert_default(self.config.escaper());
        self.escaper.store(Arc::new(escaper));
    }

    fn _update_user_group_in_place(&self) {
        self.user_group
            .store(self.config.get_user_group().map(Arc::new));
    }

    fn _update_audit_handle_in_place(&self) -> anyhow::Result<()> {
        let audit_handle = self.config.get_audit_handle()?;
        self.audit_handle.store(audit_handle);
        Ok(())
    }

    /// reload 但复用旧实例的 reload_sender（旧 notifier）：适用于监听配置未变化，
    /// 旧监听运行时继续存活，新实例通过同一 channel 接收后续的 reload/quit 命令。
    fn _reload_with_old_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let mut server = self.prepare_reload(config)?;
        server.reload_sender = self.reload_sender.clone();
        Ok(Arc::new(server))
    }

    /// reload 并使用新实例自带的 reload_sender（新 notifier）：适用于监听配置变化，
    /// 旧监听运行时被替换，新版服务器将用新 channel 驱动重新拉起的监听任务。
    fn _reload_with_new_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let server = self.prepare_reload(config)?;
        Ok(Arc::new(server))
    }

    /// 启动 TCP 监听运行时并为每个监听地址派生实例；成功后将服务器标记为在线。
    /// 未配置 listen 时（如仅作为 escape 目标）直接返回。
    fn _start_runtime(&self, server: ArcServer) -> anyhow::Result<()> {
        let Some(listen_config) = &self.config.listen else {
            return Ok(());
        };
        let listen_stats = server.get_listen_stats();
        let runtime = ListenTcpRuntime::new(WrapArcServer(server), listen_stats);
        runtime
            .run_all_instances(
                listen_config,
                self.config.listen_in_worker,
                &self.reload_sender,
            )
            .map(|_| self.server_stats.set_online())
    }

    /// 中止监听运行时：广播退出命令并把服务器标记为离线。
    fn _abort_runtime(&self) {
        let _ = self.reload_sender.send(ServerReloadCommand::QuitRuntime);
        self.server_stats.set_offline();
    }
}

/// 服务器基础信息接口：名称、类型与当前 reload 版本号。
impl BaseServer for HttpProxyServer {
    #[inline]
    fn name(&self) -> &NodeName {
        self.config.name()
    }

    #[inline]
    fn r#type(&self) -> &'static str {
        self.config.r#type()
    }

    #[inline]
    fn version(&self) -> usize {
        self.reload_version
    }
}

/// 处理明文 TCP 及 openssl 终结的 TLS TCP 连接。
#[async_trait]
impl AcceptTcpServer for HttpProxyServer {
    /// TCP 连接入口：统计连接、ACL 提前丢弃检查，配置了 TLS 时先完成握手再进入流水线。
    async fn run_tcp_task(&self, stream: TcpStream, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }

        if let Some(tls_acceptor) = &self.tls_acceptor {
            match tokio::time::timeout(self.tls_accept_timeout, tls_acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    if tls_stream.get_ref().1.session_reused() {
                        // Quick ACK is needed with session resumption
                        // TLS 会话恢复时客户端在握手最后一条消息后即发数据，
                        // 关闭 TCP 延迟确认（quick ack）以避免首个请求被延迟
                        cc_info.tcp_sock_try_quick_ack();
                    }
                    self.spawn_stream_task(tls_stream, cc_info).await
                }
                Ok(Err(e)) => {
                    self.listen_stats.add_failed();
                    debug!(
                        "{} - {} tls error: {e:?}",
                        cc_info.sock_local_addr(),
                        cc_info.sock_peer_addr()
                    );
                    // TODO record tls failure and add some sec policy
                }
                Err(_) => {
                    self.listen_stats.add_timeout();
                    debug!(
                        "{} - {} tls timeout",
                        cc_info.sock_local_addr(),
                        cc_info.sock_peer_addr()
                    );
                    // TODO record tls failure and add some sec policy
                }
            }
        } else {
            self.spawn_stream_task(stream, cc_info).await;
        }
    }
}

/// 处理 QUIC 连接：单个连接内循环 accept 双向流，每条流各自派发流水线任务。
#[async_trait]
impl AcceptQuicServer for HttpProxyServer {
    /// QUIC 连接入口：ACL 检查通过后持续接受客户端发起的双向流，直到连接出错。
    #[cfg(feature = "quic")]
    async fn run_quic_task(&self, connection: Connection, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }

        loop {
            // TODO update ctx and quit gracefully
            match connection.accept_bi().await {
                Ok((send_stream, recv_stream)) => {
                    self.spawn_quic_stream_task(send_stream, recv_stream, cc_info.clone())
                }
                Err(e) => {
                    debug!(
                        "{} - {} quic connection error: {e:?}",
                        cc_info.sock_local_addr(),
                        cc_info.sock_peer_addr()
                    );
                    break;
                }
            }
        }
    }
}

/// 服务器对外查询接口：依赖组件名称、统计对象与存活任务数；
/// 同时处理由监听层（rustls/openssl 配置）预先完成 TLS 握手的连接。
#[async_trait]
impl Server for HttpProxyServer {
    fn escaper(&self) -> &NodeName {
        self.config.escaper()
    }

    fn user_group(&self) -> &NodeName {
        self.config.user_group()
    }

    fn auditor(&self) -> &NodeName {
        self.config.auditor()
    }

    fn get_server_stats(&self) -> Option<ArcServerStats> {
        Some(self.server_stats.clone())
    }

    fn get_listen_stats(&self) -> Arc<ListenStats> {
        Arc::clone(&self.listen_stats)
    }

    fn alive_count(&self) -> i32 {
        self.server_stats.get_alive_count()
    }

    #[inline]
    fn quit_policy(&self) -> &Arc<ServerQuitPolicy> {
        &self.quit_policy
    }

    /// rustls 已在监听层完成握手，ACL 检查后直接进入流水线。
    async fn run_rustls_task(&self, stream: TlsStream<TcpStream>, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }

        self.spawn_stream_task(stream, cc_info).await;
    }

    /// openssl 已在监听层完成握手，ACL 检查后直接进入流水线。
    async fn run_openssl_task(&self, stream: SslStream<TcpStream>, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }

        self.spawn_stream_task(stream, cc_info).await;
    }
}
