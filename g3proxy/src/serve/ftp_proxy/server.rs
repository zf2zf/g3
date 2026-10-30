/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP 代理服务器：负责监听端口、解析配置、按客户端地址做准入过滤，
//! 并为每条入站连接派发一个 [`FtpProxyTask`] 来处理控制通道。
//!
//! 服务器的静态配置保存在 [`FtpProxyServerConfig`] 中；逃逸器（escaper）与
//! 审计句柄（audit handle）通过 `ArcSwap` 保存，支持不重启的热加载。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

use g3_daemon::listen::{AcceptQuicServer, AcceptTcpServer, ListenStats, ListenTcpRuntime};
use g3_daemon::server::{BaseServer, ClientConnectionInfo, ServerExt, ServerReloadCommand};
use g3_io_ext::IdleWheel;
use g3_types::acl::{AclAction, AclNetworkRule};
use g3_types::collection::{SelectiveVec, SelectiveVecBuilder};
use g3_types::metrics::NodeName;

use super::stats::FtpProxyServerStats;
use super::task::FtpProxyTask;
use crate::audit::AuditHandle;
use crate::config::server::ftp_proxy::FtpProxyServerConfig;
use crate::config::server::{AnyServerConfig, ServerConfig};
use crate::escape::ArcEscaper;
use crate::serve::{
    ArcServer, ArcServerInternal, ArcServerStats, Server, ServerInternal, ServerQuitPolicy,
    ServerRegistry, ServerStats, WrapArcServer,
};

/// FTP 代理服务器实例。
///
/// 一个实例对应配置文件中一个 `ftp-proxy` 节点，可派生多个监听线程；
/// 实例本身通过 `Arc` 在监听任务与热加载流程之间共享。
pub(crate) struct FtpProxyServer {
    /// 静态配置
    config: Arc<FtpProxyServerConfig>,
    /// 服务器级统计
    server_stats: Arc<FtpProxyServerStats>,
    /// 监听层统计（accept / drop 计数）
    listen_stats: Arc<ListenStats>,
    /// 上游 FTP 服务器列表，每条控制连接建立时从中挑选一台
    upstream: SelectiveVec<g3_types::net::WeightedUpstreamAddr>,
    /// 入站源地址过滤规则，不匹配的客户端在建连早期即被丢弃
    ingress_net_filter: Option<AclNetworkRule>,
    /// 向监听运行时下发热加载/退出命令的广播通道
    reload_sender: broadcast::Sender<ServerReloadCommand>,
    /// 任务级日志器，配置未开启时为 None
    task_logger: Option<slog::Logger>,

    /// 上游逃逸器（决定用哪条出口路径连接上游），支持热更新
    escaper: ArcSwap<ArcEscaper>,
    /// ICAP 等审计能力的句柄，支持热更新
    audit_handle: ArcSwapOption<AuditHandle>,
    /// 退出策略：是否要求强制切断存量任务
    quit_policy: Arc<ServerQuitPolicy>,
    /// 空闲检测定时器，所有任务共用一个时间轮
    idle_wheel: Arc<IdleWheel>,
    /// 当前配置版本号，每次热加载 +1
    reload_version: usize,
}

impl FtpProxyServer {
    /// 由配置构造服务器实例。
    ///
    /// 会在此处完成：上游列表校验、入站过滤规则编译、时间轮启动、
    /// 逃逸器与审计句柄的首次解析，以及指标标签的初始化。
    fn new(
        config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        listen_stats: Arc<ListenStats>,
        version: usize,
    ) -> anyhow::Result<FtpProxyServer> {
        let reload_sender = crate::serve::new_reload_notify_channel();

        // 展开上游列表；一个都没有则视为配置错误
        let mut nodes_builder = SelectiveVecBuilder::new();
        for node in &config.upstream {
            nodes_builder.insert(node.clone());
        }
        let upstream = nodes_builder
            .build()
            .ok_or_else(|| anyhow!("no upstream ftp server set"))?;

        // 编译入站源地址过滤规则（ACL）
        let ingress_net_filter = config
            .ingress_net_filter
            .as_ref()
            .map(|builder| builder.build());

        let task_logger = config.get_task_logger();
        // 启动空闲检测时间轮，所有任务共享，按配置周期 tick
        let idle_wheel = IdleWheel::spawn(config.task_idle_check_duration);

        let escaper = Arc::new(crate::escape::get_or_insert_default(config.escaper()));
        // 审计句柄可能尚未就绪，这里不阻断启动，后续热加载时再补
        let audit_handle = ArcSwapOption::from(config.get_audit_handle().ok().flatten());

        server_stats.set_extra_tags(config.extra_metrics_tags.clone());

        let server = FtpProxyServer {
            config,
            server_stats,
            listen_stats,
            upstream,
            ingress_net_filter,
            reload_sender,
            task_logger,
            escaper: ArcSwap::new(escaper),
            audit_handle,
            quit_policy: Arc::new(ServerQuitPolicy::default()),
            idle_wheel,
            reload_version: version,
        };

        Ok(server)
    }

    #[allow(private_interfaces)]
    /// 首次加载配置时创建服务器实例（版本号为 1）。
    #[allow(private_interfaces)]
    pub(crate) fn prepare_initial(
        config: FtpProxyServerConfig,
    ) -> anyhow::Result<ArcServerInternal> {
        let config = Arc::new(config);
        let server_stats = FtpProxyServerStats::new(config.name());
        let listen_stats = Arc::new(ListenStats::new(config.name()));

        let server = FtpProxyServer::new(config, server_stats, listen_stats, 1)?;
        Ok(Arc::new(server))
    }

    /// 用新配置构造一个替换实例，复用旧的统计对象，版本号 +1。
    /// 配置类型不是 FTP 代理时返回错误。
    fn prepare_reload(&self, config: AnyServerConfig) -> anyhow::Result<FtpProxyServer> {
        if let AnyServerConfig::FtpProxy(config) = config {
            let config = Arc::new(config);
            // 统计对象跨热加载沿用，保证指标连续
            let server_stats = Arc::clone(&self.server_stats);
            let listen_stats = Arc::clone(&self.listen_stats);

            let server =
                FtpProxyServer::new(config, server_stats, listen_stats, self.reload_version + 1)?;
            Ok(server)
        } else {
            Err(anyhow!(
                "config type mismatch: expect {}, actual {}",
                self.config.r#type(),
                config.r#type()
            ))
        }
    }

    /// 建连阶段的准入检查：客户端源地址命中禁止规则时直接丢弃并计数。
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
        false
    }

    /// 取一份当前审计句柄的快照，包装成任务可用的审计上下文。
    fn audit_context(&self) -> crate::audit::AuditContext {
        crate::audit::AuditContext::new(self.audit_handle.load_full())
    }

    /// 在已建立的（可能是 TLS 的）客户端流上运行一个 FTP 代理任务。
    async fn run_task_with_stream<T>(&self, stream: T, cc_info: ClientConnectionInfo)
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Pick the upstream FTP server
        // 按配置的策略从上游列表中挑选一台 FTP 服务器
        let upstream = self
            .select_consistent(
                &self.upstream,
                g3_types::collection::SelectivePickPolicy::Random,
                &cc_info,
            )
            .inner()
            .clone();

        let escaper = self.escaper.load().as_ref().clone();
        let idle_wheel = self.idle_wheel.clone();
        let task_logger = self.task_logger.clone();
        let server_config = self.config.clone();
        let server_stats = self.server_stats.clone();
        let quit_policy = self.quit_policy.clone();

        // Build TLS upstream config if configured
        // 配置了上游 TLS 时才构造客户端配置；此处 build 失败说明配置在加载阶段
        // 就应被校验掉，理论上不可达，故直接 panic 暴露问题。
        let tls_upstream_config = self.config.tls_upstream.as_ref().map(|builder| {
            // Error here means config validation failed at load time, which shouldn't happen
            let config = builder.build().expect("tls_upstream config build failed");
            Arc::new(config)
        });
        let tls_upstream_type = self.config.tls_upstream_type;

        // 拆分客户端流为读写两半，分别交给任务与并发子任务使用
        let (clt_r, clt_w) = tokio::io::split(stream);

        let audit_ctx = self.audit_context();

        let task = FtpProxyTask::new(
            server_config,
            server_stats,
            quit_policy,
            idle_wheel,
            escaper,
            cc_info,
            upstream,
            audit_ctx,
            task_logger,
            tls_upstream_config,
            tls_upstream_type,
        );

        // 任务内部自行完成上游建连与控制通道转发，出错不向上抛
        task.into_running(clt_r, clt_w).await;
    }
}

impl ServerInternal for FtpProxyServer {
    /// 导出当前配置的副本，用于配置比对与持久化
    fn _clone_config(&self) -> AnyServerConfig {
        AnyServerConfig::FtpProxy(self.config.as_ref().clone())
    }

    /// FTP 代理不依赖其它服务器节点
    fn _depend_on_server(&self, _name: &NodeName) -> bool {
        false
    }

    /// 通知监听运行时重新加载：广播当前版本号，监听线程据此替换实例
    fn _reload_config_notify_runtime(&self) {
        let cmd = ServerReloadCommand::ReloadVersion(self.reload_version);
        let _ = self.reload_sender.send(cmd);
    }

    fn _update_next_servers_in_place(&self) {}

    /// 热加载时就地替换逃逸器，存量监听无需重建
    fn _update_escaper_in_place(&self) {
        let escaper = crate::escape::get_or_insert_default(self.config.escaper());
        self.escaper.store(Arc::new(escaper));
    }

    fn _update_user_group_in_place(&self) {}

    /// 热加载时就地替换审计句柄
    fn _update_audit_handle_in_place(&self) -> anyhow::Result<()> {
        let audit_handle = self.config.get_audit_handle()?;
        self.audit_handle.store(audit_handle);
        Ok(())
    }

    /// 用旧的通知通道完成热加载（监听线程不变）
    fn _reload_with_old_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let mut server = self.prepare_reload(config)?;
        server.reload_sender = self.reload_sender.clone();
        Ok(Arc::new(server))
    }

    /// 用新构造的通知通道完成热加载（监听线程需要重建）
    fn _reload_with_new_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let server = self.prepare_reload(config)?;
        Ok(Arc::new(server))
    }

    /// 启动监听运行时：未配置 `listen` 时不启动任何监听，直接返回成功。
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

    /// 中止运行时：广播退出命令并把服务器标记为下线
    fn _abort_runtime(&self) {
        let _ = self.reload_sender.send(ServerReloadCommand::QuitRuntime);
        self.server_stats.set_offline();
    }
}

impl BaseServer for FtpProxyServer {
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

impl ServerExt for FtpProxyServer {}

#[async_trait]
impl AcceptTcpServer for FtpProxyServer {
    /// 明文 FTP：处理一条新的 TCP 控制连接
    async fn run_tcp_task(&self, stream: TcpStream, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }
}

#[async_trait]
impl AcceptQuicServer for FtpProxyServer {
    /// FTP 不支持 QUIC，空实现
    async fn run_quic_task(&self, _connection: quinn::Connection, _cc_info: ClientConnectionInfo) {}
}

#[async_trait]
impl Server for FtpProxyServer {
    fn escaper(&self) -> &NodeName {
        self.config.escaper()
    }

    /// FTP 代理不使用用户组（认证串由控制通道原样透传）
    fn user_group(&self) -> &NodeName {
        Default::default()
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

    /// 隐式 FTPS（rustls）：TLS 握手已在监听层完成，直接复用为控制连接
    async fn run_rustls_task(
        &self,
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        cc_info: ClientConnectionInfo,
    ) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }

    /// 隐式 FTPS（openssl）：同上，仅 TLS 后端不同
    async fn run_openssl_task(
        &self,
        stream: g3_openssl::SslStream<TcpStream>,
        cc_info: ClientConnectionInfo,
    ) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }
}
