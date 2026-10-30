/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use anyhow::Context;

use g3_dpi::ProtocolPortMap;
use g3_icap_client::IcapServiceClient;
use g3_types::metrics::NodeName;
use g3_types::net::{OpensslTicketKey, RollingTicketer};

use crate::config::audit::AuditorConfig;
use crate::inspect::tls::TlsInterceptionContext;

// 审计模块：把一组"内容检查 / 拦截"能力（协议识别端口表、TLS 中间人、ICAP 适配、QUIC 引流）
// 打包成名为 auditor 的配置节点，供代理任务在命中审计时取用。
// 节点可被热加载替换：reload 只影响后续新任务，已在运行的任务持有旧句柄继续工作。

mod ops; // 审计节点的配置装载与热加载（load_all / reload）
pub use ops::load_all;
pub(crate) use ops::reload;

mod registry; // 进程内的 "auditor 名 -> 实例" 注册表，是热加载与依赖通知的查询入口
pub(crate) use registry::{get_names, get_or_insert_default};

mod handle; // AuditHandle：单个任务本次审计所要使用的资源快照
pub(crate) use handle::AuditHandle;

#[cfg(feature = "quic")]
mod detour; // QUIC 引流检测：将连接交给外部检测服务，按其裁决决定继续/旁路/阻断
#[cfg(feature = "quic")]
pub(crate) use detour::DetourAction;
#[cfg(feature = "quic")]
use detour::StreamDetourClient;

/// 一个审计节点的运行时实例：配置 + 由该配置派生出的各类客户端资源。
///
/// 实例本身不可变（字段全为 Arc/Option<Arc>），reload 的方式是构造新实例替换注册表里的旧值。
pub(crate) struct Auditor {
    config: Arc<AuditorConfig>, // 节点原始配置：reload 时用于比对，句柄也直接引用它读取各项检查参数
    server_tcp_portmap: Arc<ProtocolPortMap>, // 服务端常见端口 -> 协议映射，用于按目的端口识别协议
    client_tcp_portmap: Arc<ProtocolPortMap>, // 客户端常见端口 -> 协议映射
    tls_rolling_ticketer: Option<Arc<RollingTicketer<OpensslTicketKey>>>, // TLS session ticket 密钥轮转器，后台任务定期更换密钥
    icap_reqmod_service: Option<Arc<IcapServiceClient>>, // ICAP REQMOD：请求内容改写服务
    icap_respmod_service: Option<Arc<IcapServiceClient>>, // ICAP RESPMOD：响应内容改写服务
    #[cfg(feature = "quic")]
    stream_detour_service: Option<Arc<StreamDetourClient>>, // 引流检测服务客户端（内含 QUIC 连接池）
}

impl Auditor {
    /// 构造一个只有默认配置的空审计节点。
    ///
    /// 用于按名字查不到审计节点时兜底（见 registry::get_or_insert_default），
    /// 此时仅有端口映射表，其余检查/拦截能力均为 None，即"不审计"。
    fn new_no_config(name: &NodeName) -> Arc<Self> {
        let config = AuditorConfig::empty(name);
        let server_tcp_portmap = Arc::new(config.server_tcp_portmap.clone());
        let client_tcp_portmap = Arc::new(config.client_tcp_portmap.clone());
        let auditor = Auditor {
            config: Arc::new(config),
            server_tcp_portmap,
            client_tcp_portmap,
            tls_rolling_ticketer: None,
            icap_reqmod_service: None,
            icap_respmod_service: None,
            #[cfg(feature = "quic")]
            stream_detour_service: None,
        };
        Arc::new(auditor)
    }

    /// 按配置首次创建审计节点：建立密钥轮转器等后台资源，并初始化外部服务客户端。
    fn new_with_config(config: AuditorConfig) -> anyhow::Result<Arc<Self>> {
        // 端口表从配置中拆出来单独 Arc 化，便于直接共享给任务句柄而无需再复制
        let server_tcp_portmap = Arc::new(config.server_tcp_portmap.clone());
        let client_tcp_portmap = Arc::new(config.client_tcp_portmap.clone());
        let tls_rolling_ticketer = if let Some(c) = &config.tls_ticketer {
            let ticketer = c
                .build_and_spawn_updater()
                .context("failed to create tls rolling ticketer")?;
            Some(ticketer)
        } else {
            None
        };
        let mut auditor = Auditor {
            config: Arc::new(config),
            server_tcp_portmap,
            client_tcp_portmap,
            tls_rolling_ticketer,
            icap_reqmod_service: None,
            icap_respmod_service: None,
            #[cfg(feature = "quic")]
            stream_detour_service: None,
        };
        auditor.set_agent_clients()?;
        Ok(Arc::new(auditor))
    }

    /// 用新配置生成替换实例，并把构造结果写入注册表的动作留给调用方（ops 模块）。
    ///
    /// 注意：这是"新建一个 Auditor"而非原地修改，旧实例上已派生的任务句柄不受影响。
    fn reload(&self, config: AuditorConfig) -> anyhow::Result<Arc<Self>> {
        let server_tcp_portmap = Arc::new(config.server_tcp_portmap.clone());
        let client_tcp_portmap = Arc::new(config.client_tcp_portmap.clone());
        let tls_rolling_ticketer = if self.config.tls_ticketer.eq(&config.tls_ticketer) {
            // 密钥轮转配置未变则沿用旧的轮转器：避免重启轮转任务、导致已发放的 ticket 立即失效
            self.tls_rolling_ticketer.clone()
        } else if let Some(c) = &config.tls_ticketer {
            let ticketer = c
                .build_and_spawn_updater()
                .context("failed to create tls rolling ticketer")?;
            Some(ticketer)
        } else {
            None
        };
        let mut auditor = Auditor {
            config: Arc::new(config),
            server_tcp_portmap,
            client_tcp_portmap,
            tls_rolling_ticketer,
            icap_reqmod_service: None,
            icap_respmod_service: None,
            #[cfg(feature = "quic")]
            stream_detour_service: None,
        };
        auditor.set_agent_clients()?;
        Ok(Arc::new(auditor))
    }

    /// 依据配置连接（初始化）外部检查服务客户端：ICAP REQMOD/RESPMOD 与 QUIC 引流服务。
    ///
    /// 引流客户端初始化时会 spawn 其 QUIC 连接池任务，因此该调用对 ICAP 只建对象、
    /// 对引流会真正拉起后台连接维护任务。
    fn set_agent_clients(&mut self) -> anyhow::Result<()> {
        if let Some(c) = self.config.icap_reqmod_service.clone() {
            self.icap_reqmod_service = Some(Arc::new(
                IcapServiceClient::new(c).context("failed to create ICAP REQMOD client")?,
            ));
        }
        if let Some(c) = self.config.icap_respmod_service.clone() {
            self.icap_respmod_service = Some(Arc::new(
                IcapServiceClient::new(c).context("failed to create ICAP RESPMOD client")?,
            ));
        }
        // 该客户端内部会 spawn QUIC 连接池任务，持续维持到引流服务的最小空闲连接
        #[cfg(feature = "quic")]
        if let Some(c) = self.config.stream_detour_service.clone() {
            let client = StreamDetourClient::new(c)?;
            self.stream_detour_service = Some(Arc::new(client));
        }
        Ok(())
    }

    /// 由审计节点派生出一个任务可用的资源句柄。
    ///
    /// 调用时机是引用该 auditor 的节点（服务器实例 / escape 任务）装载配置时，每个节点一份，
    /// 其下所有任务共享同一个句柄。
    ///
    /// 若配置了 TLS 中间人：启动证书签发（cert agent）任务，并用它 + 客户端/服务端 TLS 配置
    /// 组装 TlsInterceptionContext 装入句柄。未配置时句柄中 tls_interception 为 None，
    /// 表示只做明文协议检查、不做 TLS 拦截。
    pub(crate) fn build_handle(&self) -> anyhow::Result<Arc<AuditHandle>> {
        let mut handle = AuditHandle::new(self);

        if let Some(cert_agent_config) = &self.config.tls_cert_agent {
            // 签发任务后台运行，按 SNI 动态生成中间人证书；
            // 服务端 TLS 配置的 session ticket 由本节点的密钥轮转器提供密钥，密钥按周期自动更换
            let cert_agent = cert_agent_config
                .spawn_cert_agent()
                .context("failed to spawn cert generator task")?;
            let client_config = self
                .config
                .tls_interception_client
                .build()
                .context("failed to build tls client config")?;
            let server_config = self
                .config
                .tls_interception_server
                .build_with_ticketer(self.tls_rolling_ticketer.as_ref())
                .context("failed to build tls server config")?;
            let ctx = TlsInterceptionContext::new(
                cert_agent,
                client_config,
                server_config,
                self.config.tls_stream_dump,
            )?;
            handle.set_tls_interception(ctx);
        }

        Ok(Arc::new(handle))
    }
}

#[derive(Clone, Default)]
pub(crate) struct AuditContext {
    handle: Option<Arc<AuditHandle>>, // 本任务的审计资源；被 take 走后置空，保证只审计一次
}

impl AuditContext {
    /// 任务级审计上下文：服务器在创建任务时把当前生效的句柄放入（无 auditor 时为 None）。
    pub(crate) fn new(handle: Option<Arc<AuditHandle>>) -> Self {
        AuditContext { handle }
    }

    pub(crate) fn set_handle(&mut self, handle: Arc<AuditHandle>) {
        self.handle = Some(handle);
    }

    /// 只读取句柄，不消耗、也不做采样判断。
    pub(crate) fn handle(&self) -> Option<&Arc<AuditHandle>> {
        self.handle.as_ref()
    }

    /// 按 task_audit_ratio 采样决定是否真正执行审计：
    /// 无论结果如何句柄都会被取走（避免后续阶段重复审计），
    /// 只有命中采样的任务才拿到句柄去执行检查/拦截。
    pub(crate) fn check_take_handle(&mut self) -> Option<Arc<AuditHandle>> {
        self.handle.take().filter(|handle| handle.do_task_audit())
    }
}
