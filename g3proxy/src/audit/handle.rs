/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use slog::Logger;

use g3_dpi::{
    H1InterceptionConfig, H2InterceptionConfig, ImapInterceptionConfig, ProtocolInspectPolicy,
    ProtocolInspectionConfig, ProtocolPortMap, SmtpInterceptionConfig,
};
use g3_icap_client::reqmod::IcapReqmodClient;
use g3_icap_client::respmod::IcapRespmodClient;

use super::Auditor;
#[cfg(feature = "quic")]
use super::StreamDetourClient;
use crate::config::audit::AuditorConfig;
use crate::inspect::tls::TlsInterceptionContext;

/// 任务在一次审计中使用的资源句柄：把 Auditor 的配置与外部服务客户端"按任务需要"重新组合。
///
/// 与 Auditor 的区别在于生命周期：句柄由引用该 auditor 的节点在装载配置时创建
/// （见 Auditor::build_handle），其下各任务从 ArcSwap 槽位取到的是同一份 Arc 引用；
/// auditor 热加载后，已运行任务仍使用旧句柄，
/// 因此不会出现任务执行到一半资源被换掉的情况。
///
/// ICAP 客户端随句柄创建一份，任务以借用（&IcapReqmodClient）方式使用。
pub(crate) struct AuditHandle {
    auditor_config: Arc<AuditorConfig>, // 所属审计节点的配置，下面的取值方法大多直接读它
    server_tcp_portmap: Arc<ProtocolPortMap>,
    client_tcp_portmap: Arc<ProtocolPortMap>,
    tls_interception: Option<TlsInterceptionContext>, // TLS 中间人上下文：证书签发代理 + 客户端/服务端 TLS 配置
    inspect_logger: Option<Logger>,                   // 内容检查（inspect）结果日志
    intercept_logger: Option<Logger>,                 // 内容拦截（intercept）动作日志
    icap_reqmod_client: Option<IcapReqmodClient>,     // 请求改写客户端，节点未配置 ICAP 时为 None
    icap_respmod_client: Option<IcapRespmodClient>,   // 响应改写客户端
    #[cfg(feature = "quic")]
    stream_detour_client: Option<Arc<StreamDetourClient>>, // 引流服务客户端，与节点共享同一连接池
    // 以下协议检查策略在建句柄时由配置 build 一次，任务执行期只做读取，避免逐任务重复构造
    pub(crate) h2_inspect_policy: ProtocolInspectPolicy,
    pub(crate) websocket_inspect_policy: ProtocolInspectPolicy,
    pub(crate) smtp_inspect_policy: ProtocolInspectPolicy,
    pub(crate) imap_inspect_policy: ProtocolInspectPolicy,
}

impl AuditHandle {
    /// 从审计节点派生句柄：克隆各资源的 Arc 引用，并把检查策略实例化。
    ///
    /// TLS 中间人上下文不在此处构造（需要 spawn 签发任务并可能失败），
    /// 由 Auditor::build_handle 通过 set_tls_interception 另行注入。
    pub(super) fn new(auditor: &Auditor) -> Self {
        let icap_reqmod_service = auditor
            .icap_reqmod_service
            .as_ref()
            .map(|c| IcapReqmodClient::new(c.clone()));
        let icap_respmod_service = auditor
            .icap_respmod_service
            .as_ref()
            .map(|c| IcapRespmodClient::new(c.clone()));
        AuditHandle {
            auditor_config: auditor.config.clone(),
            server_tcp_portmap: auditor.server_tcp_portmap.clone(),
            client_tcp_portmap: auditor.client_tcp_portmap.clone(),
            tls_interception: None,
            inspect_logger: crate::log::inspect::get_logger(auditor.config.name()),
            intercept_logger: crate::log::intercept::get_logger(auditor.config.name()),
            icap_reqmod_client: icap_reqmod_service,
            icap_respmod_client: icap_respmod_service,
            #[cfg(feature = "quic")]
            stream_detour_client: auditor.stream_detour_service.clone(),
            h2_inspect_policy: auditor.config.h2_inspect_policy.build(),
            websocket_inspect_policy: auditor.config.websocket_inspect_policy.build(),
            smtp_inspect_policy: auditor.config.smtp_inspect_policy.build(),
            imap_inspect_policy: auditor.config.imap_inspect_policy.build(),
        }
    }

    /// 签发任务与 TLS 配置就绪后由 Auditor::build_handle 注入。
    pub(super) fn set_tls_interception(&mut self, ctx: TlsInterceptionContext) {
        self.tls_interception = Some(ctx);
    }

    // 以下访问器都是对配置/资源的只读封装：检查逻辑只依赖 AuditHandle，
    // 不再直接接触 Auditor 与配置结构，方便任务侧统一处理"未配置即跳过"的分支

    /// 检查日志器：按 auditor 名字取得，未配置该节点的日志时返回 None（不输出检查记录）。
    #[inline]
    pub(crate) fn inspect_logger(&self) -> Option<&Logger> {
        self.inspect_logger.as_ref()
    }

    /// 拦截动作日志器，命名规则同 inspect 日志。
    #[inline]
    pub(crate) fn intercept_logger(&self) -> Option<&Logger> {
        self.intercept_logger.as_ref()
    }

    /// 协议识别（DPI）总配置：各协议的检测开关与超时。
    #[inline]
    pub(crate) fn protocol_inspection(&self) -> &ProtocolInspectionConfig {
        &self.auditor_config.protocol_inspection
    }

    /// 端口映射表按 Arc 返回，任务持有后可在多次检测间复用，无需重复查表克隆。
    #[inline]
    pub(crate) fn server_tcp_portmap(&self) -> Arc<ProtocolPortMap> {
        self.server_tcp_portmap.clone()
    }

    #[inline]
    pub(crate) fn client_tcp_portmap(&self) -> Arc<ProtocolPortMap> {
        self.client_tcp_portmap.clone()
    }

    /// TLS 中间人上下文可整份克隆（内部均为 Arc），任务拿到的是同一份签发代理与 TLS 配置。
    #[inline]
    pub(crate) fn tls_interception(&self) -> Option<TlsInterceptionContext> {
        self.tls_interception.clone()
    }

    /// 写日志时 URI 保留的最大字符数，防止超长 URL 撑爆日志。
    #[inline]
    pub(crate) fn log_uri_max_chars(&self) -> usize {
        self.auditor_config.log_uri_max_chars
    }

    // 以下 h1/h2/smtp/imap_interception 系列方法：返回各协议 interception（拦截）阶段的配置，
    // 由对应协议的检查逻辑使用；这些配置结构由 g3_dpi 提供

    #[inline]
    pub(crate) fn h1_interception(&self) -> &H1InterceptionConfig {
        &self.auditor_config.h1_interception
    }

    #[inline]
    pub(crate) fn h2_interception(&self) -> &H2InterceptionConfig {
        &self.auditor_config.h2_interception
    }

    #[inline]
    pub(crate) fn smtp_interception(&self) -> &SmtpInterceptionConfig {
        &self.auditor_config.smtp_interception
    }

    #[inline]
    pub(crate) fn imap_interception(&self) -> &ImapInterceptionConfig {
        &self.auditor_config.imap_interception
    }

    // 外部服务客户端访问器：返回 None 表示节点未配置该服务，调用方据此跳过对应检查环节

    #[inline]
    pub(crate) fn icap_reqmod_client(&self) -> Option<&IcapReqmodClient> {
        self.icap_reqmod_client.as_ref()
    }

    #[inline]
    pub(crate) fn icap_respmod_client(&self) -> Option<&IcapRespmodClient> {
        self.icap_respmod_client.as_ref()
    }

    #[cfg(feature = "quic")]
    #[inline]
    pub(crate) fn stream_detour_client(&self) -> Option<&Arc<StreamDetourClient>> {
        self.stream_detour_client.as_ref()
    }

    /// 按 task_audit_ratio 做随机采样，决定本任务是否真的执行审计。
    /// 用于在大流量场景下只抽样检查，避免审计成为瓶颈。
    pub(crate) fn do_task_audit(&self) -> bool {
        use rand::distr::Distribution;

        let mut rng = rand::rng();
        self.auditor_config.task_audit_ratio.sample(&mut rng)
    }

    /// 是否为任务开启 TLS 会话密钥记录（用于事后解密分析流量）。
    #[inline]
    pub(crate) fn tls_keylog(&self) -> bool {
        self.auditor_config.tls_keylog.enable
    }

    /// 每个任务的 TLS 密钥日志缓冲最多保留多少条密钥记录（超出后不再记录）。
    #[inline]
    pub(crate) fn tls_keylog_max_entries(&self) -> usize {
        self.auditor_config.tls_keylog.max_entries
    }
}
