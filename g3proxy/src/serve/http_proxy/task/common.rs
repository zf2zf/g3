/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use slog::Logger;
use tokio::time::Instant;

use g3_daemon::server::ClientConnectionInfo;
use g3_icap_client::reqmod::h1::HttpAdapterErrorResponse;
use g3_io_ext::{IdleWheel, OptionalInterval};
use g3_types::acl::AclAction;
use g3_types::acl_set::AclDstHostRuleSet;
use g3_types::net::{OpensslClientConfig, UpstreamAddr};

use super::{HttpProxyServerConfig, HttpProxyServerStats};
use crate::escape::ArcEscaper;
use crate::module::http_forward::HttpProxyClientResponse;
use crate::module::http_header;
use crate::module::tcp_connect::TcpConnectTaskNotes;
use crate::serve::{ServerIdleChecker, ServerQuitPolicy, ServerTaskNotes};

/// 各类 HTTP 子任务的公共上下文：把一次任务运行所需的服务器级共享状态
/// （配置、统计、出口选择器等）与客户端连接信息打包在一起，供任务以 Arc 持有复用。
#[derive(Clone)]
pub(crate) struct CommonTaskContext {
    pub(crate) server_config: Arc<HttpProxyServerConfig>,
    pub(crate) server_stats: Arc<HttpProxyServerStats>,
    /// 服务器退出策略：任务在空闲/等待时可据此感知优雅退出或强制停止
    pub(crate) server_quit_policy: Arc<ServerQuitPolicy>,
    /// 惰性定时器轮子，各任务用它注册空闲检测 interval
    pub(crate) idle_wheel: Arc<IdleWheel>,
    /// 出口选择器：负责为目标地址挑选网络出口（egress）并执行出口级访问控制
    pub(crate) escaper: ArcEscaper,
    /// 客户端连接信息（来源地址、认证用户、是否可信网段等）
    pub(crate) cc_info: ClientConnectionInfo,
    /// 作为上游 HTTPS 客户端时使用的 TLS 配置
    pub(crate) tls_client_config: Arc<OpensslClientConfig>,
    /// 任务日志 logger；为 None 表示不写任务日志
    pub(crate) task_logger: Option<Logger>,

    /// 目标主机的 ACL 规则集（可按用户/会话动态选取），用于 upstream 访问控制
    pub(crate) dst_host_filter: Option<Arc<AclDstHostRuleSet>>,
}

impl CommonTaskContext {
    #[inline]
    pub(crate) fn client_addr(&self) -> SocketAddr {
        self.cc_info.client_addr()
    }

    /// 基于空闲轮子与任务的统计信息创建空闲检测器：
    /// 连续空闲次数超过 task_idle_max_count 时按退出策略处理任务
    pub(crate) fn idle_checker(&self, task_notes: &ServerTaskNotes) -> ServerIdleChecker {
        ServerIdleChecker::new(
            self.idle_wheel.clone(),
            task_notes.user_ctx().map(|c| c.user().clone()),
            self.server_config.task_idle_max_count,
            self.server_quit_policy.clone(),
        )
    }

    /// 对目标 upstream 做端口 + 主机名的访问控制检查，返回最终允许/禁止动作。
    /// 任一规则集命中 forbid 时提前返回；否则将各过滤器结论合并为默认动作。
    pub(crate) fn check_upstream(&self, upstream: &UpstreamAddr) -> AclAction {
        // 目标地址为空（如转发请求缺少 Host）时默认禁止
        let mut default_action = if upstream.is_empty() {
            AclAction::Forbid
        } else {
            AclAction::Permit
        };

        if let Some(filter) = &self.server_config.dst_port_filter {
            let port = upstream.port();
            let (found, action) = filter.check_port(&port);
            if found && action.forbid_early() {
                return action;
            };
            default_action = default_action.restrict(action);
        }

        if let Some(filter) = &self.dst_host_filter {
            let (found, action) = filter.check(upstream.host());
            if found && action.forbid_early() {
                return action;
            }
            default_action = default_action.restrict(action);
        }

        default_action
    }

    /// 在本地产生的错误回复（local reply，如 403/502）中追加自定义头：
    /// 携带服务器 ID、出口连接信息、动态出口信息等，方便客户端/运维定位链路
    pub(crate) fn set_custom_header_for_local_reply(
        &self,
        tcp_notes: &TcpConnectTaskNotes,
        rsp: &mut HttpProxyClientResponse,
    ) {
        if let Some(server_id) = &self.server_config.server_id {
            // X-Remote-Connection-Info: 记录实际使用的本机绑定地址与目标地址
            let line = http_header::remote_connection_info(
                server_id,
                tcp_notes.bind.ip(),
                tcp_notes.local,
                tcp_notes.next,
                &tcp_notes.expire,
            );
            rsp.add_extra_header(line);

            if let Some(egress_info) = &tcp_notes.egress {
                let line = http_header::dynamic_egress_info(server_id, egress_info);
                rsp.add_extra_header(line);
            }
        }

        // 链式代理场景：把上游真实目标地址/出口 IP 也回显给客户端
        if self.server_config.echo_chained_info {
            if let Some(addr) = tcp_notes.chained.target_addr {
                rsp.set_upstream_addr(addr);
            }

            if let Some(addr) = tcp_notes.chained.outgoing_addr {
                rsp.set_outgoing_ip(addr.ip());
            }
        }
    }

    /// 与 set_custom_header_for_local_reply 相同的信息，但写入 ICAP 适配错误回复的头部
    pub(crate) fn set_custom_header_for_adaptation_error_reply(
        &self,
        tcp_notes: &TcpConnectTaskNotes,
        rsp: &mut HttpAdapterErrorResponse,
    ) {
        if let Some(server_id) = &self.server_config.server_id {
            // 直接把链路信息写入 ICAP 错误回复的 header 集合
            http_header::set_remote_connection_info(
                &mut rsp.headers,
                server_id,
                tcp_notes.bind.ip(),
                tcp_notes.local,
                tcp_notes.next,
                &tcp_notes.expire,
            );

            if let Some(egress_info) = &tcp_notes.egress {
                http_header::set_dynamic_egress_info(&mut rsp.headers, server_id, egress_info);
            }
        }

        if self.server_config.echo_chained_info {
            if let Some(addr) = tcp_notes.chained.target_addr {
                http_header::set_upstream_addr(&mut rsp.headers, addr);
            }

            if let Some(addr) = tcp_notes.chained.outgoing_addr {
                http_header::set_outgoing_ip(&mut rsp.headers, addr);
            }
        }
    }

    /// 任务日志定期 flush 的间隔；未配置任务日志时返回 None
    pub(super) fn log_flush_interval(&self) -> Option<Duration> {
        self.task_logger.as_ref()?;
        self.server_config.task_log_flush_interval
    }

    /// 创建用于周期性 flush 任务日志的 interval（首次触发也延迟一个周期）
    pub(super) fn get_log_interval(&self) -> OptionalInterval {
        self.log_flush_interval()
            .map(|log_interval| {
                let log_interval =
                    tokio::time::interval_at(Instant::now() + log_interval, log_interval);
                OptionalInterval::with(log_interval)
            })
            .unwrap_or_default()
    }
}
