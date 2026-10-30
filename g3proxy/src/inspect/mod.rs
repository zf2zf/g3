/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 源站内容检测（inspection）/ 拦截（interception）模块的入口与公共类型。
//!
//! 客户端流量经 TCP 连接进入后，由 `StreamInspection<SC>` 枚举表示当前流
//! 所处的协议检测状态机（未知流、TLS、StartTLS、HTTP/1、HTTP/2、WebSocket、
//! SMTP、IMAP、FTP 等）。真正的驱动循环是
//! [`StreamInspection::into_loop_inspection`]（实现见 stream/mod.rs）：它反复取出
//! 当前状态、调用对应协议对象的 `intercept()`，并把返回的下一个状态继续驱动，
//! 直到出现 `StreamInspection::End`、协议会话自然结束（返回 `None`），
//! 或某个直接终结状态的协议对象返回 `Ok(())`。
//! 主要类型：
//! - `StreamInspectContext<SC>`：单个检测任务的上下文（审计句柄、服务器配置、
//!   空闲检测轮、任务/连接记录、嵌套检测层数等）。
//! - `StreamInspectTaskNotes` / `StreamInspectConnectNotes`：任务级与连接级记录。
//! - `InterceptionError`（见 error.rs）：检测终止时返回的错误。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arcstr::ArcStr;
use slog::Logger;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::{
    H1InterceptionConfig, H2InterceptionConfig, ImapInterceptionConfig, MaybeProtocol,
    ProtocolInspectAction, ProtocolInspector, SmtpInterceptionConfig,
};
use g3_io_ext::IdleWheel;
use g3_types::net::{Host, OpensslClientConfig};

use crate::audit::AuditHandle;
use crate::auth::{User, UserForbiddenStats, UserSite};
use crate::config::server::ServerConfig;
use crate::module::tcp_connect::TcpConnectTaskNotes;
use crate::serve::{ArcServerStats, ServerIdleChecker, ServerTaskNotes};

mod error;
pub(crate) use error::InterceptionError;

pub(crate) mod stream;
pub(crate) use stream::StreamTransitTask;

pub(crate) mod tls;
use tls::TlsInterceptionContext;

pub(crate) mod start_tls;
use start_tls::StartTlsProtocol;

pub(crate) mod http;
mod websocket;

pub(crate) mod ftp;
pub(crate) mod imap;
pub(crate) mod smtp;

/// 检测任务关联的用户上下文（认证信息快照）
///
/// 从 serve 层的 `ServerTaskNotes` 中提取，供各协议检测读取用户级配置
/// （超时、站点策略等）；未启用认证时整个上下文为 `None`。
#[derive(Clone)]
pub(super) struct StreamInspectUserContext {
    /// 认证时客户端提交的原始用户名（未经规范化）
    raw_user_name: Option<ArcStr>,
    /// 解析出的用户对象，携带用户级超时/策略配置
    user: Arc<User>,
    /// 用户所属站点配置（可选），优先级高于用户级配置
    user_site: Option<Arc<UserSite>>,
    /// 用户被拦截（forbidden）次数的统计
    forbidden_stats: Arc<UserForbiddenStats>,
}

impl StreamInspectUserContext {
    /// HTTP 响应头接收超时：优先取站点配置，其次用户配置，均无则返回 `None`
    fn http_rsp_hdr_recv_timeout(&self) -> Option<Duration> {
        self.user_site
            .as_ref()
            .and_then(|site| site.http_rsp_hdr_recv_timeout())
            .or(self.user.http_rsp_hdr_recv_timeout())
    }
}

/// 单个检测任务的记录信息（地址、任务 ID、用户上下文）
///
/// 在检测流水线中随上下文 `StreamInspectContext` 一路携带，用于日志、
/// 审计与连接记录。注意 `server_addr` 指本代理服务器监听地址，
/// `client_addr` 指下游客户端地址。
#[derive(Clone)]
pub(crate) struct StreamInspectTaskNotes {
    task_id: Uuid,
    /// 下游客户端地址
    pub(crate) client_addr: SocketAddr,
    /// 本代理服务器监听地址
    pub(crate) server_addr: SocketAddr,
    /// 处理该任务的 worker 线程编号；非多线程部署时为 `None`
    worker_id: Option<usize>,
    /// 用户上下文；未启用认证时为 `None`
    user_ctx: Option<StreamInspectUserContext>,
}

impl StreamInspectTaskNotes {
    /// 认证用户对象；未启用认证或认证失败时返回 `None`
    pub(crate) fn user(&self) -> Option<&Arc<User>> {
        self.user_ctx.as_ref().map(|ctx| &ctx.user)
    }

    /// 原始用户名；无用户上下文或未提供时返回 `None`
    pub(crate) fn raw_username(&self) -> Option<&ArcStr> {
        self.user_ctx
            .as_ref()
            .and_then(|ctx| ctx.raw_user_name.as_ref())
    }

    /// 任务唯一 ID，用于跨日志/审计关联同一任务
    #[inline]
    pub(crate) fn task_id(&self) -> &Uuid {
        &self.task_id
    }
}

impl From<&ServerTaskNotes> for StreamInspectTaskNotes {
    /// 从 serve 层任务记录派生检测任务记录（截断为检测所需的最小信息）
    fn from(task_notes: &ServerTaskNotes) -> Self {
        StreamInspectTaskNotes {
            task_id: task_notes.id,
            client_addr: task_notes.client_addr(),
            server_addr: task_notes.server_addr(),
            worker_id: task_notes.worker_id(),
            user_ctx: task_notes.user_ctx().map(|ctx| StreamInspectUserContext {
                raw_user_name: ctx.raw_user_name().cloned(),
                user: ctx.user().clone(),
                user_site: ctx.user_site().cloned(),
                forbidden_stats: ctx.forbidden_stats().clone(),
            }),
        }
    }
}

/// 连接级别的记录：代理到上游建立 TCP 连接时的两端地址
///
/// 与任务记录不同，这里记录的是"本连接"的源/目的地址，
/// 用于 FTPS 数据通道匹配、拨测（udpdump）等需要按连接定位的场景。
#[derive(Clone, Copy)]
pub(crate) struct StreamInspectConnectNotes {
    /// 本端（代理侧）本地地址
    pub(crate) client_addr: SocketAddr,
    /// 下一跳（上游服务器）地址
    pub(crate) server_addr: SocketAddr,
}

impl From<&TcpConnectTaskNotes> for StreamInspectConnectNotes {
    /// 从 TCP 连接任务记录派生
    ///
    /// `local`/`next` 在连接建立后必然已填充，故此处使用 `unwrap`。
    fn from(tcp_notes: &TcpConnectTaskNotes) -> Self {
        StreamInspectConnectNotes {
            client_addr: tcp_notes.local.unwrap(),
            server_addr: tcp_notes.next.unwrap(),
        }
    }
}

/// 单个检测任务的上下文：聚合检测所需的配置、统计与运行时资源
///
/// 该结构在 `StreamInspection` 状态机各协议对象间传递与克隆；
/// `inspection_depth` 记录嵌套检测层数（如 TLS 拦截后内层再做 HTTP 检测），
/// 防止协议识别无限递归。
pub(crate) struct StreamInspectContext<SC: ServerConfig> {
    /// 审计句柄：提供 TLS 拦截配置、各协议 inspect policy 与拦截配置、日志器
    audit_handle: Arc<AuditHandle>,
    /// 当前 server 的配置
    server_config: Arc<SC>,
    /// server 运行时统计（在线状态、任务数等）
    server_stats: ArcServerStats,
    /// server 退出策略（是否强制终止在途任务）
    server_quit_policy: Arc<ServerQuitPolicy>,
    /// 空闲检测时间轮：用于任务级空闲计时
    idle_wheel: Arc<IdleWheel>,
    /// 任务级记录（地址、task id、用户上下文）
    task_notes: StreamInspectTaskNotes,
    /// 连接级记录（本连接到上游的两端地址）
    connect_notes: StreamInspectConnectNotes,
    /// 当前嵌套检测层数，初值 0；每进入一层内层检测 +1
    inspection_depth: usize,

    /// 允许的空闲任务数上限（用户配置优先，否则取 server 配置）
    max_idle_count: usize,
}

impl<SC: ServerConfig> Clone for StreamInspectContext<SC> {
    /// 全字段克隆：所有成员均为 Arc/Copy/Clone，便于在状态机转移时廉价传递上下文
    fn clone(&self) -> Self {
        StreamInspectContext {
            audit_handle: self.audit_handle.clone(),
            server_config: self.server_config.clone(),
            server_stats: self.server_stats.clone(),
            server_quit_policy: self.server_quit_policy.clone(),
            idle_wheel: self.idle_wheel.clone(),
            task_notes: self.task_notes.clone(),
            connect_notes: self.connect_notes,
            inspection_depth: self.inspection_depth,
            max_idle_count: self.max_idle_count,
        }
    }
}

impl<SC: ServerConfig> StreamInspectContext<SC> {
    /// 构造检测上下文
    ///
    /// `max_idle_count` 优先取用户的空闲任务上限，未认证或用户未配置时
    /// 回退到 server 级配置；`inspection_depth` 初始为 0（最外层检测）。
    pub(crate) fn new(
        audit_handle: Arc<AuditHandle>,
        server_config: Arc<SC>,
        server_stats: ArcServerStats,
        server_quit_policy: Arc<ServerQuitPolicy>,
        idle_wheel: Arc<IdleWheel>,
        task_notes: &ServerTaskNotes,
        tcp_notes: &TcpConnectTaskNotes,
    ) -> Self {
        let max_idle_count = task_notes
            .user_ctx()
            .and_then(|c| c.user().task_max_idle_count())
            .unwrap_or(server_config.task_max_idle_count());

        StreamInspectContext {
            audit_handle,
            server_config,
            server_stats,
            server_quit_policy,
            idle_wheel,
            task_notes: StreamInspectTaskNotes::from(task_notes),
            connect_notes: StreamInspectConnectNotes::from(tcp_notes),
            inspection_depth: 0,
            max_idle_count,
        }
    }

    /// 认证用户的引用；未启用认证时返回 `None`
    #[inline]
    fn user(&self) -> Option<&User> {
        self.task_notes.user().map(|u| u.as_ref())
    }

    /// 克隆认证用户的 `Arc`；无用户上下文时返回 `None`
    fn user_cloned(&self) -> Option<Arc<User>> {
        self.task_notes.user().cloned()
    }

    /// 原始用户名；无用户上下文时返回 `None`
    #[inline]
    fn raw_user_name(&self) -> Option<&ArcStr> {
        self.task_notes.raw_username()
    }

    /// 当前检测任务的唯一 ID
    #[inline]
    pub(crate) fn server_task_id(&self) -> &Uuid {
        self.task_notes.task_id()
    }

    /// server 是否要求强制退出（强制终止在途任务，不再等待）
    #[inline]
    fn server_force_quit(&self) -> bool {
        self.server_quit_policy.force_quit()
    }

    /// server 是否已下线（不再接受新请求，在途任务应尽快结束）
    #[inline]
    fn server_offline(&self) -> bool {
        !self.server_stats.is_online()
    }

    /// 检测（inspection）日志器；未配置日志输出时返回 `None`
    #[inline]
    pub(crate) fn inspect_logger(&self) -> Option<&Logger> {
        self.audit_handle.inspect_logger()
    }

    /// 拦截（interception）日志器；未配置时返回 `None`
    #[inline]
    pub(crate) fn intercept_logger(&self) -> Option<&Logger> {
        self.audit_handle.intercept_logger()
    }

    /// 创建空闲检测器，绑定时间轮、quit 策略与空闲任务上限
    ///
    /// 用于在长时间空闲的检测任务上触发超时回收，避免占用连接资源。
    pub(crate) fn idle_checker(&self) -> ServerIdleChecker {
        ServerIdleChecker::new(
            self.idle_wheel.clone(),
            self.user_cloned(),
            self.max_idle_count,
            self.server_quit_policy.clone(),
        )
    }

    /// 构造协议识别器
    ///
    /// 基于 server/client 端口映射表推断默认协议；若调用方已通过显式协议
    /// （如 StartTLS 升级、端口约定）指定 `explicit_protocol`，则优先入队。
    pub(crate) fn protocol_inspector(
        &self,
        explicit_protocol: Option<MaybeProtocol>,
    ) -> ProtocolInspector {
        let mut inspector = ProtocolInspector::new(
            self.audit_handle.server_tcp_portmap(),
            self.audit_handle.client_tcp_portmap(),
        );
        if let Some(p) = explicit_protocol {
            inspector.push_protocol(p);
        }
        inspector
    }

    /// 当前嵌套检测层数（用于防止检测递归过深）
    #[inline]
    pub(crate) fn current_inspection_depth(&self) -> usize {
        self.inspection_depth
    }

    /// 进入下一层嵌套检测时调用，层数 +1
    ///
    /// 例如 TLS 中间人拦截完成后，对内层明文协议再建一个检测对象。
    #[inline]
    fn increase_inspection_depth(&mut self) {
        self.inspection_depth += 1;
    }

    /// TLS 中间人拦截上下文；server 未启用 TLS 拦截时返回 `None`
    #[inline]
    pub(crate) fn tls_interception(&self) -> Option<TlsInterceptionContext> {
        self.audit_handle.tls_interception()
    }

    /// 用户站点级别的 TLS 客户端配置（用于模拟上游 TLS 指纹）；未配置返回 `None`
    pub(crate) fn user_site_tls_client(&self) -> Option<&OpensslClientConfig> {
        self.task_notes
            .user_ctx
            .as_ref()
            .and_then(|v| v.user_site.as_ref())
            .and_then(|v| v.tls_client())
    }

    /// 记录 URI 时允许的最大字符数：优先用户配置，否则用审计默认值
    fn log_uri_max_chars(&self) -> usize {
        self.task_notes
            .user_ctx
            .as_ref()
            .and_then(|cx| cx.user.log_uri_max_chars())
            .unwrap_or_else(|| self.audit_handle.log_uri_max_chars())
    }

    /// HTTP/1 拦截配置（超时、缓冲区大小等）
    #[inline]
    fn h1_interception(&self) -> &H1InterceptionConfig {
        self.audit_handle.h1_interception()
    }

    /// HTTP/1 响应头接收超时：优先用户/站点配置，否则回退到拦截配置默认值
    fn h1_rsp_hdr_recv_timeout(&self) -> Duration {
        self.task_notes
            .user_ctx
            .as_ref()
            .and_then(|ctx| ctx.http_rsp_hdr_recv_timeout())
            .unwrap_or(self.h1_interception().rsp_head_recv_timeout)
    }

    /// 查询指定 host 的 HTTP/2 检测动作（放行/拦截/忽略等）
    ///
    /// `check` 返回 (是否命中策略, 命中动作)；未命中时返回缺省动作。
    #[inline]
    fn h2_inspect_action(&self, host: &Host) -> ProtocolInspectAction {
        match self.audit_handle.h2_inspect_policy.check(host) {
            (true, policy_action) => policy_action,
            (false, missing_policy_action) => missing_policy_action,
        }
    }

    /// HTTP/2 拦截配置
    #[inline]
    fn h2_interception(&self) -> &H2InterceptionConfig {
        self.audit_handle.h2_interception()
    }

    /// HTTP/2 响应头接收超时：优先用户/站点配置，否则回退到拦截配置默认值
    fn h2_rsp_hdr_recv_timeout(&self) -> Duration {
        self.task_notes
            .user_ctx
            .as_ref()
            .and_then(|ctx| ctx.http_rsp_hdr_recv_timeout())
            .unwrap_or(self.h2_interception().rsp_head_recv_timeout)
    }

    /// 查询指定 host 的 WebSocket 检测动作；同 `h2_inspect_action` 的匹配语义
    #[inline]
    fn websocket_inspect_action(&self, host: &Host) -> ProtocolInspectAction {
        match self.audit_handle.websocket_inspect_policy.check(host) {
            (true, policy_action) => policy_action,
            (false, missing_policy_action) => missing_policy_action,
        }
    }

    /// 查询指定 host 的 SMTP 检测动作
    #[inline]
    fn smtp_inspect_action(&self, host: &Host) -> ProtocolInspectAction {
        match self.audit_handle.smtp_inspect_policy.check(host) {
            (true, policy_action) => policy_action,
            (false, missing_policy_action) => missing_policy_action,
        }
    }

    /// SMTP 拦截配置
    #[inline]
    fn smtp_interception(&self) -> &SmtpInterceptionConfig {
        self.audit_handle.smtp_interception()
    }

    /// 查询指定 host 的 IMAP 检测动作
    #[inline]
    fn imap_inspect_action(&self, host: &Host) -> ProtocolInspectAction {
        match self.audit_handle.imap_inspect_policy.check(host) {
            (true, policy_action) => policy_action,
            (false, missing_policy_action) => missing_policy_action,
        }
    }

    /// IMAP 拦截配置
    #[inline]
    fn imap_interception(&self) -> &ImapInterceptionConfig {
        self.audit_handle.imap_interception()
    }

    /// 当前用户是否已被拉黑
    ///
    /// 用于在检测早期短路：被拉黑的用户应直接拒绝而非继续检测。
    /// 无用户上下文（未认证）时返回 `false`。
    fn belongs_to_blocked_user(&self) -> bool {
        self.task_notes
            .user_ctx
            .as_ref()
            .map(|cx| cx.user.is_blocked())
            .unwrap_or(false)
    }
}

/// 一条流当前所处的协议检测状态机状态
///
/// 检测以"状态转移"的方式推进：每完成一层识别/拦截，`transition()` 返回下一
/// 个状态（或 `End` 终结）。变体按检测层次组织：
/// 未知流 -> TLS/StartTLS -> 应用层协议（HTTP/1、HTTP/2、WebSocket、SMTP、
/// IMAP、FTP 控制/上传数据通道）。嵌套检测（如 TLS 内的 HTTP）会进入更深层。
pub(crate) enum StreamInspection<SC: ServerConfig> {
    /// 检测终结：任务完成或被拒绝，不再转移
    End,
    /// 协议未知，需要继续探测
    StreamUnknown(stream::StreamInspectObject<SC>),
    /// 对未知流做内容探测/审查
    StreamInspect(stream::StreamInspectObject<SC>),
    /// 现代 TLS（基于标准 OpenSSL）中间人拦截
    TlsModern(tls::TlsInterceptObject<SC>),
    /// TLCP（国密 TLS，需 tongsuo 后端）中间人拦截
    #[cfg(feature = "vendored-tongsuo")]
    TlsTlcp(tls::TlsInterceptObject<SC>),
    /// StartTLS：明文协商后升级为 TLS 的拦截
    StartTls(start_tls::StartTlsInterceptObject<SC>),
    /// HTTP/1 请求/响应检测
    H1(http::H1InterceptObject<SC>),
    /// HTTP/2 帧与流检测
    H2(http::H2InterceptObject<SC>),
    /// HTTP/1 Upgrade 得到的 WebSocket 检测
    Websocket(websocket::H1WebsocketInterceptObject<SC>),
    /// SMTP 协议检测
    Smtp(smtp::SmtpInterceptObject<SC>),
    /// IMAP 协议检测
    Imap(imap::ImapInterceptObject<SC>),
    /// FTP 控制通道检测
    Ftp(ftp::FtpInterceptObject<SC>),
    /// FTP/FTPS 上传数据通道检测
    FtpUploadData(ftp::FtpUploadDataInterceptObject<SC>),
}

/// 装箱的读半部：检测对象持有统一的类型擦除 IO，便于在状态机间转移时换装
type BoxAsyncRead = Box<dyn AsyncRead + Send + Sync + Unpin + 'static>;
/// 装箱的写半部：同上
type BoxAsyncWrite = Box<dyn AsyncWrite + Send + Sync + Unpin + 'static>;
