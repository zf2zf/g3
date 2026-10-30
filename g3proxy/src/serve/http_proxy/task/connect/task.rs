/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use http::Version;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_daemon::server::ServerQuitPolicy;
use g3_daemon::stat::task::TcpStreamTaskStats;
use g3_io_ext::{IdleInterval, LimitedReader, LimitedWriter, StreamCopyConfig};
use g3_types::acl::AclAction;
use g3_types::net::{ProxyRequestType, UpstreamAddr};

use super::protocol::{HttpClientWriter, HttpProxyRequest};
use super::{CommonTaskContext, TcpConnectTaskCltWrapperStats};
use crate::audit::AuditContext;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{StreamInspectContext, StreamTransitTask};
use crate::log::task::tcp_connect::TaskLogForTcpConnect;
use crate::module::http_forward::HttpProxyClientResponse;
use crate::module::tcp_connect::{
    TcpConnectError, TcpConnectTaskConf, TcpConnectTaskNotes, TcpConnection,
};
use crate::serve::ftp_proxy::audit_bridge::{
    FtpUploadAuditContext, run_ftp_upload_audit_or_relay_bidi,
};
use crate::serve::ftp_proxy::upload_state::get_ftp_upload_state;
use crate::serve::http_proxy::HttpConnectTaskAliveGuard;
use crate::serve::{
    ServerStats, ServerTaskError, ServerTaskForbiddenError, ServerTaskNotes, ServerTaskResult,
    ServerTaskStage,
};

/// HTTP CONNECT 隧道任务：处理客户端发起的 CONNECT 请求，
/// 建立到上游的裸 TCP 连接（可能经 TLS 嵌套封装），回 200 后进入双向流转发。
///
/// 任务的整个生命周期分为两阶段：
/// 1. `connect_to_upstream`：ACL / 认证检查 + 建立上游连接；
/// 2. `into_running`：把已建立的上游流与客户端流交给 `tokio::spawn` 做双向 copy。
pub(crate) struct HttpProxyConnectTask {
    // 所属客户端连接与服务器级共享上下文（配置、统计、escaper 等）
    ctx: Arc<CommonTaskContext>,
    // CONNECT 请求的目标地址（host:port）
    upstream: UpstreamAddr,
    // 已建立的上游连接（读端 + 写端），未建立时为 None
    stream_ups: Option<TcpConnection>,
    // 出错回复 HTTP 响应后，客户端连接是否还能回到 HTTP 模式复用（false 表示需关闭）
    back_to_http: bool,
    // 通用任务记录：客户端地址、用户上下文、当前阶段、请求许可等
    task_notes: ServerTaskNotes,
    // CONNECT 专用记录：下一跳地址、本地地址、重试次数、override peer 等
    tcp_notes: TcpConnectTaskNotes,
    // 本任务的字节数统计（客户端侧 / 上游侧读写量）
    task_stats: Arc<TcpStreamTaskStats>,
    // 审计上下文，用于把隧道流送交 ICAP 等审计模块
    audit_ctx: AuditContext,
    // 客户端请求使用的 HTTP 版本，生成响应时需保持一致
    http_version: Version,
    // 是否已经计入"存活任务"统计；Drop 时据此决定是否回收计数
    started: bool,
    // 存活任务计数的 RAII 守卫，drop 时自动减一
    _alive_guard: Option<HttpConnectTaskAliveGuard>,
}

impl Drop for HttpProxyConnectTask {
    // 任务在任意路径被丢弃时，都要保证"存活请求数"等计数被归还
    fn drop(&mut self) {
        if self.started {
            self.post_stop();
            self.started = false;
        }
    }
}

impl HttpProxyConnectTask {
    /// 从已解析出的 CONNECT 请求创建任务实例。
    /// 此时尚未建立上游连接，也尚未计入存活统计。
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        audit_ctx: AuditContext,
        req: &HttpProxyRequest<impl AsyncRead>,
        task_notes: ServerTaskNotes,
    ) -> Self {
        HttpProxyConnectTask {
            ctx: Arc::clone(ctx),
            upstream: req.upstream.clone(),
            stream_ups: None,
            back_to_http: false,
            task_notes,
            tcp_notes: TcpConnectTaskNotes::default(),
            task_stats: Arc::new(TcpStreamTaskStats::default()),
            audit_ctx,
            http_version: req.inner.version,
            started: false,
            _alive_guard: None,
        }
    }

    /// 回复 429 Too Many Requests（用户级限流或并发已满触发）
    async fn reply_too_many_requests<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::too_many_requests(self.http_version);
        // no custom header is set
        let _ = rsp.reply_err_to_request(clt_w).await;
        // 429 之后不复用连接，由外层关闭客户端连接
        self.back_to_http = false;
    }

    /// 回复 403 Forbidden（ACL 禁止访问目标）
    async fn reply_forbidden<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::forbidden(self.http_version);
        // no custom header is set
        let _ = rsp.reply_err_to_request(clt_w).await;
        self.back_to_http = false;
    }

    /// 回复 405 Method Not Allowed（该用户/服务禁止 CONNECT 这类协议）
    async fn reply_banned_protocol<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::method_not_allowed(self.http_version);
        // no custom header is set
        let _ = rsp.reply_err_to_request(clt_w).await;
        self.back_to_http = false;
    }

    /// 上游连接建立成功后回复 "HTTP/1.x 200 Connection Established"。
    /// 该响应之后客户端与上游之间即为裸 TCP 隧道，不再有任何 HTTP 语义。
    async fn reply_ok<W>(&self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut rsp =
            HttpProxyClientResponse::from_standard(http::StatusCode::OK, self.http_version, false);
        // 按配置附加自定义响应头（例如连接标签、下一跳信息）
        self.ctx
            .set_custom_header_for_local_reply(&self.tcp_notes, &mut rsp);
        rsp.reply_ok_to_connect(clt_w)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)
    }

    /// 把上游连接失败 `TcpConnectError` 映射为给客户端的 HTTP 错误响应。
    async fn reply_connect_err<W>(&mut self, e: &TcpConnectError, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        // If the next-hop was derived from username params and DNS failed,
        // treat it as a bad request (400) instead of origin DNS error.
        if self.tcp_notes.override_peer.is_some() && matches!(e, TcpConnectError::ResolveFailed(_))
        {
            // 目标地址来自用户名参数且解析失败：属于"用户名里写的目的地不合法"，回 400
            let mut rsp = HttpProxyClientResponse::bad_request(self.http_version);
            rsp.set_error_message("Proxy targeting didn't find a match");
            // no custom header is set for 400
            self.back_to_http = false;
            let _ = rsp.reply_err_to_request(clt_w).await;
            return;
        }

        // 其它错误：由 TcpConnectError 映射为对应状态码
        // （403 / 500 / 503 / 504 / DNS 失败用的自定义错误码等）
        let mut rsp = HttpProxyClientResponse::from_tcp_connect_error(e, Version::HTTP_11, false);
        self.ctx
            .set_custom_header_for_local_reply(&self.tcp_notes, &mut rsp);
        // 若响应带 Connection: close，则连接不能回到 HTTP 模式继续复用
        let should_close = rsp.should_close();
        self.back_to_http = !should_close;

        if rsp.reply_err_to_request(clt_w).await.is_err() {
            // 连错误响应都写不出去，只能关闭连接
            self.back_to_http = false;
        }
    }

    /// 第一阶段入口：尝试建立到 upstream 的连接并回复客户端。
    /// 结果通过 `self.stream_ups`（成功）与 `self.back_to_http`（失败时的连接处置）传出。
    pub(crate) async fn connect_to_upstream<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        self.pre_start();
        match self.run_connect(clt_w).await {
            Ok(()) => {
                // 隧道已就绪：连接将被升级为裸 TCP，不再按 HTTP 解析
                self.back_to_http = false;
            }
            Err(e) => {
                // 失败路径：错误响应已在 run_connect 内部回复，这里只负责写任务日志
                if let Some(log_ctx) = self.get_log_context() {
                    log_ctx.log(e);
                }
            }
        }
    }

    /// 处理服务器级"目标地址 ACL"判定结果，禁止时回 403 并记入禁止统计
    async fn handle_server_upstream_acl_action<W>(
        &mut self,
        action: AclAction,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        // 把 AclAction 归一为"是否禁止"；AndLog 变体的日志目前尚未实现（见下方 TODO）
        let forbid = match action {
            AclAction::Permit => false,
            AclAction::PermitAndLog => {
                // TODO log permit
                false
            }
            AclAction::Forbid => true,
            AclAction::ForbidAndLog => {
                // TODO log forbid
                true
            }
        };
        if forbid {
            self.ctx.server_stats.forbidden.add_dest_denied();
            if let Some(user_ctx) = self.task_notes.user_ctx() {
                // also add to user level forbidden stats
                user_ctx.add_dest_denied();
            }

            self.reply_forbidden(clt_w).await;
            Err(ServerTaskError::ForbiddenByRule(
                ServerTaskForbiddenError::DestDenied,
            ))
        } else {
            Ok(())
        }
    }

    /// 处理"用户级目标地址 ACL"判定结果，禁止时回 403
    async fn handle_user_upstream_acl_action<W>(
        &mut self,
        action: AclAction,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let forbid = match action {
            AclAction::Permit => false,
            AclAction::PermitAndLog => {
                // TODO log permit
                false
            }
            AclAction::Forbid => true,
            AclAction::ForbidAndLog => {
                // TODO log forbid
                true
            }
        };
        if forbid {
            self.reply_forbidden(clt_w).await;
            Err(ServerTaskError::ForbiddenByRule(
                ServerTaskForbiddenError::DestDenied,
            ))
        } else {
            Ok(())
        }
    }

    /// 处理"用户级协议 ACL"判定结果：用户是否被允许使用 CONNECT，禁止时回 405
    async fn handle_user_protocol_acl_action<W>(
        &mut self,
        action: AclAction,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let forbid = match action {
            AclAction::Permit => false,
            AclAction::PermitAndLog => {
                // TODO log permit
                false
            }
            AclAction::Forbid => true,
            AclAction::ForbidAndLog => {
                // TODO log forbid
                true
            }
        };
        if forbid {
            self.reply_banned_protocol(clt_w).await;
            Err(ServerTaskError::ForbiddenByRule(
                ServerTaskForbiddenError::ProtoBanned,
            ))
        } else {
            Ok(())
        }
    }

    /// CONNECT 的核心准备流程：用户级限流/并发控制 -> 协议与目标 ACL -> 服务器级 ACL
    /// -> 客户端 socket 选项 -> 通过 escaper 建立上游连接。
    /// 任一步失败都会先回复相应 HTTP 错误再以 Err 返回。
    async fn run_connect<W>(&mut self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let tcp_client_misc_opts;
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            let user_ctx = user_ctx.clone();

            // 用户级速率限制（每秒新建请求数），超限回 429
            if user_ctx.check_rate_limit().is_err() {
                self.reply_too_many_requests(clt_w).await;
                return Err(ServerTaskError::ForbiddenByRule(
                    ServerTaskForbiddenError::RateLimited,
                ));
            }

            // 用户级并发配额：permit 需一直持有到任务结束（保存在 task_notes 中，Drop 时释放）
            match user_ctx.acquire_request_semaphore() {
                Ok(permit) => self.task_notes.user_req_alive_permit = Some(permit),
                Err(_) => {
                    self.reply_too_many_requests(clt_w).await;
                    return Err(ServerTaskError::ForbiddenByRule(
                        ServerTaskForbiddenError::FullyLoaded,
                    ));
                }
            }

            // 该用户是否允许使用 CONNECT 协议
            let action = user_ctx.check_proxy_request(ProxyRequestType::HttpConnect);
            self.handle_user_protocol_acl_action(action, clt_w).await?;

            // 用户级目标地址/端口 ACL
            let action = user_ctx.check_upstream(&self.upstream);
            self.handle_user_upstream_acl_action(action, clt_w).await?;

            // server level dst host/port acl rules
            let action = self.ctx.check_upstream(&self.upstream);
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            // 客户端侧 socket 选项（no_delay/MSS/TTL/拥塞控制等）：
            // 用户显式配置的项生效，未配置的沿用服务器级配置
            tcp_client_misc_opts = user_ctx
                .user_config()
                .tcp_client_misc_opts(&self.ctx.server_config.tcp_misc_opts);
        } else {
            // 匿名（无认证用户）场景：只走服务器级 ACL
            // server level dst host/port acl rules
            let action = self.ctx.check_upstream(&self.upstream);
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            tcp_client_misc_opts = Cow::Borrowed(&self.ctx.server_config.tcp_misc_opts);
        }

        // set client side socket options
        self.ctx
            .cc_info
            .tcp_sock_set_raw_opts(&tcp_client_misc_opts, true)
            .map_err(|_| {
                ServerTaskError::InternalServerError("failed to set client socket options")
            })?;

        self.task_notes.stage = ServerTaskStage::Connecting;

        let task_conf = TcpConnectTaskConf {
            upstream: &self.upstream,
        };
        // 交由 escaper（出站转发模块）建立连接：内部包含 DNS 解析、多地址依次尝试、
        // 下一级代理（socks5/http）握手、TLS 嵌套封装以及 failover 等逻辑，
        // 结果地址与重试次数等信息回填到 tcp_notes
        match self
            .ctx
            .escaper
            .tcp_setup_connection(
                &task_conf,
                &mut self.tcp_notes,
                &self.task_notes,
                self.task_stats.clone(),
                &mut self.audit_ctx,
            )
            .await
        {
            Ok(connection) => {
                self.task_notes.stage = ServerTaskStage::Connected;
                self.stream_ups = Some(connection);
                Ok(())
            }
            Err(e) => {
                self.reply_connect_err(&e, clt_w).await;
                Err(e.into())
            }
        }
    }

    /// 告知外层（HTTP 连接循环）本次 CONNECT 失败后连接是否仍可当作 HTTP 复用
    pub(crate) fn back_to_http(&self) -> bool {
        self.back_to_http
    }

    /// 任务正式开始时调用：增加存活任务/用户请求计数，并按配置输出"任务已创建"日志
    fn pre_start(&mut self) {
        // guard 存活到任务 Drop，其 Drop 负责把 alive 计数减一
        self._alive_guard = Some(self.ctx.server_stats.add_http_connect_task());

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| {
                s.req_total.add_http_connect();
                s.req_alive.add_http_connect();
            });
        }

        if self.ctx.server_config.flush_task_log_on_created
            && let Some(log_ctx) = self.get_log_context()
        {
            log_ctx.log_created();
        }

        self.started = true;
    }

    /// 任务结束时调用（经由 Drop）：减少用户存活请求计数并释放并发配额 permit
    fn post_stop(&mut self) {
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| {
                s.req_alive.del_http_connect();
            });

            // 显式 take + drop，确保并发信号量许可立即归还
            if let Some(user_req_alive_permit) = self.task_notes.user_req_alive_permit.take() {
                drop(user_req_alive_permit);
            }
        }
    }

    /// 构造任务日志上下文。未配置 task logger 时返回 None。
    /// 字节数取自 task_stats，因此日志内容依赖于统计的实时更新时机。
    fn get_log_context(&self) -> Option<TaskLogForTcpConnect<'_>> {
        self.ctx
            .task_logger
            .as_ref()
            .map(|logger| TaskLogForTcpConnect {
                logger,
                upstream: &self.upstream,
                task_notes: &self.task_notes,
                tcp_notes: &self.tcp_notes,
                client_rd_bytes: self.task_stats.clt.read.get_bytes(),
                client_wr_bytes: self.task_stats.clt.write.get_bytes(),
                remote_rd_bytes: self.task_stats.ups.read.get_bytes(),
                remote_wr_bytes: self.task_stats.ups.write.get_bytes(),
            })
    }

    /// 第二阶段入口：上游连接已建立时，把整个任务交给独立 tokio 任务做双向转发。
    /// 调用后原 HTTP 连接循环不再持有客户端读端；若上游未建立则什么都不做（等待 Drop）。
    pub(crate) fn into_running<CDR, CDW>(mut self, clt_r: CDR, clt_w: HttpClientWriter<CDW>)
    where
        CDR: AsyncRead + Send + Sync + Unpin + 'static,
        CDW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        if self.stream_ups.is_none() {
            // 连接失败（或已被其它路径消耗），不进入转发阶段
            return;
        }

        tokio::spawn(async move {
            match self.stream_ups.take() {
                Some((ups_r, ups_w)) => {
                    let e = match self.run_connected(clt_r, clt_w, ups_r, ups_w).await {
                        // 隧道正常结束也记为 Finished，便于日志统一处理
                        Ok(_) => ServerTaskError::Finished,
                        Err(e) => e,
                    };
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log(e);
                    }
                }
                None => unreachable!(),
            }
        });
    }

    /// 隧道正式建立后的流程：回 200 -> 标记阶段/统计 -> 进入转发。
    /// `clt_w` 先以 HttpClientWriter 身份写出 200 响应，随后拆出裸流参与转发。
    async fn run_connected<CDR, CDW, UR, UW>(
        &mut self,
        clt_r: CDR,
        mut clt_w: HttpClientWriter<CDW>,
        ups_r: UR,
        ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CDR: AsyncRead + Send + Sync + Unpin + 'static,
        CDW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        if self.ctx.server_config.flush_task_log_on_connected
            && let Some(log_ctx) = self.get_log_context()
        {
            log_ctx.log_connected();
        }

        self.task_notes.stage = ServerTaskStage::Replying;
        // CONNECT 握手的关键一步：向客户端回 200，此后客户端才开始发送隧道数据
        self.reply_ok(&mut clt_w).await?;

        // For FTPS control channel (port 990), mark the domain early
        // This ensures data channels can find the domain when they connect
        // 提前登记 客户端IP/服务器IP -> 域名 的映射，供随后的 FTPS 数据通道做证书生成与审计
        let upstream_port = self.upstream.port();
        if upstream_port == 990 {
            let client_ip = self.task_notes.client_addr().ip();
            if let Some(server_ip) = self.tcp_notes.next.map(|addr| addr.ip()) {
                let domain = match self.upstream.host() {
                    g3_types::net::Host::Domain(d) => d.to_string(),
                    g3_types::net::Host::Ip(ip) => ip.to_string(),
                };
                get_ftp_upload_state().mark_ftps_domain(client_ip, server_ip, &domain);
            }
        }

        self.task_notes.mark_relaying();
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            // 此刻请求才真正"可用"（已过握手），计入 ready 而非 alive
            user_ctx.foreach_req_stats(|s| {
                s.req_ready.add_http_connect();
            });
        }
        // 200 已写完，把 HTTP 写器还原为底层裸写端，避免 HTTP 分帧干扰隧道数据
        let clt_w = clt_w.into_inner();

        // Just relay - bidirectional TCP tunnel forwarding
        self.relay(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 双向转发的分发点：根据目标端口/全局状态判断这是 FTP 控制通道、FTPS 数据通道
    /// 还是普通隧道，分别走"带协议检视的转发"、"FTP 上传审计转发"或"纯透明双向 copy"。
    async fn relay<CDR, CDW, UR, UW>(
        &mut self,
        clt_r: CDR,
        clt_w: CDW,
        ups_r: UR,
        ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CDR: AsyncRead + Send + Sync + Unpin + 'static,
        CDW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // 客户端两侧套上限速与字节统计包装
        let (clt_r, clt_w) = self.update_clt(clt_r, clt_w);

        let upstream_port = self.upstream.port();
        let is_ftp_control = upstream_port == 21 || upstream_port == 990;
        let is_ftps_control = upstream_port == 990;

        let client_ip = self.task_notes.client_addr().ip();
        let Some(server_ip) = self.tcp_notes.next.map(|addr| addr.ip()) else {
            // 拿不到下一跳地址（例如未真正直连），无法关联 FTP 状态，直接透明转发
            return self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await;
        };

        // For FTPS control channel, save the domain to global state
        // This domain will be used for data channel TLS certificate generation
        if is_ftps_control {
            let domain = match self.upstream.host() {
                g3_types::net::Host::Domain(d) => d.to_string(),
                g3_types::net::Host::Ip(ip) => ip.to_string(),
            };
            get_ftp_upload_state().mark_ftps_domain(client_ip, server_ip, &domain);
        }

        // Check if this is FTPS data channel by looking up the saved domain
        // 数据通道本身没有域名信息，靠 (客户端IP, 服务器IP) 反查控制通道登记的域名识别
        let ftps_domain = get_ftp_upload_state().get_ftps_domain(client_ip, server_ip);
        let is_ftps_data_channel = ftps_domain.is_some();

        // FTP/FTPS 控制通道（21/990）以及 FTPS 数据通道：走协议检视转发，
        // 由检视模块解析控制命令（含 STOR）并驱动后续审计
        if (is_ftp_control || is_ftps_data_channel)
            && let Some(audit_handle) = self.audit_ctx.handle()
        {
            let ctx = StreamInspectContext::new(
                audit_handle.clone(),
                self.ctx.server_config.clone(),
                self.ctx.server_stats.clone(),
                self.ctx.server_quit_policy.clone(),
                self.ctx.idle_wheel.clone(),
                &self.task_notes,
                &self.tcp_notes,
            );
            return crate::inspect::stream::transit_with_inspection(
                clt_r,
                clt_w,
                ups_r,
                ups_w,
                ctx,
                self.upstream.clone(),
                None,
            )
            .await;
        }

        // 存在 FTP 上传登记（控制通道此前收到 STOR 等上传命令）：
        // 按 (客户端IP, 服务器IP) FIFO 取出一条未过期登记，取出即消费 —— 说明当前连接是该上传的数据通道
        if !is_ftp_control
            && !is_ftps_data_channel
            && let Some(upload_info) = get_ftp_upload_state().consume_upload(client_ip, server_ip)
            && let Some(audit_handle) = self.audit_ctx.handle()
            && let Some(icap_client) = audit_handle.icap_reqmod_client().cloned()
        {
            // 用本任务的实际四元组告知 ICAP，便于其关联控制/数据通道
            let data_channel_tuple = self.tcp_notes.local.and_then(|local_addr| {
                self.tcp_notes
                    .next
                    .map(|remote_addr| g3_icap_client::reqmod::ConnectionTuple {
                        server_addr: local_addr,
                        remote_addr,
                        protocol: g3_icap_client::reqmod::ConnectionProtocol::Tcp,
                    })
            });

            let audit_ctx = FtpUploadAuditContext {
                icap_client: Arc::new(icap_client),
                idle_wheel: self.ctx.idle_wheel.clone(),
                max_idle_count: self.ctx.server_config.task_max_idle_count(),
                copy_config: self.ctx.server_config.limited_copy_config(),
                client_addr: Some(self.task_notes.client_addr()),
                ftp_command: upload_info.ftp_command,
                ftp_path: upload_info.ftp_path,
                data_channel_tuple,
                keylog_buffer: None,
            };

            // 上行（客户端->服务器）送 ICAP 审计并转发，下行仍为普通双向转发；
            // 返回值是审计到的上传字节数，此处无需统计，故忽略
            let _ = run_ftp_upload_audit_or_relay_bidi(
                clt_r,
                clt_w,
                ups_r,
                ups_w,
                self.ctx.idle_wheel.clone(),
                self.ctx.server_config.task_max_idle_count(),
                Some(audit_ctx),
            )
            .await;
            return Ok(());
        }

        // For non-FTP traffic (including HTTPS), perform ICAP audit if configured
        // 普通隧道流量：仅当（用户配置优先，否则服务配置）启用审计时才走检视转发
        if !is_ftp_control
            && !is_ftps_data_channel
            && let Some(audit_handle) = self.audit_ctx.handle()
        {
            let audit_task = self
                .task_notes
                .user_ctx()
                .map(|ctx| {
                    let user_config = &ctx.user_config().audit;
                    user_config.enable_protocol_inspection
                        && user_config
                            .do_task_audit()
                            .unwrap_or_else(|| audit_handle.do_task_audit())
                })
                .unwrap_or_else(|| audit_handle.do_task_audit());

            if audit_task {
                let ctx = StreamInspectContext::new(
                    audit_handle.clone(),
                    self.ctx.server_config.clone(),
                    self.ctx.server_stats.clone(),
                    self.ctx.server_quit_policy.clone(),
                    self.ctx.idle_wheel.clone(),
                    &self.task_notes,
                    &self.tcp_notes,
                );
                return crate::inspect::stream::transit_with_inspection(
                    clt_r,
                    clt_w,
                    ups_r,
                    ups_w,
                    ctx,
                    self.upstream.clone(),
                    None,
                )
                .await;
            }
        }

        // 默认路径：无审计的裸 TCP 双向 copy；
        // 空闲超时由 idle_wheel + max_idle_count 控制，限速由上面的 Limited* 包装流控制
        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 给客户端读写端套上限速包装器（LimitedReader/LimitedWriter）与统计包装器。
    /// 上限取"用户配置"与"服务器配置"中更严格的一方；
    /// 若用户还有跨服务的全局限速，则再叠加 global limiter。
    fn update_clt<CDR, CDW>(
        &self,
        clt_r: CDR,
        clt_w: CDW,
    ) -> (LimitedReader<CDR>, LimitedWriter<CDW>)
    where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Unpin,
    {
        let mut wrapper_stats =
            TcpConnectTaskCltWrapperStats::new(&self.ctx.server_stats, &self.task_stats);

        // north = 客户端上行（读方向），south = 客户端下行（写方向）
        let limit_config = if let Some(user_ctx) = self.task_notes.user_ctx() {
            // 同一用户可能命中多个服务的流量统计，全部串接到同一个统计包装器上
            wrapper_stats.push_user_io_stats(user_ctx.fetch_traffic_stats(
                self.ctx.server_config.name(),
                self.ctx.server_stats.share_extra_tags(),
            ));

            user_ctx
                .user_config()
                .tcp_sock_speed_limit
                .shrink_as_smaller(&self.ctx.server_config.tcp_sock_speed_limit)
        } else {
            self.ctx.server_config.tcp_sock_speed_limit
        };

        let wrapper_stats = Arc::new(wrapper_stats);
        let mut clt_r = LimitedReader::local_limited(
            clt_r,
            limit_config.shift_millis,
            limit_config.max_north,
            wrapper_stats.clone(),
        );
        let mut clt_w = LimitedWriter::local_limited(
            clt_w,
            limit_config.shift_millis,
            limit_config.max_south,
            wrapper_stats,
        );

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            let user = user_ctx.user();
            if let Some(limiter) = user.tcp_all_upload_speed_limit() {
                clt_r.add_global_limiter(limiter.clone());
            }
            if let Some(limiter) = user.tcp_all_download_speed_limit() {
                clt_w.add_global_limiter(limiter.clone());
            }
        }

        (clt_r, clt_w)
    }
}

// 双向转发的通用实现由 StreamTransitTask 的默认方法提供（transit_transparent*）：
// 本 impl 只负责把 copy 缓冲区参数、空闲检查、周期性日志等回调接到服务器配置与任务上下文上。
impl StreamTransitTask for HttpProxyConnectTask {
    fn copy_config(&self) -> StreamCopyConfig {
        // 单次 copy 的缓冲区大小与让出调度阈值
        self.ctx.server_config.tcp_copy
    }

    fn idle_check_interval(&self) -> IdleInterval {
        // 向全局 idle wheel 注册一个计时器，用于判断隧道是否长时间无数据
        self.ctx.idle_wheel.register()
    }

    fn max_idle_count(&self) -> usize {
        // 允许的空闲检查次数上限，超过即认为隧道已死（用户可覆盖此默认值）
        self.ctx.server_config.task_idle_max_count
    }

    fn log_client_shutdown(&self) {
        if let Some(log_ctx) = self.get_log_context() {
            log_ctx.log_client_shutdown();
        }
    }

    fn log_upstream_shutdown(&self) {
        if let Some(log_ctx) = self.get_log_context() {
            log_ctx.log_upstream_shutdown();
        }
    }

    fn log_periodic(&self) {
        if let Some(log_ctx) = self.get_log_context() {
            log_ctx.log_periodic();
        }
    }

    fn log_flush_interval(&self) -> Option<Duration> {
        self.ctx.log_flush_interval()
    }

    fn quit_policy(&self) -> &ServerQuitPolicy {
        self.ctx.server_quit_policy.as_ref()
    }

    fn user(&self) -> Option<&User> {
        self.task_notes.user_ctx().map(|ctx| ctx.user().as_ref())
    }
}
