/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use futures_util::FutureExt;
use http::header;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_http::client::HttpForwardRemoteResponse;
use g3_http::server::HttpProxyClientRequest;
use g3_http::{HttpBodyReader, HttpBodyType};
use g3_icap_client::reqmod::h1::{
    H1ReqmodAdaptationError, HttpAdapterErrorResponse, HttpRequestAdapter,
    ReqmodAdaptationEndState, ReqmodAdaptationRunState, ReqmodRecvHttpResponseBody,
};
use g3_icap_client::respmod::h1::{
    HttpResponseAdapter, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use g3_io_ext::{
    GlobalLimitGroup, LimitedBufReadExt, LimitedReadExt, LimitedWriteExt, StreamCopy,
    StreamCopyError,
};
use g3_types::acl::AclAction;
use g3_types::net::{HttpHeaderMap, ProxyRequestType, UpstreamAddr};

use super::protocol::{HttpClientReader, HttpClientWriter, HttpProxyRequest};
use super::{
    CommonTaskContext, HttpForwardTaskCltWrapperStats, HttpForwardTaskStats,
    HttpsForwardTaskCltWrapperStats,
};
use crate::audit::AuditContext;
use crate::config::server::ServerConfig;
use crate::log::task::http_forward::TaskLogForHttpForward;
use crate::module::http_forward::{
    BoxHttpForwardConnection, BoxHttpForwardContext, BoxHttpForwardReader, BoxHttpForwardWriter,
    HttpForwardTaskNotes, HttpProxyClientResponse,
};
use crate::module::http_header;
use crate::module::tcp_connect::{
    TcpConnectError, TcpConnectTaskConf, TcpConnectTaskNotes, TlsConnectTaskConf,
};
use crate::serve::http_proxy::HttpForwardTaskAliveGuard;
use crate::serve::{
    ServerIdleChecker, ServerStats, ServerTaskError, ServerTaskForbiddenError, ServerTaskNotes,
    ServerTaskResult, ServerTaskStage,
};

/// 一次正向 HTTP 转发任务的完整状态与执行逻辑。
///
/// 生命周期：由协议层解析出请求后创建，run() 驱动整个转发流程
/// （ACL 检查 -> 获取/新建上游连接 -> 发送请求头/请求体 -> 接收并回传响应），
/// 期间按需向客户端回复错误响应，并维护任务级统计与日志。
pub(crate) struct HttpProxyForwardTask<'a> {
    ctx: Arc<CommonTaskContext>, // 任务共享上下文（服务器配置、统计、idle wheel 等）
    audit_ctx: AuditContext,     // 审计上下文，可从中取到 ICAP reqmod/respmod 客户端
    upstream: UpstreamAddr,      // 转发目标（直连时为目标服务器，链式时为下一跳代理）
    req: &'a HttpProxyClientRequest, // 已解析的客户端请求（借用，任务不修改其主体）
    is_https: bool,              // 是否经 TLS 连接上游（https 转发）
    should_close: bool,          // 本任务结束后是否必须关闭客户端连接（不能再复用）
    send_error_response: bool,   // 出错时是否还允许向客户端补发错误响应（响应已开始发出后置 false）
    task_notes: ServerTaskNotes, // 通用任务笔记（阶段、用户、日志字段等）
    http_notes: HttpForwardTaskNotes, // HTTP 转发专属笔记（方法/URI、各阶段耗时、响应码、重试标志）
    tcp_notes: TcpConnectTaskNotes, // 上游连接笔记（实际下一跳、绑定地址、链式信息等）
    task_stats: Arc<HttpForwardTaskStats>, // 本任务客户端/上游读写字节统计
    max_idle_count: usize,       // 允许连续 idle tick 的次数上限，超过即判定空闲超时
    started: bool,               // 是否已执行 pre_start（决定 Drop 时是否需要 post_stop 清理）
    _alive_guard: Option<HttpForwardTaskAliveGuard>, // 存活任务计数守卫，随任务析构自动减一
}

/// 析构时若任务已启动但未正常走完 post_stop，则补做清理（释放用户级存活计数/信号量许可）。
impl Drop for HttpProxyForwardTask<'_> {
    fn drop(&mut self) {
        if self.started {
            self.post_stop();
            self.started = false;
        }
    }
}

impl<'a> HttpProxyForwardTask<'a> {
    /// 从已解析的客户端请求创建转发任务。
    /// URI 日志截断长度、任务最大空闲次数优先取用户级配置，缺省回落到服务器级配置。
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        audit_ctx: AuditContext,
        req: &'a HttpProxyRequest<impl AsyncRead>,
        is_https: bool,
        task_notes: ServerTaskNotes,
    ) -> Self {
        let uri_log_max_chars = task_notes
            .user_ctx()
            .and_then(|c| c.user_config().log_uri_max_chars)
            .unwrap_or(ctx.server_config.log_uri_max_chars);
        let http_notes = HttpForwardTaskNotes::new(
            req.time_received,
            task_notes.task_created_instant(),
            req.inner.method.clone(),
            req.inner.uri.clone(),
            uri_log_max_chars,
        );
        let max_idle_count = task_notes
            .user_ctx()
            .and_then(|c| c.user().task_max_idle_count())
            .unwrap_or(ctx.server_config.task_idle_max_count);
        HttpProxyForwardTask {
            ctx: Arc::clone(ctx),
            audit_ctx,
            upstream: req.upstream.clone(),
            req: &req.inner,
            is_https,
            should_close: !req.inner.keep_alive(),
            send_error_response: true,
            task_notes,
            http_notes,
            tcp_notes: TcpConnectTaskNotes::default(),
            task_stats: Arc::new(HttpForwardTaskStats::default()),
            max_idle_count,
            started: false,
            _alive_guard: None,
        }
    }

    /// 供协议层查询：本任务结束后客户端连接是否必须关闭（不能再读取下一个流水线请求）。
    #[inline]
    pub(crate) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 回复客户端 429（请求过多，触发限速/并发上限），并标记关闭连接。
    async fn reply_too_many_requests<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::too_many_requests(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.http_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 回复客户端 403（被 ACL 规则禁止），并标记关闭连接。
    async fn reply_forbidden<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::forbidden(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.http_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 回复客户端 405 Method Not Allowed（该请求协议/方法被用户 ACL 禁止），并标记关闭连接。
    async fn reply_banned_protocol<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::method_not_allowed(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.http_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 上游连接失败时回复客户端本地错误响应。
    /// 错误响应由 TcpConnectError 映射（DNS 失败/超时/拒连等对应不同状态码）。
    async fn reply_connect_err<W>(&mut self, e: &TcpConnectError, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        // If the next-hop was derived from username params and DNS failed,
        // treat it as a bad request (400) instead of origin DNS error.
        // Check override_next_proxy() first (per review).
        // （下一跳来自用户名参数且解析失败时，视为用户配置错误返回 400，而非上游 DNS 错误）
        if self.tcp_notes.override_peer.is_some() && matches!(e, TcpConnectError::ResolveFailed(_))
        {
            let mut rsp = HttpProxyClientResponse::bad_request(self.req.version);
            rsp.set_error_message("Proxy targeting didn't find a match");
            // no custom header is set for 400
            if rsp.should_close() {
                self.should_close = true;
            }
            if rsp.reply_err_to_request(clt_w).await.is_ok() {
                self.http_notes.rsp_status = rsp.status();
            }
            return;
        }

        let mut rsp = HttpProxyClientResponse::from_tcp_connect_error(
            e,
            self.req.version,
            // 若请求体还没收完，连接必须关闭：残留 body 字节会被误认为下一个请求
            self.should_close || self.req.body_type().is_some(),
        );

        // 按配置为本地生成的响应附加自定义诊断头（如 X-Remote-Connection-Info）
        self.ctx
            .set_custom_header_for_local_reply(&self.tcp_notes, &mut rsp);

        if rsp.should_close() {
            self.should_close = true;
        }

        if rsp.reply_err_to_request(clt_w).await.is_err() {
            self.should_close = true;
        } else {
            self.http_notes.rsp_status = rsp.status();
        }
    }

    /// 任务进行中出错时回复客户端本地错误响应。
    /// 部分错误（如客户端写失败）无法或无需回复，from_task_err 会返回 None；
    /// 此时若请求体未收完，只能关闭客户端连接。
    async fn reply_task_err<W>(&mut self, e: &ServerTaskError, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let body_pending = self.req.body_type().is_some();
        let rsp = HttpProxyClientResponse::from_task_err(
            e,
            self.req.version,
            // 请求体未收完时连接不可复用，必须 close
            self.should_close || body_pending,
        );

        if let Some(mut rsp) = rsp {
            self.ctx
                .set_custom_header_for_local_reply(&self.tcp_notes, &mut rsp);

            if rsp.should_close() {
                self.should_close = true;
            }

            if rsp.reply_err_to_request(clt_w).await.is_err() {
                self.should_close = true;
            } else {
                self.http_notes.rsp_status = rsp.status();
            }
        } else if body_pending {
            self.should_close = true;
        }
    }

    /// 组装本任务的日志上下文（含客户端/上游四向字节数），未配置日志器时返回 None。
    fn get_log_context(&self) -> Option<TaskLogForHttpForward<'_>> {
        let Some(logger) = &self.ctx.task_logger else {
            return None;
        };

        let http_user_agent = self
            .req
            .end_to_end_headers
            .get(header::USER_AGENT)
            .map(|v| v.to_str());
        Some(TaskLogForHttpForward {
            logger,
            upstream: &self.upstream,
            task_notes: &self.task_notes,
            http_notes: &self.http_notes,
            http_user_agent,
            tcp_notes: &self.tcp_notes,
            client_rd_bytes: self.task_stats.clt.read.get_bytes(),
            client_wr_bytes: self.task_stats.clt.write.get_bytes(),
            remote_rd_bytes: self.task_stats.ups.read.get_bytes(),
            remote_wr_bytes: self.task_stats.ups.write.get_bytes(),
        })
    }

    /// 任务入口：pre_start 登记 -> 执行转发流程 -> 无论成败都输出结束日志。
    /// clt_r 为 None 表示客户端侧没有需要继续读取的请求体数据。
    pub(crate) async fn run<CDR, CDW>(
        &mut self,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
        fwd_ctx: &mut BoxHttpForwardContext,
    ) where
        CDR: AsyncRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        self.pre_start();
        let e = match self.run_forward(clt_r, clt_w, fwd_ctx).await {
            Ok(()) => ServerTaskError::Finished,
            Err(e) => e,
        };
        if let Some(log_ctx) = self.get_log_context() {
            log_ctx.log(&e);
        }
    }

    /// 任务开始登记：占用服务器与用户级存活计数，按配置立即输出"任务已创建"日志。
    fn pre_start(&mut self) {
        self._alive_guard = Some(self.ctx.server_stats.add_http_forward_task());

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| {
                s.req_total.add_http_forward(self.is_https);
                s.req_alive.add_http_forward(self.is_https);
            });
        }

        if self.ctx.server_config.flush_task_log_on_created
            && let Some(log_ctx) = self.get_log_context()
        {
            log_ctx.log_created();
        }

        self.started = true;
    }

    /// 任务结束清理：释放用户级存活计数，并归还并发请求信号量许可。
    fn post_stop(&mut self) {
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| s.req_alive.del_http_forward(self.is_https));

            if let Some(user_req_alive_permit) = self.task_notes.user_req_alive_permit.take() {
                drop(user_req_alive_permit);
            }
        }
    }

    /// 处理服务器级"目标地址" ACL 结果：Forbid 时累加禁止计数、回复 403 并返回错误终止任务。
    async fn handle_server_upstream_acl_action<W>(
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

    /// 处理用户级"目标地址" ACL 结果：Forbid 时回复 403 并终止任务。
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

    /// 处理用户级 User-Agent ACL 结果：Forbid 时回复 403 并终止任务。
    async fn handle_user_ua_acl_action<W>(
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
                ServerTaskForbiddenError::UaBlocked,
            ))
        } else {
            Ok(())
        }
    }

    /// 处理用户级"请求协议"ACL 结果（http/https 转发是否被禁）：
    /// Forbid 时回复 405 并终止任务。
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

    /// 给客户端读写器安装统计回调与限速器：
    /// 1) 按 http/https 选用不同的 wrapper 统计（同时累加任务级、用户级流量）；
    /// 2) 已解析进来的请求头字节先计入统计；
    /// 3) 用户级限速与服务器级限速取更严格者作为本地限速，再叠加用户全局共享限速器。
    fn setup_clt_limit_and_stats<CDR, CDW>(
        &mut self,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
    ) where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Unpin,
    {
        // 请求头解析阶段消耗的字节不会经过读写器，这里手工计入客户端读统计
        let origin_header_size = self.req.origin_header_size() as u64;
        self.task_stats.clt.read.add_bytes(origin_header_size);

        let (clt_r_stats, clt_w_stats, limit_config) = if self.is_https {
            let mut wrapper_stats =
                HttpsForwardTaskCltWrapperStats::new(&self.ctx.server_stats, &self.task_stats);

            let limit_config = if let Some(user_ctx) = self.task_notes.user_ctx() {
                let user_io_stats = user_ctx.fetch_traffic_stats(
                    self.ctx.server_config.name(),
                    self.ctx.server_stats.share_extra_tags(),
                );
                for s in &user_io_stats {
                    s.io.https_forward.add_in_bytes(origin_header_size);
                }
                wrapper_stats.push_user_io_stats(user_io_stats);

                let user_config = user_ctx.user_config();
                // 用户限速与服务端限速一致时无需局部限速；否则取两者中更严格的配置
                if user_config
                    .tcp_sock_speed_limit
                    .eq(&self.ctx.server_config.tcp_sock_speed_limit)
                {
                    None
                } else {
                    let limit_config = user_config
                        .tcp_sock_speed_limit
                        .shrink_as_smaller(&self.ctx.server_config.tcp_sock_speed_limit);
                    Some(limit_config)
                }
            } else {
                None
            };

            let (clt_r_stats, clt_w_stats) = wrapper_stats.split();
            (clt_r_stats, clt_w_stats, limit_config)
        } else {
            let mut wrapper_stats =
                HttpForwardTaskCltWrapperStats::new(&self.ctx.server_stats, &self.task_stats);

            let limit_config = if let Some(user_ctx) = self.task_notes.user_ctx() {
                let user_io_stats = user_ctx.fetch_traffic_stats(
                    self.ctx.server_config.name(),
                    self.ctx.server_stats.share_extra_tags(),
                );
                for s in &user_io_stats {
                    s.io.http_forward.add_in_bytes(origin_header_size);
                }
                wrapper_stats.push_user_io_stats(user_io_stats);

                let user_config = user_ctx.user_config();
                // 用户限速与服务端限速一致时无需局部限速；否则取两者中更严格的配置
                if user_config
                    .tcp_sock_speed_limit
                    .eq(&self.ctx.server_config.tcp_sock_speed_limit)
                {
                    None
                } else {
                    let limit_config = user_config
                        .tcp_sock_speed_limit
                        .shrink_as_smaller(&self.ctx.server_config.tcp_sock_speed_limit);
                    Some(limit_config)
                }
            } else {
                None
            };

            let (clt_r_stats, clt_w_stats) = wrapper_stats.split();
            (clt_r_stats, clt_w_stats, limit_config)
        };

        // 客户端写器上原有的全局限速器只保留"服务器"分组（连接建立时挂入），
        // 随后再按需要叠加用户维度的全局共享限速器
        clt_w.retain_global_limiter_by_group(GlobalLimitGroup::Server);
        if let Some(br) = clt_r {
            br.reset_buffer_stats(clt_r_stats);
            clt_w.reset_stats(clt_w_stats);
            if let Some(limit_config) = &limit_config {
                br.reset_local_limit(limit_config.shift_millis, limit_config.max_north);
                clt_w.reset_local_limit(limit_config.shift_millis, limit_config.max_south);
            }
            if let Some(user_ctx) = self.task_notes.user_ctx() {
                let user = user_ctx.user();
                if let Some(limiter) = user.tcp_all_upload_speed_limit() {
                    // 已收到的请求头字节先在全局上行限速额度中扣除
                    limiter.try_consume(origin_header_size);
                    br.add_global_limiter(limiter.clone());
                }
                if let Some(limiter) = user.tcp_all_download_speed_limit() {
                    clt_w.add_global_limiter(limiter.clone());
                }
            }
        } else {
            // 请求无 body：客户端读器已交出，只需配置写器的统计与限速
            clt_w.reset_stats(clt_w_stats);
            if let Some(limit_config) = &limit_config {
                clt_w.reset_local_limit(limit_config.shift_millis, limit_config.max_south);
            }
            if let Some(user_ctx) = self.task_notes.user_ctx() {
                let user = user_ctx.user();
                if let Some(limiter) = user.tcp_all_upload_speed_limit() {
                    limiter.try_consume(origin_header_size);
                }
                if let Some(limiter) = user.tcp_all_download_speed_limit() {
                    clt_w.add_global_limiter(limiter.clone());
                }
            }
        }
    }

    /// 转发主流程：限流/并发检查 -> 各级 ACL -> 客户端侧限速与统计 ->
    /// 优先复用上游 keepalive 连接，失败（且可重试）或没有则新建连接 ->
    /// 执行转发并把可用连接放回连接池。
    async fn run_forward<CDR, CDW>(
        &mut self,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
        fwd_ctx: &mut BoxHttpForwardContext,
    ) -> ServerTaskResult<()>
    where
        CDR: AsyncRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        let mut upstream_keepalive = self.ctx.server_config.http_forward_upstream_keepalive;
        let tcp_client_misc_opts;
        let mut audit_task = false;

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            let user_ctx = user_ctx.clone();

            // 用户请求速率限制检查
            if user_ctx.check_rate_limit().is_err() {
                self.reply_too_many_requests(clt_w).await;
                return Err(ServerTaskError::ForbiddenByRule(
                    ServerTaskForbiddenError::RateLimited,
                ));
            }

            // 占用用户并发请求信号量许可（任务存活期间持有，post_stop 时归还）
            match user_ctx.acquire_request_semaphore() {
                Ok(permit) => self.task_notes.user_req_alive_permit = Some(permit),
                Err(_) => {
                    self.reply_too_many_requests(clt_w).await;
                    return Err(ServerTaskError::ForbiddenByRule(
                        ServerTaskForbiddenError::FullyLoaded,
                    ));
                }
            }

            // 用户级 ACL 三连检：协议类型（http/https 转发）、目标地址、User-Agent
            let request_type = if self.is_https {
                ProxyRequestType::HttpsForward
            } else {
                ProxyRequestType::HttpForward
            };
            let action = user_ctx.check_proxy_request(request_type);
            self.handle_user_protocol_acl_action(action, clt_w).await?;

            let action = user_ctx.check_upstream(&self.upstream);
            self.handle_user_upstream_acl_action(action, clt_w).await?;

            // server level dst host/port acl rules
            let action = self.ctx.check_upstream(&self.upstream);
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            if let Some(action) = user_ctx.check_http_user_agent(&self.req.end_to_end_headers) {
                self.handle_user_ua_acl_action(action, clt_w).await?;
            }

            let user_config = user_ctx.user_config();

            // 上游 keepalive 策略：用户级配置与服务器级配置合并（更严格者生效）
            upstream_keepalive = upstream_keepalive.adjust_to(user_config.http_upstream_keepalive);
            tcp_client_misc_opts =
                user_config.tcp_client_misc_opts(&self.ctx.server_config.tcp_misc_opts);

            // 是否对本任务开启审计（ICAP 适配）；用户显式配置优先，否则用审计句柄的默认值
            if let Some(audit_handle) = self.audit_ctx.handle() {
                audit_task = user_config
                    .audit
                    .do_task_audit()
                    .unwrap_or_else(|| audit_handle.do_task_audit());
            }
        } else {
            // server level dst host/port acl rules
            let action = self.ctx.check_upstream(&self.upstream);
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            tcp_client_misc_opts = Cow::Borrowed(&self.ctx.server_config.tcp_misc_opts);

            if let Some(audit_handle) = self.audit_ctx.handle() {
                audit_task = audit_handle.do_task_audit();
            }
        }

        // set client side socket options
        // 对客户端方向 socket 应用合并后的 tcp 选项（keepalive、TTL 等）
        self.ctx
            .cc_info
            .tcp_sock_set_raw_opts(&tcp_client_misc_opts, true)
            .map_err(|_| {
                ServerTaskError::InternalServerError("failed to set client socket options")
            })?;

        self.setup_clt_limit_and_stats(clt_r, clt_w);

        // 告知转发模块本次连接的目标与是否 TLS，用于连接池匹配与动态上游解析
        fwd_ctx.prepare_connection(&self.upstream, self.is_https);

        // 优先尝试复用连接池中对该目标的空闲 keepalive 连接
        if let Some(mut connection) = fwd_ctx
            .get_alive_connection(
                &self.task_notes,
                self.task_stats.clone(),
                upstream_keepalive.idle_expire(),
            )
            .await
        {
            self.task_notes.stage = ServerTaskStage::Connected;
            self.http_notes.reused_connection = true;
            fwd_ctx.fetch_tcp_notes(&mut self.tcp_notes);
            self.http_notes.retry_new_connection = false;
            if let Some(user_ctx) = self.task_notes.user_ctx() {
                user_ctx.foreach_req_stats(|s| s.req_reuse.add_http_forward(self.is_https));
            }

            if self.ctx.server_config.flush_task_log_on_connected
                && let Some(log_ctx) = self.get_log_context()
            {
                log_ctx.log_connected();
            }

            // 让复用连接为本任务准备新的上下文（任务笔记、限速统计等）
            connection.0.prepare_new(&self.task_notes, &self.upstream);
            self.mark_relaying();

            let r = self
                .run_with_connection(fwd_ctx, clt_r, clt_w, connection, audit_task)
                .await;
            match r {
                Ok(ups_s) => {
                    self.save_or_close(fwd_ctx, clt_w, ups_s).await;
                    return Ok(());
                }
                Err(e) => {
                    if self.http_notes.retry_new_connection {
                        // 失败发生在向上游发出任何请求数据之前（幂等安全），
                        // 输出本次日志后丢弃该连接，继续走下面的新建连接重试
                        if let Some(log_ctx) = self.get_log_context() {
                            log_ctx.log(&e);
                        }
                        self.task_stats.ups.reset();
                        // continue to make new connection
                        if let Some(user_ctx) = self.task_notes.user_ctx() {
                            user_ctx
                                .foreach_req_stats(|s| s.req_renew.add_http_forward(self.is_https));
                        }
                    } else {
                        // 请求已部分发出，不能重试，直接回错误并终止
                        self.should_close = true;
                        if self.send_error_response {
                            self.reply_task_err(&e, clt_w).await;
                        }
                        return Err(e);
                    }
                }
            }
        }

        // 无可复用连接（或复用失败后重试）：新建上游连接
        let connection = self.get_new_connection(fwd_ctx, clt_w).await?;
        match self
            .run_with_connection(fwd_ctx, clt_r, clt_w, connection, audit_task)
            .await
        {
            Ok(ups_s) => {
                self.save_or_close(fwd_ctx, clt_w, ups_s).await;
                Ok(())
            }
            Err(e) => {
                self.should_close = true;
                if self.send_error_response {
                    self.reply_task_err(&e, clt_w).await;
                }
                Err(e)
            }
        }
    }

    /// 任务结束后的连接去留：若客户端连接需关闭则同时关闭上游连接并 shutdown 客户端写器；
    /// 否则把可复用的上游连接放回连接池。
    async fn save_or_close<CDW>(
        &self,
        fwd_ctx: &mut BoxHttpForwardContext,
        clt_w: &mut HttpClientWriter<CDW>,
        ups_s: Option<BoxHttpForwardConnection>,
    ) where
        CDW: AsyncWrite + Unpin,
    {
        if self.should_close {
            if let Some(mut connection) = ups_s {
                let _ = connection.0.shutdown().await;
            }
            let _ = clt_w.shutdown().await;
        } else if let Some(connection) = ups_s {
            fwd_ctx.save_alive_connection(connection);
        }
    }

    /// 新建上游连接并切换到 Connected/Relaying 阶段；连接失败时回复客户端错误并上抛。
    async fn get_new_connection<CDW>(
        &mut self,
        fwd_ctx: &mut BoxHttpForwardContext,
        clt_w: &mut HttpClientWriter<CDW>,
    ) -> ServerTaskResult<BoxHttpForwardConnection>
    where
        CDW: AsyncWrite + Send + Unpin,
    {
        self.task_notes.stage = ServerTaskStage::Connecting;
        self.http_notes.reused_connection = false;

        match self.make_new_connection(fwd_ctx).await {
            Ok(mut connection) => {
                self.task_notes.stage = ServerTaskStage::Connected;
                fwd_ctx.fetch_tcp_notes(&mut self.tcp_notes);

                if self.ctx.server_config.flush_task_log_on_connected
                    && let Some(log_ctx) = self.get_log_context()
                {
                    log_ctx.log_connected();
                }

                connection.0.prepare_new(&self.task_notes, &self.upstream);
                self.mark_relaying();
                Ok(connection)
            }
            Err(e) => {
                fwd_ctx.fetch_tcp_notes(&mut self.tcp_notes);
                self.should_close = true;
                self.reply_connect_err(&e, clt_w).await;
                Err(e.into())
            }
        }
    }

    /// 实际建立上游连接：is_https 时走 TCP+TLS（TLS SNI 优先取请求 Host，
    /// TLS 客户端配置可被用户站点级配置覆盖），否则仅 TCP 连接。
    async fn make_new_connection(
        &self,
        fwd_ctx: &mut BoxHttpForwardContext,
    ) -> Result<BoxHttpForwardConnection, TcpConnectError> {
        if self.is_https {
            let tls_name = self.req.host.as_ref().unwrap_or(&self.upstream).host();

            let tls_client = self
                .task_notes
                .user_ctx()
                .and_then(|ctx| ctx.user_site())
                .and_then(|site| site.tls_client())
                .unwrap_or(&self.ctx.tls_client_config);

            let task_conf = TlsConnectTaskConf {
                tcp: TcpConnectTaskConf {
                    upstream: &self.upstream,
                },
                tls_config: tls_client,
                tls_name,
            };
            fwd_ctx
                .make_new_https_connection(&task_conf, &self.task_notes, self.task_stats.clone())
                .await
        } else {
            let task_conf = TcpConnectTaskConf {
                upstream: &self.upstream,
            };
            fwd_ctx
                .make_new_http_connection(&task_conf, &self.task_notes, self.task_stats.clone())
                .await
        }
    }

    /// 标记任务进入转发（Relaying）阶段，并累加用户级"就绪"请求计数。
    fn mark_relaying(&mut self) {
        self.task_notes.mark_relaying();
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| s.req_ready.add_http_forward(self.is_https));
        }
    }

    /// 在已建立的上游连接上执行本次转发。
    /// 返回 Ok(Some(conn)) 表示连接可放回池复用；Ok(None) 表示连接已被显式关闭。
    /// 若任务开启审计且存在 ICAP reqmod 客户端，则走请求适配路径，否则走普通转发路径。
    async fn run_with_connection<CDR, CDW>(
        &mut self,
        fwd_ctx: &mut BoxHttpForwardContext,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
        mut ups_c: BoxHttpForwardConnection,
        audit_task: bool,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        CDR: AsyncRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        // 复用连接健康检查：池中的空闲连接此刻不应立即可读；若 poll 立刻就绪
        // （残留数据/EOF/读错误）说明连接已不可信。此时尚未发出请求，可安全换新连接重试
        if self.http_notes.reused_connection
            && let Some(r) = ups_c.1.fill_wait_data().now_or_never()
        {
            self.http_notes.retry_new_connection = true;
            return match r {
                Ok(true) => Err(ServerTaskError::UpstreamAppError(anyhow!(
                    "unexpected data found when polling IDLE connection"
                ))),
                Ok(false) => Err(ServerTaskError::ClosedByUpstream),
                Err(e) => Err(ServerTaskError::UpstreamReadFailed(e)),
            };
        }

        // ICAP reqmod 审计路径：由适配器接管"读客户端请求 + 写上游"的过程
        if audit_task
            && let Some(audit_handle) = self.audit_ctx.handle()
            && let Some(reqmod) = audit_handle.icap_reqmod_client()
        {
            match reqmod
                .h1_adapter(
                    self.ctx.server_config.tcp_copy,
                    self.ctx.server_config.body_line_max_len,
                    true,
                    self.ctx.idle_checker(&self.task_notes),
                )
                .await
            {
                Ok(mut adapter) => {
                    let mut adaptation_state =
                        ReqmodAdaptationRunState::new(self.task_notes.task_created_instant());
                    adapter.set_client_addr(self.ctx.client_addr());
                    if let Some(name) = self.task_notes.raw_user_name() {
                        adapter.set_client_username(name.clone());
                    }
                    let r = self
                        .run_with_adaptation(clt_r, clt_w, ups_c, adapter, &mut adaptation_state)
                        .await;
                    // 把适配器测得的请求头/请求体发送耗时回填到任务笔记
                    if let Some(dur) = adaptation_state.dur_ups_send_header {
                        self.http_notes.dur_req_send_hdr = dur;
                    }
                    if let Some(dur) = adaptation_state.dur_ups_send_all {
                        self.http_notes.dur_req_send_all = dur;
                    }
                    return r;
                }
                Err(e) => {
                    // 适配器建立失败：此刻尚未发送请求，标记可换新连接重试；
                    // 未配置 bypass 则直接报错，否则降级走普通转发路径
                    self.http_notes.retry_new_connection = true;
                    if !reqmod.bypass() {
                        return Err(ServerTaskError::InternalAdapterError(e));
                    }
                }
            }
        }

        self.run_without_adaptation(fwd_ctx, clt_r, clt_w, ups_c)
            .await
    }

    /// 等待上游响应头的超时：用户级配置优先，否则服务器级配置。
    fn rsp_hdr_recv_timeout(&self) -> Duration {
        self.task_notes
            .user_ctx()
            .and_then(|ctx| ctx.http_rsp_header_recv_timeout())
            .unwrap_or(self.ctx.server_config.timeout.recv_rsp_header)
    }

    /// ICAP reqmod 路径的执行体：并发地进行"适配器转发请求"与"读取上游响应"，
    /// 上游可能提前返回最终响应（如 413 拒绝大请求体、适配器还没传完请求体），
    /// 拿到响应头后跳出循环并回传响应。
    async fn run_with_adaptation<CDR, CDW>(
        &mut self,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
        mut ups_c: BoxHttpForwardConnection,
        icap_adapter: HttpRequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        CDR: AsyncRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        use crate::module::http_forward::HttpForwardWriterForAdaptation;

        let ups_w = &mut ups_c.0;
        let ups_r = &mut ups_c.1;

        let mut ups_w_adaptation = HttpForwardWriterForAdaptation { inner: ups_w };
        let mut adaptation_fut = icap_adapter
            .xfer(
                adaptation_state,
                self.req,
                clt_r.as_mut(),
                &mut ups_w_adaptation,
            )
            .boxed();

        let mut log_interval = self.ctx.get_log_interval();

        // 记录进入本函数时客户端已读字节数，用于判断请求是否尚未向外发送（决定能否重试）
        let clt_read_size = self.task_stats.clt.read.get_bytes();
        let mut rsp_header: Option<HttpForwardRemoteResponse> = None;
        loop {
            tokio::select! {
                biased;

                r = ups_r.fill_wait_data() => {
                    match r {
                        Ok(true) => {
                            // we got some data from upstream
                            let hdr = self.recv_response_header(ups_r).await?;
                            match hdr.code {
                                100 | 103 => {
                                    // CONTINUE | Early Hints
                                    self.send_response_header(clt_w, &hdr).await?;
                                }
                                _ => {
                                    rsp_header = Some(hdr);
                                    break;
                                }
                            }
                        }
                        Ok(false) =>  {
                            // 上游关闭：若请求尚未向外发送任何字节，可换新连接重试
                            if self.task_stats.clt.read.get_bytes() == clt_read_size {
                                self.http_notes.retry_new_connection = true;
                            }
                            return Err(ServerTaskError::ClosedByUpstream);
                        },
                        Err(e) => {
                            if self.task_stats.clt.read.get_bytes() == clt_read_size {
                                self.http_notes.retry_new_connection = true;
                            }
                            return Err(ServerTaskError::UpstreamReadFailed(e));
                        },
                    }
                }
                r = &mut adaptation_fut => {
                    match r {
                        Ok(ReqmodAdaptationEndState::OriginalTransferred) => {
                            break;
                        }
                        Ok(ReqmodAdaptationEndState::AdaptedTransferred(_r)) => {
                            // TODO add log for adapted request?
                            break;
                        }
                        Ok(ReqmodAdaptationEndState::HttpErrResponse(rsp, rsp_recv_body)) => {
                            // 适配器直接给出 HTTP 错误响应，透传回客户端后任务结束
                            self.send_adaptation_error_response(clt_w, rsp, rsp_recv_body).await?;
                            return Ok(None);
                        }
                        Err(e) => {
                            // 仅当 ICAP 服务器侧连接断开/读失败且请求还没发出时才允许重试
                            if self.task_stats.clt.read.get_bytes() == clt_read_size {
                                self.http_notes.retry_new_connection = matches!(
                                    e,
                                    H1ReqmodAdaptationError::IcapServerConnectionClosed | H1ReqmodAdaptationError::IcapServerReadFailed(_)
                                );
                            }
                            return Err(e.into());
                        }
                    }
                }
                _ = log_interval.tick() => {
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
            }
        }
        drop(adaptation_fut);

        let mut close_remote = false;
        let mut rsp_header = match rsp_header {
            Some(header) => {
                if !adaptation_state.clt_read_finished {
                    // not all client data read in, drop the client connection
                    self.should_close = true;
                }
                if !adaptation_state.ups_write_finished {
                    // not all client data sent out, only drop the remote connection
                    close_remote = true;
                }
                // if not all data sent to remote, the remote response should be `close`,
                // and the remote connection will close if remote has set `close`
                header
            }
            None => {
                // 请求已全部交给上游但尚未读到响应头：带超时等待最终响应（跳过中间 1xx）
                match tokio::time::timeout(
                    self.rsp_hdr_recv_timeout(),
                    self.recv_final_response_header(ups_r, clt_w),
                )
                .await
                {
                    Ok(Ok(rsp_header)) => rsp_header,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ServerTaskError::UpstreamAppTimeout(
                            "timeout to receive response header",
                        ));
                    }
                }
            }
        };
        self.http_notes.mark_rsp_recv_hdr();

        // audit_task=true：响应体也可能再经 ICAP respmod 适配；
        // 把 reqmod 阶段产生的共享响应头带入 respmod 阶段
        self.send_response(
            clt_w,
            ups_r,
            &mut rsp_header,
            true,
            adaptation_state.take_respond_shared_headers(),
        )
        .await?;

        self.task_notes.stage = ServerTaskStage::Finished;
        if close_remote {
            // 请求未完整发给上游：该上游连接不可复用，直接关闭
            let _ = ups_w.shutdown().await;
            Ok(None)
        } else {
            Ok(Some(ups_c))
        }
    }

    /// 把 ICAP 适配器返回的本地错误响应（含可选的响应体）写回客户端；
    /// 响应已开始发出，之后不允许再补发代理自身的错误响应。
    async fn send_adaptation_error_response<W>(
        &mut self,
        clt_w: &mut W,
        mut rsp: HttpAdapterErrorResponse,
        rsp_recv_body: Option<ReqmodRecvHttpResponseBody>,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.should_close = true;

        self.ctx
            .set_custom_header_for_adaptation_error_reply(&self.tcp_notes, &mut rsp);

        let buf = rsp.serialize(self.should_close);
        self.send_error_response = false;
        clt_w
            .write_all(buf.as_ref())
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        self.http_notes.rsp_status = rsp.status.as_u16();

        if let Some(mut recv_body) = rsp_recv_body {
            // 错误响应带响应体：从 ICAP 连接流式拷贝到客户端，完毕后归还该 ICAP 连接
            let mut body_reader = recv_body.body_reader();
            let copy_to_clt =
                StreamCopy::new(&mut body_reader, clt_w, &self.ctx.server_config.tcp_copy);
            copy_to_clt.await.map_err(|e| match e {
                StreamCopyError::ReadFailed(e) => ServerTaskError::InternalAdapterError(anyhow!(
                    "read http error response from adapter failed: {e:?}"
                )),
                StreamCopyError::WriteFailed(e) => ServerTaskError::ClientTcpWriteFailed(e),
            })?;
            recv_body.save_connection().await;
        } else {
            clt_w
                .flush()
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        }

        Ok(())
    }

    /// 普通（无 reqmod 适配）转发路径的调度：按请求是否携带 body 选择不同策略——
    /// 无 body 直接单轮收发；小 body 一次性读完整体发送（可安全重试）；
    /// 大 body 流式转发并在发送中并发等待上游提前响应。
    async fn run_without_adaptation<CDR, CDW>(
        &mut self,
        fwd_ctx: &mut BoxHttpForwardContext,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
        mut ups_c: BoxHttpForwardConnection,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        CDR: AsyncRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        match self.req.body_type() {
            Some(body_type) => {
                let Some(clt_r) = clt_r else {
                    return Err(ServerTaskError::InternalServerError(
                        "http body is expected but no body reader supplied",
                    ));
                };

                let mut clt_body_reader =
                    HttpBodyReader::new(clt_r, body_type, self.ctx.server_config.body_line_max_len);

                if self.req.end_to_end_headers.contains_key(header::EXPECT) {
                    // Expect: 100-continue：先发头等待上游决定，不抢读 body
                    return self
                        .run_with_body(None, &mut clt_body_reader, clt_w, ups_c)
                        .await;
                }

                // 快速路径：尝试一次性把整个请求体读进内存（正文不超过一个拷贝缓冲大小时成立），
                // 这样后续任何失败都能安全地换新连接整体重发
                let mut fast_read_buf = vec![0u8; self.ctx.server_config.tcp_copy.buffer_size()];
                let nr = clt_body_reader
                    .read_all_now(&mut fast_read_buf)
                    .await
                    .map_err(ServerTaskError::ClientTcpReadFailed)?
                    .ok_or(ServerTaskError::ClosedByClient)?;
                if nr == 0 {
                    // body 暂时不可读（如大 body 未到达），退回流式转发
                    return self
                        .run_with_body(None, &mut clt_body_reader, clt_w, ups_c)
                        .await;
                }

                fast_read_buf.truncate(nr);
                if clt_body_reader.finished() {
                    // 完整 body 已在内存中：头+体一次性发出
                    return self
                        .run_with_all_body(fwd_ctx, fast_read_buf, clt_w, ups_c)
                        .await;
                }

                // 只读到部分 body：以已读部分为起点做流式转发；
                // 若失败且尚未向外发出数据，则换新连接重试（携带已读的快读缓冲）
                loop {
                    match self
                        .run_with_body(
                            Some(fast_read_buf.clone()),
                            &mut clt_body_reader,
                            clt_w,
                            ups_c,
                        )
                        .await
                    {
                        Ok(r) => return Ok(r),
                        Err(e) => {
                            if self.http_notes.reused_connection
                                && self.http_notes.retry_new_connection
                            {
                                if let Some(log_ctx) = self.get_log_context() {
                                    log_ctx.log(&e);
                                }
                                self.task_stats.ups.reset();
                                ups_c = self.get_new_connection(fwd_ctx, clt_w).await?;
                            } else {
                                self.http_notes.retry_new_connection = false;
                                return Err(e);
                            }
                        }
                    }
                }
            }
            None => self.run_without_body(clt_w, ups_c).await,
        }
    }

    /// 无请求体的转发（GET/HEAD 等）：只发请求头，等待并回传响应；
    /// 复用连接上失败且未读到任何响应时可换新连接重试。
    async fn run_without_body<W>(
        &mut self,
        clt_w: &mut W,
        mut ups_c: BoxHttpForwardConnection,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let ups_w = &mut ups_c.0;
        let ups_r = &mut ups_c.1;

        // 先乐观地允许重试；一旦开始收到上游响应数据就置回 false
        self.http_notes.retry_new_connection = true;
        ups_w
            .send_request_header(self.req, None)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        ups_w
            .flush()
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        self.http_notes.mark_req_send_hdr();
        self.http_notes.mark_req_no_body();

        // 带超时等待上游响应头
        let mut rsp_header = match tokio::time::timeout(
            self.rsp_hdr_recv_timeout(),
            self.recv_response_header(ups_r),
        )
        .await
        {
            Ok(Ok(rsp_header)) => {
                self.http_notes.retry_new_connection = false;
                rsp_header
            }
            Ok(Err(e)) => {
                if self.task_stats.ups.read.get_bytes() == 0 {
                    // 还没从上游读到任何字节：对端关闭/读错误可换新连接重试；
                    // 解析错误等则不重试
                    self.http_notes.retry_new_connection = matches!(
                        e,
                        ServerTaskError::ClosedByUpstream | ServerTaskError::UpstreamReadFailed(_)
                    );
                } else {
                    self.http_notes.retry_new_connection = false;
                }
                return Err(e);
            }
            Err(_) => {
                // 等响应头超时：请求可能已被上游处理，绝不重试
                self.http_notes.retry_new_connection = false;
                return Err(ServerTaskError::UpstreamAppTimeout(
                    "timeout to receive response header",
                ));
            }
        };
        self.http_notes.mark_rsp_recv_hdr();

        self.send_response(clt_w, ups_r, &mut rsp_header, false, None)
            .await?;

        self.task_notes.stage = ServerTaskStage::Finished;
        Ok(Some(ups_c))
    }

    /// 把完整请求（头+内存中的 body）一次性发给上游并带超时等待响应头；
    /// 因请求未外发前失败仍可整体重试，返回错误时通过 retry_new_connection 表明是否可重试。
    async fn send_full_req_and_recv_rsp(
        &mut self,
        body: &[u8],
        ups_r: &mut BoxHttpForwardReader,
        ups_w: &mut BoxHttpForwardWriter,
    ) -> ServerTaskResult<HttpForwardRemoteResponse> {
        self.http_notes.retry_new_connection = true;

        ups_w
            .send_request_header(self.req, Some(body))
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        ups_w
            .flush()
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        self.http_notes.mark_req_send_hdr();
        self.http_notes.mark_req_send_all();

        match tokio::time::timeout(
            self.rsp_hdr_recv_timeout(),
            self.recv_response_header(ups_r),
        )
        .await
        {
            Ok(Ok(rsp_header)) => {
                self.http_notes.retry_new_connection = false;
                Ok(rsp_header)
            }
            Ok(Err(e)) => {
                if self.task_stats.ups.read.get_bytes() == 0 {
                    self.http_notes.retry_new_connection = matches!(
                        e,
                        ServerTaskError::ClosedByUpstream | ServerTaskError::UpstreamReadFailed(_)
                    );
                } else {
                    self.http_notes.retry_new_connection = false;
                }
                Err(e)
            }
            Err(_) => {
                self.http_notes.retry_new_connection = false;
                Err(ServerTaskError::UpstreamAppTimeout(
                    "timeout to receive response header",
                ))
            }
        }
    }

    /// 请求体已全部在内存中的转发路径：整体重发失败可换新连接循环重试，成功后回传响应。
    async fn run_with_all_body<CDW>(
        &mut self,
        fwd_ctx: &mut BoxHttpForwardContext,
        body: Vec<u8>,
        clt_w: &mut HttpClientWriter<CDW>,
        mut ups_c: BoxHttpForwardConnection,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        CDW: AsyncWrite + Send + Unpin,
    {
        loop {
            let ups_w = &mut ups_c.0;
            let ups_r = &mut ups_c.1;

            let mut rsp_header = match self
                .send_full_req_and_recv_rsp(body.as_slice(), ups_r, ups_w)
                .await
            {
                Ok(rsp_header) => rsp_header,
                Err(e) => {
                    if self.http_notes.reused_connection && self.http_notes.retry_new_connection {
                        if let Some(log_ctx) = self.get_log_context() {
                            log_ctx.log(&e);
                        }
                        self.task_stats.ups.reset();
                        ups_c = self.get_new_connection(fwd_ctx, clt_w).await?;
                        continue;
                    } else {
                        self.http_notes.retry_new_connection = false;
                        return Err(e);
                    }
                }
            };

            self.http_notes.mark_rsp_recv_hdr();

            self.send_response(clt_w, ups_r, &mut rsp_header, false, None)
                .await?;

            self.task_notes.stage = ServerTaskStage::Finished;
            return Ok(Some(ups_c));
        }
    }

    /// 带流式请求体的转发路径：先发送请求头，然后并发执行
    /// "客户端 body -> 上游" 拷贝与 "等待上游响应头"（上游可能在 body 未传完时
    /// 就提前返回最终响应，例如 413）；循环内还处理空闲超时计数、周期日志、
    /// 用户封禁与服务器退出策略。
    async fn run_with_body<R, CDW>(
        &mut self,
        fast_read_buf: Option<Vec<u8>>,
        clt_body_reader: &mut HttpBodyReader<'_, R>,
        clt_w: &mut HttpClientWriter<CDW>,
        mut ups_c: BoxHttpForwardConnection,
    ) -> ServerTaskResult<Option<BoxHttpForwardConnection>>
    where
        R: AsyncBufRead + Send + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        let ups_w = &mut ups_c.0;
        let ups_r = &mut ups_c.1;

        // 发送请求头阶段失败可重试；一旦开始外发 body（下面立即置 false）就不再重试
        self.http_notes.retry_new_connection = true;
        ups_w
            .send_request_header(self.req, None)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        ups_w
            .flush()
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        self.http_notes.mark_req_send_hdr();
        self.http_notes.retry_new_connection = false;

        // 请求体拷贝器：fast_read_buf 是之前抢读到的 body 起始部分，作为已读数据先行写出
        let mut clt_to_ups = match fast_read_buf {
            Some(buf) => StreamCopy::with_data(
                clt_body_reader,
                ups_w,
                &self.ctx.server_config.tcp_copy,
                buf,
            ),
            None => StreamCopy::new(clt_body_reader, ups_w, &self.ctx.server_config.tcp_copy),
        };

        let mut rsp_header: Option<HttpForwardRemoteResponse> = None;

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut log_interval = self.ctx.get_log_interval();
        let mut idle_count = 0;
        loop {
            tokio::select! {
                biased;

                r = ups_r.fill_wait_data() => {
                    match r {
                        Ok(true) => {
                            // we got some data from upstream
                            let hdr = self.recv_response_header(ups_r).await?;
                            match hdr.code {
                                100 | 103 => {
                                    // CONTINUE | Early Hints
                                    self.send_response_header(clt_w, &hdr).await?;
                                }
                                _ => {
                                    rsp_header = Some(hdr);
                                    break;
                                }
                            }
                        }
                        Ok(false) => {
                            // 上游关闭：若还没从客户端读走任何 body 字节，可换新连接重试
                            if clt_to_ups.read_size() == 0 {
                                self.http_notes.retry_new_connection = true;
                            }
                            return Err(ServerTaskError::ClosedByUpstream);
                        },
                        Err(e) => {
                            if clt_to_ups.read_size() == 0 {
                                self.http_notes.retry_new_connection = true;
                            }
                            return Err(ServerTaskError::UpstreamReadFailed(e));
                        },
                    }
                }
                r = &mut clt_to_ups => {
                    // 请求体已全部发给上游：结束循环，转为等待最终响应
                    r.map_err(|e| match e {
                        StreamCopyError::ReadFailed(e) => ServerTaskError::ClientTcpReadFailed(e),
                        StreamCopyError::WriteFailed(e) => ServerTaskError::UpstreamWriteFailed(e),
                    })?;
                    self.http_notes.mark_req_send_all();
                    break;
                }
                _ = log_interval.tick() => {
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
                n = idle_interval.tick() => {
                    // 空闲检查：拷贝持续空闲则累计，超限判定超时；
                    // 无缓存数据=客户端不发（读侧超时），有缓存数据=上游不收（写侧超时）
                    if clt_to_ups.is_idle() {
                        idle_count += n;

                        if let Some(user_ctx) = self.task_notes.user_ctx() {
                            let user = user_ctx.user();
                            if user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }
                        }

                        if idle_count >= self.max_idle_count {
                            return if clt_to_ups.no_cached_data() {
                                Err(ServerTaskError::ClientAppTimeout("idle while reading request body"))
                            } else {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while sending request body"))
                            };
                        }
                    } else {
                        idle_count = 0;

                        clt_to_ups.reset_active();
                    }

                    if let Some(user_ctx) = self.task_notes.user_ctx()
                        && user_ctx.user().is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    if self.ctx.server_quit_policy.force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
        drop(idle_interval);

        let mut close_remote = false;
        let copy_done = clt_to_ups.finished();
        let mut rsp_header = match rsp_header {
            Some(header) => {
                if !clt_body_reader.finished() {
                    // not all client data read in, drop the client connection
                    self.should_close = true;
                }
                if !copy_done {
                    // not all client data sent out, only drop the remote connection
                    close_remote = true;
                }
                // if not all data sent to remote, the remote response should be `close`,
                // and the remote connection will close if remote has set `close`
                header
            }
            None => {
                match tokio::time::timeout(
                    self.rsp_hdr_recv_timeout(),
                    self.recv_final_response_header(ups_r, clt_w),
                )
                .await
                {
                    Ok(Ok(rsp_header)) => rsp_header,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ServerTaskError::UpstreamAppTimeout(
                            "timeout to receive response header",
                        ));
                    }
                }
            }
        };
        self.http_notes.mark_rsp_recv_hdr();

        self.send_response(clt_w, ups_r, &mut rsp_header, false, None)
            .await?;

        self.task_notes.stage = ServerTaskStage::Finished;
        if close_remote {
            let _ = ups_w.shutdown().await;
            Ok(None)
        } else {
            Ok(Some(ups_c))
        }
    }

    /// 读取最终响应头：100 Continue 先转发给客户端再读下一条；
    /// 103 Early Hints 持续转发直到出现非 103 响应。
    async fn recv_final_response_header<W>(
        &mut self,
        ups_r: &mut BoxHttpForwardReader,
        clt_w: &mut W,
    ) -> ServerTaskResult<HttpForwardRemoteResponse>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            let hdr = self.recv_response_header(ups_r).await?;
            match hdr.code {
                100 => {
                    // HTTP CONTINUE
                    self.send_response_header(clt_w, &hdr).await?;
                    // recv the final response header
                    return self.recv_response_header(ups_r).await;
                }
                103 => {
                    // HTTP Early Hints
                    self.send_response_header(clt_w, &hdr).await?;
                }
                _ => return Ok(hdr),
            }
        }
    }

    /// 从上游读取一条响应头（可能是 1xx 临时响应），并更新 http_notes 中的耗时信息。
    async fn recv_response_header(
        &mut self,
        ups_r: &mut BoxHttpForwardReader,
    ) -> ServerTaskResult<HttpForwardRemoteResponse> {
        ups_r
            .recv_response_header(
                &self.req.method,
                self.req.keep_alive(),
                self.ctx.server_config.rsp_hdr_max_size,
                &mut self.http_notes,
            )
            .await
            .map_err(|e| e.into())
    }

    /// 把上游响应回传给客户端：先做 keepalive 一致性与代理信息头改写，
    /// 若开启审计且存在 ICAP respmod 客户端则走响应适配路径，否则直接流式回传。
    /// adaptation_respond_shared_headers 为 reqmod 阶段与 respmod 阶段共享的响应头。
    async fn send_response<R, W>(
        &mut self,
        clt_w: &mut W,
        ups_r: &mut R,
        rsp_header: &mut HttpForwardRemoteResponse,
        audit_task: bool,
        adaptation_respond_shared_headers: Option<HttpHeaderMap>,
    ) -> ServerTaskResult<()>
    where
        R: AsyncBufRead + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        // keepalive 协商：本任务要关客户端则要求响应也别复用；
        // 上游响应本身不 keepalive 时客户端连接也必须关闭
        if self.should_close {
            rsp_header.set_no_keep_alive();
        }
        if !rsp_header.keep_alive() {
            self.should_close = true;
        }
        // origin_status 记录上游原始状态码；rsp_status 在真正发出前置 0 表示尚未回复
        self.http_notes.origin_status = rsp_header.code;
        self.http_notes.rsp_status = 0;
        self.update_response_header(rsp_header);

        // ICAP respmod 审计路径：响应体经适配器改写后再回传
        if audit_task
            && let Some(audit_handle) = self.audit_ctx.handle()
            && let Some(respmod) = audit_handle.icap_respmod_client()
        {
            match respmod
                .h1_adapter(
                    self.ctx.server_config.tcp_copy,
                    self.ctx.server_config.body_line_max_len,
                    self.ctx.idle_checker(&self.task_notes),
                )
                .await
            {
                Ok(mut adapter) => {
                    let mut adaptation_state = RespmodAdaptationRunState::new(
                        self.task_notes.task_created_instant(),
                        self.http_notes.dur_rsp_recv_hdr,
                    );
                    adapter.set_client_addr(self.ctx.client_addr());
                    if let Some(name) = self.task_notes.raw_user_name() {
                        adapter.set_client_username(name.clone());
                    }
                    adapter.set_respond_shared_headers(adaptation_respond_shared_headers);
                    let r = self
                        .send_response_with_adaptation(
                            clt_w,
                            ups_r,
                            rsp_header,
                            adapter,
                            &mut adaptation_state,
                        )
                        .await;
                    if !adaptation_state.clt_write_finished || !adaptation_state.ups_read_finished {
                        // 响应未完整读写：两端连接都不能再复用
                        self.should_close = true;
                    }
                    if let Some(dur) = adaptation_state.dur_ups_recv_all {
                        self.http_notes.dur_rsp_recv_all = dur;
                    }
                    // 客户端还没收到任何响应数据时，出错仍可补发代理自身的错误响应
                    self.send_error_response = !adaptation_state.clt_write_started;
                    return r;
                }
                Err(e) => {
                    if !respmod.bypass() {
                        return Err(ServerTaskError::InternalAdapterError(e));
                    }
                }
            }
        }

        self.send_response_without_adaptation(clt_w, ups_r, rsp_header)
            .await
    }

    /// 由 ICAP respmod 适配器接管"读上游响应体并写客户端"的整个过程，
    /// 期间仅并发做周期日志输出；记录适配后（adapted）或原始响应的状态码。
    async fn send_response_with_adaptation<R, W>(
        &mut self,
        clt_w: &mut W,
        ups_r: &mut R,
        rsp_header: &HttpForwardRemoteResponse,
        icap_adapter: HttpResponseAdapter<ServerIdleChecker>,
        adaptation_state: &mut RespmodAdaptationRunState,
    ) -> ServerTaskResult<()>
    where
        R: AsyncBufRead + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        let mut log_interval = self.ctx.get_log_interval();
        let mut adaptation_fut = icap_adapter
            .xfer(adaptation_state, self.req, rsp_header, ups_r, clt_w)
            .boxed();
        loop {
            tokio::select! {
                biased;

                _ = log_interval.tick() => {
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
                r = &mut adaptation_fut => {
                    return match r {
                        Ok(RespmodAdaptationEndState::OriginalTransferred) => {
                            self.http_notes.rsp_status = rsp_header.code;
                            Ok(())
                        }
                        Ok(RespmodAdaptationEndState::AdaptedTransferred(adapted_rsp)) => {
                            self.http_notes.rsp_status = adapted_rsp.code;
                            Ok(())
                        }
                        Err(e) => Err(e.into()),
                    }
                }
            }
        }
    }

    /// 直接回传响应：响应无 body（如 HEAD/204/304）时只发响应头；
    /// 有 body 时把头序列化进首个拷贝块，交给 send_response_body 流式转发。
    async fn send_response_without_adaptation<R, W>(
        &mut self,
        clt_w: &mut W,
        ups_r: &mut R,
        rsp_header: &HttpForwardRemoteResponse,
    ) -> ServerTaskResult<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.send_error_response = false;

        if let Some(body_type) = rsp_header.body_type(&self.req.method) {
            let mut buf = Vec::with_capacity(self.ctx.server_config.tcp_copy.buffer_size());
            rsp_header.serialize_to(&mut buf);
            self.http_notes.rsp_status = rsp_header.code; // the following function must send rsp header out
            self.send_response_body(buf, clt_w, ups_r, body_type).await
        } else {
            self.send_response_header(clt_w, rsp_header).await?;
            self.http_notes.rsp_status = rsp_header.code;
            self.http_notes.mark_rsp_no_body();
            Ok(())
        }
    }

    /// 响应体流式回传：按响应体类型（chunked / content-length）用 HttpBodyReader
    /// 解析上游 body，并经 StreamCopy 拷贝到客户端（响应头字节已作为预置数据先写出）。
    /// 循环内处理空闲超时、周期日志、用户封禁与强制退出；
    /// 退出前若响应头还没发给客户端，会先尽力把已缓存的头部字节 flush 出去。
    async fn send_response_body<R, W>(
        &mut self,
        header: Vec<u8>,
        clt_w: &mut W,
        ups_r: &mut R,
        body_type: HttpBodyType,
    ) -> ServerTaskResult<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let header_len = header.len() as u64;
        let mut body_reader =
            HttpBodyReader::new(ups_r, body_type, self.ctx.server_config.body_line_max_len);

        // 响应头 + 上游 body 合并为一个拷贝流，减少一次独立写
        let mut ups_to_clt = StreamCopy::with_data(
            &mut body_reader,
            clt_w,
            &self.ctx.server_config.tcp_copy,
            header,
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut log_interval = self.ctx.get_log_interval();
        let mut idle_count = 0;
        loop {
            tokio::select! {
                biased;

                r = &mut ups_to_clt => {
                    return match r {
                        Ok(_) => {
                            self.http_notes.mark_rsp_recv_all();
                            // clt_w is already flushed
                            Ok(())
                        }
                        Err(StreamCopyError::ReadFailed(e)) => {
                            if ups_to_clt.copied_size() < header_len {
                                let _ = ups_to_clt.write_flush().await; // flush rsp header to client
                            }
                            Err(ServerTaskError::UpstreamReadFailed(e))
                        }
                        Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::ClientTcpWriteFailed(e)),
                    };
                }
                _ = log_interval.tick() => {
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
                n = idle_interval.tick() => {
                    if ups_to_clt.is_idle() {
                        idle_count += n;

                        if let Some(user_ctx) = self.task_notes.user_ctx() {
                            let user = user_ctx.user();
                            if user.is_blocked() {
                                if ups_to_clt.copied_size() < header_len {
                                    let _ = ups_to_clt.write_flush().await; // flush rsp header to client
                                }
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }

                        }

                        if idle_count >= self.max_idle_count {
                            return if ups_to_clt.no_cached_data() {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while reading response body"))
                            } else {
                                Err(ServerTaskError::ClientAppTimeout("idle while sending response with body"))
                            };
                        }
                    } else {
                        idle_count = 0;

                        ups_to_clt.reset_active();
                    }

                    if let Some(user_ctx) = self.task_notes.user_ctx()
                        && user_ctx.user().is_blocked() {
                            if ups_to_clt.copied_size() < header_len {
                                let _ = ups_to_clt.write_flush().await; // flush rsp header to client
                            }
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    if self.ctx.server_quit_policy.force_quit() {
                        if ups_to_clt.copied_size() < header_len {
                            let _ = ups_to_clt.write_flush().await; // flush rsp header to client
                        }
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }

    /// 改写响应头：把代理自身的诊断信息（服务器 id、上游连接信息、动态出口、
    /// 链式部署下的目标地址/出口 IP）追加到 hop-by-hop 头集合，
    /// 这些头会原样透传给客户端且不参与 ICAP 适配改写。
    fn update_response_header(&self, rsp: &mut HttpForwardRemoteResponse) {
        // append headers to hop-by-hop headers, so they will pass to client without adaptation
        if let Some(server_id) = &self.ctx.server_config.server_id {
            if self.ctx.server_config.http_forward_mark_upstream {
                http_header::set_upstream_id(&mut rsp.hop_by_hop_headers, server_id);
            }

            http_header::set_remote_connection_info(
                &mut rsp.hop_by_hop_headers,
                server_id,
                self.tcp_notes.bind.ip(),
                self.tcp_notes.local,
                self.tcp_notes.next,
                &self.tcp_notes.expire,
            );

            if let Some(egress_info) = &self.tcp_notes.egress {
                http_header::set_dynamic_egress_info(
                    &mut rsp.hop_by_hop_headers,
                    server_id,
                    egress_info,
                );
            }
        }

        if self.ctx.server_config.echo_chained_info {
            if let Some(addr) = self.tcp_notes.chained.target_addr {
                http_header::set_upstream_addr(&mut rsp.hop_by_hop_headers, addr);
            }

            if let Some(addr) = self.tcp_notes.chained.outgoing_addr {
                http_header::set_outgoing_ip(&mut rsp.hop_by_hop_headers, addr);
            }
        }
    }

    /// 序列化并立即（write+flush）把一条响应头发给客户端，用于 1xx 等临时响应透传。
    async fn send_response_header<W>(
        &mut self,
        clt_w: &mut W,
        rsp: &HttpForwardRemoteResponse,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let buf = rsp.serialize();
        clt_w
            .write_all_flush(buf.as_ref())
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)
    }
}
