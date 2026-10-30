/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ahash::AHashMap;
use arcstr::ArcStr;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use g3_io_ext::{ArcLimitedWriterStats, LimitedWriter};
use g3_types::auth::UserAuthError;
use g3_types::net::{HttpAuth, HttpProxySubProtocol};

use super::protocol::{HttpClientReader, HttpClientWriter, HttpProxyRequest};
use super::{
    CommonTaskContext, FtpOverHttpTask, HttpProxyCltWrapperStats, HttpProxyConnectTask,
    HttpProxyForwardTask, HttpProxyPipelineStats, HttpProxyUntrustedTask,
};
use crate::audit::AuditContext;
use crate::auth::{UserContext, UserGroup, UserRequestStats};
use crate::config::server::ServerConfig;
use crate::escape::EgressPathSelection;
use crate::module::http_forward::{BoxHttpForwardContext, HttpProxyClientResponse};
use crate::serve::{ServerStats, ServerTaskNotes};

/// 本连接上某个已认证用户的使用统计（用于连接复用计数与存活连接数增减）。
struct UserData {
    req_stats: Arc<UserRequestStats>,
    // 若该用户请求落在站点上，站点级别的统计同样需要增减
    site_req_stats: Option<Arc<UserRequestStats>>,
    // 该用户在本条（复用）连接上已发出的请求数
    count: usize,
}

/// 连接关闭时回收该用户占用的一层（http）存活连接计数。
impl Drop for UserData {
    fn drop(&mut self) {
        self.req_stats.l7_conn_alive.dec_http();
        if let Some(site_req_stats) = &self.site_req_stats {
            site_req_stats.l7_conn_alive.dec_http();
        }
    }
}

/// 本条连接上各类请求的计数，用于审计与诊断（按用户/匿名/认证失败等分类）。
struct RequestCount {
    passed_users: AHashMap<ArcStr, UserData>,
    anonymous: usize,
    auth_failed: usize,
    invalid: usize,
    // 连续认证失败次数：>1 时直接断开连接，避免暴力尝试
    consequent_auth_failed: usize,
}

/// 初始化为空计数。
impl Default for RequestCount {
    fn default() -> Self {
        RequestCount {
            passed_users: AHashMap::new(),
            anonymous: 0,
            auth_failed: 0,
            invalid: 0,
            consequent_auth_failed: 0,
        }
    }
}

/// 流水线写端任务：从 reader 投递的队列中取出请求，做认证与路由，
/// 为每个请求分发具体子任务（forward / connect / ftp-over-http / untrusted），
/// 并把响应写回客户端 socket。
pub(crate) struct HttpProxyPipelineWriterTask<CDR, CDW> {
    ctx: Arc<CommonTaskContext>,
    audit_ctx: AuditContext,
    // None 表示服务器未配置用户组，所有请求按匿名处理
    user_group: Option<Arc<UserGroup>>,
    // 来自 reader 任务的消息队列：Ok 为待处理请求，Err 为需直接回复客户端的错误响应
    task_queue: mpsc::Receiver<Result<HttpProxyRequest<CDR>, HttpProxyClientResponse>>,
    // 客户端写端；分发子任务期间会被 take() 走，归还前本任务无法写回其他响应
    stream_writer: Option<HttpClientWriter<CDW>>,
    forward_context: BoxHttpForwardContext,
    wrapper_stats: ArcLimitedWriterStats,
    pipeline_stats: Arc<HttpProxyPipelineStats>,
    req_count: RequestCount,
}

/// 主循环每一步的走向：继续处理下一个请求，或结束整条连接。
enum LoopAction {
    Continue,
    Break,
}

/// 写端任务的构建与各子任务分发逻辑。
/// `CDR` 为客户端读半部（随请求体移交），`CDW` 为客户端写半部。
impl<CDR, CDW> HttpProxyPipelineWriterTask<CDR, CDW>
where
    CDR: AsyncRead + Send + Sync + Unpin + 'static,
    CDW: AsyncWrite + Send + Sync + Unpin + 'static,
{
    /// 创建写端任务：用南向限速的 [LimitedWriter] 包裹写半部，并准备转发上下文。
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        audit_ctx: AuditContext,
        user_group: Option<Arc<UserGroup>>,
        task_receiver: mpsc::Receiver<Result<HttpProxyRequest<CDR>, HttpProxyClientResponse>>,
        write_half: CDW,
        pipeline_stats: &Arc<HttpProxyPipelineStats>,
    ) -> Self {
        let forward_context = ctx
            .escaper
            .new_http_forward_context(Arc::clone(&ctx.escaper));
        let clt_w_stats = HttpProxyCltWrapperStats::new_for_writer(&ctx.server_stats);
        let limit_config = &ctx.server_config.tcp_sock_speed_limit;
        let clt_w = LimitedWriter::local_limited(
            write_half,
            limit_config.shift_millis,
            limit_config.max_south,
            Arc::clone(&clt_w_stats),
        );
        HttpProxyPipelineWriterTask {
            ctx: Arc::clone(ctx),
            audit_ctx,
            user_group,
            task_queue: task_receiver,
            stream_writer: Some(clt_w),
            forward_context,
            wrapper_stats: clt_w_stats,
            pipeline_stats: Arc::clone(pipeline_stats),
            req_count: RequestCount::default(),
        }
    }

    /// 对单个请求做代理认证：无认证头时走匿名，Basic 认证时校验用户名/密码
    /// （用户名可能带参数后缀，先还原出真实用户名）。成功后还会检查客户端 IP
    /// 与站点归属，并维护本连接的用户复用计数。返回 Ok(None) 表示服务器不要求认证。
    async fn do_auth(
        &mut self,
        req: &HttpProxyRequest<CDR>,
    ) -> Result<Option<UserContext>, UserAuthError> {
        if let Some(user_group) = &self.user_group {
            let mut user_ctx = match &req.inner.auth_info {
                HttpAuth::None => user_group
                    .get_anonymous_user()
                    .map(|(user, user_type)| {
                        UserContext::new(
                            None,
                            user,
                            user_type,
                            self.ctx.server_config.name(),
                            self.ctx.server_stats.share_extra_tags(),
                        )
                    })
                    .ok_or(UserAuthError::NoUserSupplied)?,
                HttpAuth::Basic(v) => {
                    let username = v.username.as_original();
                    let username = self
                        .ctx
                        .server_config
                        .username_params
                        .as_ref()
                        .map(|c| c.real_username(username))
                        .unwrap_or(username);
                    user_group
                        .check_user_with_password(
                            username,
                            &v.password,
                            self.ctx.server_config.name(),
                            self.ctx.server_stats.share_extra_tags(),
                        )
                        .await?
                }
            };
            user_ctx.check_client_addr(self.ctx.client_addr())?;

            user_ctx.check_in_site(
                self.ctx.server_config.name(),
                self.ctx.server_stats.share_extra_tags(),
                &req.upstream,
            );
            self.req_count
                .passed_users
                .entry(user_ctx.user_name().clone())
                .and_modify(|e| {
                    // 本连接上同一用户的后续请求：只累加复用计数
                    user_ctx.mark_reused_client_connection();
                    e.count += 1;
                })
                .or_insert_with(|| {
                    // 该用户在本连接上的首个请求：计入连接总数与存活数
                    let req_stats = user_ctx.req_stats().clone();
                    req_stats.conn_total.add_http();
                    req_stats.l7_conn_alive.inc_http();
                    let site_req_stats = if let Some(site_req_stats) = user_ctx.site_req_stats() {
                        site_req_stats.conn_total.add_http();
                        site_req_stats.l7_conn_alive.inc_http();
                        Some(Arc::clone(site_req_stats))
                    } else {
                        None
                    };
                    UserData {
                        req_stats,
                        site_req_stats,
                        count: 1,
                    }
                });
            Ok(Some(user_ctx))
        } else {
            self.req_count.anonymous += 1;
            Ok(None)
        }
    }

    /// 写端主循环：逐个取出 reader 投递的消息并处理，直到队列耗尽或需要断开连接。
    pub(crate) async fn into_running(mut self) {
        loop {
            let res = match self.task_queue.recv().await {
                Some(Ok(req)) => {
                    // 先认证再分发；认证失败的请求走 untrusted 任务（可能仍代理认证错误响应）
                    let res = match self.do_auth(&req).await {
                        Ok(user_ctx) => {
                            self.req_count.consequent_auth_failed = 0;
                            self.run(req, user_ctx).await
                        }
                        Err(e) => {
                            self.req_count.consequent_auth_failed += 1;
                            self.req_count.auth_failed += 1;
                            self.run_untrusted(req, e.blocked_delay()).await
                        }
                    };
                    // reader 以存活任务数判断连接是否值得继续保活，这里必须及时递减
                    self.pipeline_stats.del_task();
                    res
                }
                Some(Err(rsp)) => {
                    // the response will always be `Connection: Close`
                    // reader 解析出错，直接回错误响应并终止本连接
                    self.req_count.invalid += 1;
                    if !self.ctx.server_config.no_early_error_reply
                        && let Some(stream_w) = &mut self.stream_writer
                    {
                        let _ = rsp.reply_err_to_request(stream_w).await;
                    }

                    self.notify_reader_to_close();
                    LoopAction::Break
                }
                None => LoopAction::Break,
            };
            match res {
                LoopAction::Continue => {}
                LoopAction::Break => {
                    break;
                }
            }
        }
    }

    /// 解析请求中指定的出口（egress）路径选择：
    /// 1) 自定义头部里的数字编号；2) Basic 用户名参数中编码的下一跳代理地址。
    /// 头部会被移除（end-to-end 头，不转发给上游）。参数非法时返回 Err。
    fn get_egress_path_selection(
        &self,
        req: &mut HttpProxyRequest<CDR>,
    ) -> Result<Option<EgressPathSelection>, ()> {
        let mut egress_path = EgressPathSelection::default();

        if let Some(header) = &self.ctx.server_config.egress_path_selection_header {
            // check and remove the custom header
            if let Some(value) = req.inner.end_to_end_headers.remove(header) {
                match usize::from_str(value.to_str()) {
                    Ok(id) => {
                        egress_path.set_number_id(self.ctx.server_config.escaper().clone(), id)
                    }
                    Err(e) => {
                        debug!("invalid egress path number id value in header {header}: {e}");
                        return Err(());
                    }
                }
            }
        }

        // Optional: compute username-param-derived escaper address and store override
        if let Some(name_params) = &self.ctx.server_config.username_params
            && let HttpAuth::Basic(v) = &req.inner.auth_info
        {
            match name_params.parse_egress_upstream_http(v.username.as_original()) {
                Ok(Some(ups)) => {
                    debug!(
                        "[{}] http username params -> next proxy {}",
                        self.ctx.server_config.name(),
                        ups.addr
                    );
                    egress_path.set_upstream(self.ctx.escaper.name().clone(), ups);
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("failed to get upstream addr from username: {e}");
                    return Err(());
                }
            }
        }

        if egress_path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(egress_path))
        }
    }

    /// 分发认证通过的请求：先做出口路径选择，再根据客户端侧子协议
    /// （CONNECT / HTTP 转发 / HTTPS 转发 / FTP-over-HTTP）创建对应子任务执行。
    /// 执行结束后负责把写端/读端归还给各自的主人（见 run_* 系列方法）。
    async fn run(
        &mut self,
        mut req: HttpProxyRequest<CDR>,
        user_ctx: Option<UserContext>,
    ) -> LoopAction {
        let Ok(path_selection) = self.get_egress_path_selection(&mut req) else {
            self.req_count.invalid += 1;
            // Bad request: unsupported param combo or invalid params
            if let Some(stream_w) = &mut self.stream_writer {
                let rsp = HttpProxyClientResponse::bad_request(req.inner.version);
                let _ = rsp.reply_err_to_request(stream_w).await;
            }
            self.notify_reader_to_close();
            return LoopAction::Break;
        };

        let task_notes = ServerTaskNotes::with_path_selection(
            self.ctx.cc_info.clone(),
            user_ctx,
            req.time_accepted.elapsed(),
            path_selection,
        );

        let mut audit_ctx = self.audit_ctx.clone();
        // 查询最终出口(escaper)对该请求的能力：若其本身就能转发 https/ftp 流量，
        // 则改写为 HttpForward 按普通 HTTP 转发处理，否则保留原子协议走专用路径
        let remote_protocol = match req.client_protocol {
            HttpProxySubProtocol::TcpConnect => HttpProxySubProtocol::TcpConnect,
            HttpProxySubProtocol::HttpForward => {
                let _ = self
                    .forward_context
                    .check_in_final_escaper(&task_notes, &req.upstream, &mut audit_ctx)
                    .await;
                HttpProxySubProtocol::HttpForward
            }
            HttpProxySubProtocol::HttpsForward => {
                let forward_capability = self
                    .forward_context
                    .check_in_final_escaper(&task_notes, &req.upstream, &mut audit_ctx)
                    .await;
                if forward_capability.forward_https() {
                    HttpProxySubProtocol::HttpForward
                } else {
                    HttpProxySubProtocol::HttpsForward
                }
            }
            HttpProxySubProtocol::FtpOverHttp => {
                let forward_capability = self
                    .forward_context
                    .check_in_final_escaper(&task_notes, &req.upstream, &mut audit_ctx)
                    .await;
                if forward_capability.forward_ftp(&req.inner.method) {
                    HttpProxySubProtocol::HttpForward
                } else {
                    HttpProxySubProtocol::FtpOverHttp
                }
            }
        };

        match remote_protocol {
            HttpProxySubProtocol::TcpConnect => {
                // CONNECT：写端与读端（随请求移交）一起交给 connect 子任务
                if let (Some(mut stream_w), Some(stream_r)) =
                    (self.stream_writer.take(), req.body_reader.take())
                {
                    let mut connect_task =
                        HttpProxyConnectTask::new(&self.ctx, audit_ctx, &req, task_notes);
                    connect_task.connect_to_upstream(&mut stream_w).await;
                    if connect_task.back_to_http() {
                        // 隧道最终回到 HTTP 语义：把写端收回，并把读端经 channel 归还 reader
                        // reopen write end
                        self.stream_writer = Some(stream_w);
                        // reopen read end
                        if req.stream_sender.try_send(Some(stream_r)).is_err() {
                            // read end has closed, impossible as reader should be waiting this channel
                            LoopAction::Break
                        } else {
                            LoopAction::Continue
                        }
                    } else {
                        // 纯隧道转发：读端不再归还（None 通知 reader 停止），
                        // connect 任务接管整条连接直到双向结束，本任务退出
                        // close read end
                        let _ = req.stream_sender.try_send(None);
                        connect_task.into_running(stream_r.into_inner(), stream_w);
                        LoopAction::Break
                    }
                } else {
                    unreachable!()
                }
            }
            HttpProxySubProtocol::HttpForward | HttpProxySubProtocol::HttpsForward => {
                if let Some(mut stream_w) = self.stream_writer.take() {
                    match self
                        .run_forward(&mut stream_w, req, task_notes, audit_ctx, remote_protocol)
                        .await
                    {
                        LoopAction::Continue => {
                            self.reset_client_writer(stream_w);
                            LoopAction::Continue
                        }
                        LoopAction::Break => LoopAction::Break,
                    }
                } else {
                    unreachable!()
                }
            }
            HttpProxySubProtocol::FtpOverHttp => {
                if let (Some(mut stream_w), Some(stream_r)) =
                    (self.stream_writer.take(), req.body_reader.take())
                {
                    match self
                        .run_ftp_over_http(&mut stream_w, stream_r, req, task_notes)
                        .await
                    {
                        LoopAction::Continue => {
                            self.reset_client_writer(stream_w);
                            LoopAction::Continue
                        }
                        LoopAction::Break => LoopAction::Break,
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }

    /// 子任务用完后收回写端：重置统计归属与本地限速，恢复到可继续写回下一条响应。
    fn reset_client_writer(&mut self, mut stream_w: HttpClientWriter<CDW>) {
        stream_w.reset_stats(Arc::clone(&self.wrapper_stats));
        let limit_config = &self.ctx.server_config.tcp_sock_speed_limit;
        stream_w.reset_local_limit(limit_config.shift_millis, limit_config.max_south);
        self.stream_writer = Some(stream_w);
    }

    /// 处理认证失败的请求：按配置回 403/407 或直接丢弃，必要时先做延时（反爆破）。
    /// 若只是普通认证失败（非封禁、首次失败），交给 [HttpProxyUntrustedTask]
    /// 回带 Proxy-Authenticate 质询的响应并尽量维持连接，让客户端可以重新带认证重试。
    async fn run_untrusted(
        &mut self,
        mut req: HttpProxyRequest<CDR>,
        blocked_delay: Option<Duration>,
    ) -> LoopAction {
        if self.ctx.server_config.no_early_error_reply {
            // 配置为不提前回错误：最多延时后直接断开，不发任何响应
            if let Some(duration) = blocked_delay {
                self.ctx.server_stats.forbidden.add_user_blocked();

                // delay some time before close
                tokio::time::sleep(duration).await;
            } else {
                self.ctx.server_stats.forbidden.add_auth_failed();
            }

            self.notify_reader_to_close();
            LoopAction::Break
        } else if let Some(duration) = blocked_delay {
            self.ctx.server_stats.forbidden.add_user_blocked();

            // delay some time before reply
            tokio::time::sleep(duration).await;

            // user is blocked, always close the connection
            if let Some(clt_w) = &mut self.stream_writer {
                let rsp = HttpProxyClientResponse::forbidden(req.inner.version);
                // no custom header is set
                let _ = rsp.reply_err_to_request(clt_w).await;
            }

            self.notify_reader_to_close();
            LoopAction::Break
        } else if self.req_count.consequent_auth_failed > 1 {
            // if the previous request has already failed, close the connection
            // 连续第二次失败：回 407 质询后立即断开
            self.ctx.server_stats.forbidden.add_auth_failed();

            if let Some(clt_w) = &mut self.stream_writer {
                // no custom header is set
                let _ = HttpProxyClientResponse::reply_proxy_auth_err(
                    req.inner.version,
                    clt_w,
                    &self.ctx.server_config.auth_realm,
                    true,
                )
                .await;
            }

            self.notify_reader_to_close();
            LoopAction::Break
        } else if let Some(clt_w) = &mut self.stream_writer {
            // 首次认证失败：回 407 质询，连接可保留等待客户端重试
            self.ctx.server_stats.forbidden.add_auth_failed();

            match req.body_reader.take() {
                Some(stream_r) => {
                    // 请求带 body：untrusted 任务需消费掉 body，之后视情况归还/关闭读端
                    let mut untrusted_task = HttpProxyUntrustedTask::new(&self.ctx, &req);
                    let mut clt_r = Some(stream_r);
                    untrusted_task.run(&mut clt_r, clt_w).await;
                    if untrusted_task.should_close() {
                        // close read end
                        let _ = req.stream_sender.try_send(None);
                        LoopAction::Break
                    } else {
                        // reopen read end
                        if req.stream_sender.try_send(clt_r).is_err() {
                            // read end has closed, impossible as reader should be waiting this channel
                            LoopAction::Break
                        } else {
                            LoopAction::Continue
                        }
                    }
                }
                None => {
                    let mut untrusted_task = HttpProxyUntrustedTask::new(&self.ctx, &req);
                    let mut clt_r = None;
                    untrusted_task.run::<CDR, CDW>(&mut clt_r, clt_w).await;
                    if untrusted_task.should_close() {
                        // i.e. ups_s io error may cause response data to be corrupted
                        self.notify_reader_to_close();
                        LoopAction::Break
                    } else {
                        LoopAction::Continue
                    }
                }
            }
        } else {
            self.ctx.server_stats.forbidden.add_auth_failed();

            // should be impossible
            self.notify_reader_to_close();
            LoopAction::Break
        }
    }

    /// 执行 HTTP/HTTPS 转发子任务，把上游响应写回客户端。
    /// 返回 Continue 时写端已交还（由调用方 reset），读端按需要通过 channel 归还。
    async fn run_forward(
        &mut self,
        clt_w: &mut HttpClientWriter<CDW>,
        mut req: HttpProxyRequest<CDR>,
        task_notes: ServerTaskNotes,
        audit_ctx: AuditContext,
        remote_protocol: HttpProxySubProtocol,
    ) -> LoopAction {
        // 记录是否为 https 流量；按需去掉 Host 头里显式的默认端口
        let is_https = match remote_protocol {
            HttpProxySubProtocol::HttpForward => {
                if self.ctx.server_config.drop_default_port_in_host && req.upstream.port() == 80 {
                    req.drop_default_port_in_host();
                }
                false
            }
            HttpProxySubProtocol::HttpsForward => {
                if self.ctx.server_config.drop_default_port_in_host && req.upstream.port() == 443 {
                    req.drop_default_port_in_host();
                }
                true
            }
            _ => unreachable!(),
        };

        match req.body_reader.take() {
            Some(stream_r) => {
                // we have a body, or we need to close the connection
                // we may need to send stream_r back if we have a body
                let mut forward_task =
                    HttpProxyForwardTask::new(&self.ctx, audit_ctx, &req, is_https, task_notes);
                let mut clt_r = Some(stream_r);
                forward_task
                    .run(&mut clt_r, clt_w, &mut self.forward_context)
                    .await;
                if forward_task.should_close() {
                    // close read end
                    let _ = req.stream_sender.try_send(None);
                    LoopAction::Break
                } else {
                    // reopen read end
                    if req.stream_sender.try_send(clt_r).is_err() {
                        // read end has closed, impossible as reader should be waiting this channel
                        LoopAction::Break
                    } else {
                        LoopAction::Continue
                    }
                }
            }
            None => {
                // no http body, and the connection is expected to keep alive from the client side
                let mut forward_task =
                    HttpProxyForwardTask::new(&self.ctx, audit_ctx, &req, is_https, task_notes);
                let mut clt_r = None;
                forward_task
                    .run::<CDR, CDW>(&mut clt_r, clt_w, &mut self.forward_context)
                    .await;
                if forward_task.should_close() {
                    // i.e. ups_s io error may cause response data to be corrupted
                    self.notify_reader_to_close();
                    LoopAction::Break
                } else {
                    LoopAction::Continue
                }
            }
        }
    }

    /// 执行 FTP-over-HTTP 子任务：客户端用 HTTP 请求承载 FTP 操作，
    /// 读写端成对交给子任务，结束后视 should_close 决定归还读端还是断开。
    async fn run_ftp_over_http(
        &mut self,
        clt_w: &mut HttpClientWriter<CDW>,
        mut clt_r: HttpClientReader<CDR>,
        req: HttpProxyRequest<CDR>,
        task_notes: ServerTaskNotes,
    ) -> LoopAction {
        let mut ftp_task = FtpOverHttpTask::new(&self.ctx, &req, task_notes);
        ftp_task.run(&mut clt_r, clt_w).await;
        if ftp_task.should_close() {
            // close read end
            let _ = req.stream_sender.try_send(None);
            LoopAction::Break
        } else {
            // reopen read end
            if req.stream_sender.try_send(Some(clt_r)).is_err() {
                // read end has closed, impossible as reader should be waiting this channel
                LoopAction::Break
            } else {
                LoopAction::Continue
            }
        }
    }

    /// notify reader to close while it's not closed and not in waiting writer status.
    /// always use the req.stream_sender.send(None) when possible.
    /// 兜底关闭手段：reader 此刻不在等待归还读端的状态时，通过关闭接收队列
    /// 让 reader 的 `task_queue.closed()` 分支感知并退出（能走 stream_sender 时优先用那个）。
    fn notify_reader_to_close(&mut self) {
        self.task_queue.close(); // may be deleted as the writer will be dropped later
    }
}
