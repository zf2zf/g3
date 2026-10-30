/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use http::Method;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_ftp_client::{
    FtpClient, FtpFileFacts, FtpFileListError, FtpFileRetrieveStartError, FtpFileStatError,
    FtpFileStoreStartError, FtpSessionOpenError,
};
use g3_http::server::HttpProxyClientRequest;
use g3_http::{HttpBodyDecodeReader, HttpBodyReader, HttpBodyType};
use g3_io_ext::{GlobalLimitGroup, SizedReader, StreamCopy, StreamCopyError};
use g3_types::acl::AclAction;
use g3_types::net::ProxyRequestType;

use super::protocol::{HttpClientReader, HttpClientWriter, HttpProxyRequest};
use super::{
    CommonTaskContext, FtpOverHttpTaskCltWrapperStats, FtpOverHttpTaskStats,
    HttpProxyFtpConnectionProvider, ListWriter,
};
use crate::config::server::ServerConfig;
use crate::log::task::ftp_over_http::TaskLogForFtpOverHttp;
use crate::module::ftp_over_http::{BoxFtpRemoteConnection, FtpOverHttpTaskNotes, FtpRequestPath};
use crate::module::http_forward::HttpProxyClientResponse;
use crate::module::tcp_connect::{TcpConnectError, TcpConnectTaskConf};
use crate::serve::http_proxy::FtpOverHttpTaskAliveGuard;
use crate::serve::{
    ServerStats, ServerTaskError, ServerTaskForbiddenError, ServerTaskNotes, ServerTaskResult,
    ServerTaskStage,
};

/// 本模块使用的 FTP 客户端实例类型：连接由 tcp_connect 隧道提供者创建，
/// 连接类型为可经由 HTTP 隧道转发的 BoxFtpRemoteConnection。
type HttpProxyFtpClient = FtpClient<
    HttpProxyFtpConnectionProvider,
    BoxFtpRemoteConnection,
    TcpConnectError,
    ServerTaskNotes,
>;

/// 单个 FTP-over-HTTP 请求对应的服务端任务。
///
/// 把客户端的 HTTP 方法映射到 FTP 操作：GET=列目录/下载文件、PUT=上传文件、
/// DELETE=删除文件/目录。FTP 控制命令的解析与 PORT/PASV/EPSV 地址改写由底层
/// g3-ftp-client 库完成，本任务负责 HTTP 语义（状态码、分块编码、Range 等）
/// 到 FTP 语义的转换，以及任务级的统计、日志与 ACL 检查。
pub(crate) struct FtpOverHttpTask<'a> {
    ctx: Arc<CommonTaskContext>, // 服务器级共享上下文（配置、escaper、统计等）
    req: &'a HttpProxyClientRequest, // 解析出的客户端 HTTP 请求
    should_close: bool,          // 本次响应后是否需要关闭客户端连接
    task_notes: ServerTaskNotes, // 通用任务备注（阶段、耗时、用户上下文）
    ftp_notes: FtpOverHttpTaskNotes, // FTP 专属备注（URL 路径、用户名密码、控制/数据连接 TCP 备注）
    task_stats: Arc<FtpOverHttpTaskStats>, // 本任务字节流量统计
    max_idle_count: usize,       // 允许的最大连续空闲周期数（超时管理）
    started: bool,               // pre_start 是否已执行（保证 drop 时正确 post_stop）
    _alive_guard: Option<FtpOverHttpTaskAliveGuard>, // 存活计数守卫，drop 时自动减一
}

/// 任务对象销毁时收尾：若已启动则执行 post_stop，归还用户并发额度并递减存活统计。
impl Drop for FtpOverHttpTask<'_> {
    fn drop(&mut self) {
        if self.started {
            self.post_stop();
            self.started = false;
        }
    }
}

impl<'a> FtpOverHttpTask<'a> {
    /// 从已解析的 HTTP 代理请求创建任务：提取 FTP 路径/账号信息（ftp_notes），
    /// 并按用户配置或服务器配置确定最大空闲周期数。
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        req: &'a HttpProxyRequest<impl AsyncRead>,
        task_notes: ServerTaskNotes,
    ) -> Self {
        let ftp_notes = FtpOverHttpTaskNotes::new(
            &req.inner,
            &req.upstream,
            ctx.server_config.log_uri_max_chars,
        );
        // 空闲上限优先取用户配置，否则取服务器配置
        let max_idle_count = task_notes
            .user_ctx()
            .and_then(|c| c.user().task_max_idle_count())
            .unwrap_or(ctx.server_config.task_idle_max_count);
        FtpOverHttpTask {
            ctx: Arc::clone(ctx),
            req: &req.inner,
            should_close: !req.inner.keep_alive(),
            task_notes,
            ftp_notes,
            task_stats: Arc::new(FtpOverHttpTaskStats::default()),
            max_idle_count,
            started: false,
            _alive_guard: None,
        }
    }

    /// 响应发出后是否需要关闭客户端连接（供上层 HTTP 会话决定是否复用连接）
    #[inline]
    pub(crate) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 组装任务日志上下文：汇总请求备注与各通道（HTTP 客户端、FTP 控制/数据）的字节数；
    /// 服务器未配置任务日志时返回 None
    fn get_log_context(&self) -> Option<TaskLogForFtpOverHttp<'_>> {
        let Some(logger) = &self.ctx.task_logger else {
            return None;
        };

        let http_user_agent = self
            .req
            .end_to_end_headers
            .get(http::header::USER_AGENT)
            .map(|v| v.to_str());
        Some(TaskLogForFtpOverHttp {
            logger,
            task_notes: &self.task_notes,
            ftp_notes: &self.ftp_notes,
            http_user_agent,
            client_rd_bytes: self.task_stats.http_client.read.get_bytes(),
            client_wr_bytes: self.task_stats.http_client.write.get_bytes(),
            ftp_c_rd_bytes: self.task_stats.ftp_server.control_read.get_bytes(),
            ftp_c_wr_bytes: self.task_stats.ftp_server.control_write.get_bytes(),
            ftp_d_rd_bytes: self.task_stats.ftp_server.transfer_read.get_bytes(),
            ftp_d_wr_bytes: self.task_stats.ftp_server.transfer_write.get_bytes(),
        })
    }

    /// 任务对外入口：登记启动、执行 FTP 流程、统一记录最终日志。
    /// 错误不外抛，只体现在日志与 should_close 状态里。
    pub(crate) async fn run<CDR, CDW>(
        &mut self,
        clt_r: &mut HttpClientReader<CDR>,
        clt_w: &mut HttpClientWriter<CDW>,
    ) where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        self.pre_start();
        // run_ftp 的失败原因已经回复给客户端或被记录，这里仅归一为 Finished 用于打日志
        let e = match self.run_ftp(clt_r, clt_w).await {
            Ok(()) => ServerTaskError::Finished,
            Err(e) => e,
        };
        if let Some(log_ctx) = self.get_log_context() {
            log_ctx.log(e);
        }
    }

    /// 任务启动登记：递增服务器存活任务计数（持有 guard，drop 时自动递减）、
    /// 累加用户级请求统计，并按配置在创建时立即输出一条日志
    fn pre_start(&mut self) {
        self._alive_guard = Some(self.ctx.server_stats.add_ftp_over_http_task());

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| {
                s.req_total.add_ftp_over_http();
                s.req_alive.add_ftp_over_http();
            });
        }

        if self.ctx.server_config.flush_task_log_on_created
            && let Some(log_ctx) = self.get_log_context()
        {
            log_ctx.log_created();
        }

        self.started = true;
    }

    /// 任务结束收尾：递减用户级存活请求统计，并释放并发许可（permit，
    /// 与 run_ftp 中 acquire_request_semaphore 对应）。
    fn post_stop(&mut self) {
        if let Some(user_ctx) = self.task_notes.user_ctx() {
            user_ctx.foreach_req_stats(|s| s.req_alive.del_ftp_over_http());

            if let Some(user_req_alive_permit) = self.task_notes.user_req_alive_permit.take() {
                drop(user_req_alive_permit);
            }
        }
    }

    /// 在本地生成的响应中带上 ftp_over_http 模块自定义头（供客户端调试/追踪）
    fn enable_custom_header_for_local_reply(&self, rsp: &mut HttpProxyClientResponse) {
        self.ctx
            .set_custom_header_for_local_reply(&self.ftp_notes.control_tcp_notes, rsp);
    }

    /// 回复 429：用户触发限速或并发已满，并强制关闭连接
    async fn reply_too_many_requests<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::too_many_requests(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 回复 403：被 ACL 规则禁止
    async fn reply_forbidden<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::forbidden(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 回复 405：FTP-over-HTTP 协议被用户 ACL 禁止
    async fn reply_banned_protocol<W>(&mut self, clt_w: &mut W)
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::method_not_allowed(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
    }

    /// 处理服务器级目标 ACL 判定结果：Forbid 时累加禁止统计（服务器 + 用户级）、
    /// 回复 403 并返回错误；Permit 则放行。
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

    /// 处理用户级目标（upstream）ACL 判定结果：Forbid 时回复 403 并返回错误
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

    /// 处理用户级协议 ACL 判定结果：Forbid 时回复 405 并返回错误
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

    /// 为客户端 HTTP 读写流装配限速器与统计回调：
    /// - 请求头字节先计入任务/用户统计；
    /// - 写出方向保留服务器级全局限速，读写方向叠加用户级全局限速；
    /// - 用户套接字限速与服务器配置不同时，取两者较小值作为本连接的本地限速；
    /// - 用 FtpOverHttpTaskCltWrapperStats 替换默认的裸统计回调，实现三级（任务/服务器/用户）联动计数。
    fn setup_clt_limit_and_stats<CDR, CDW>(
        &mut self,
        clt_r: &mut HttpClientReader<CDR>,
        clt_w: &mut HttpClientWriter<CDW>,
    ) where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Unpin,
    {
        let origin_header_size = self.req.origin_header_size() as u64;
        self.task_stats
            .http_client
            .read
            .add_bytes(origin_header_size);

        clt_w.retain_global_limiter_by_group(GlobalLimitGroup::Server);

        let mut wrapper_stats =
            FtpOverHttpTaskCltWrapperStats::new(&self.ctx.server_stats, &self.task_stats);
        let limit_config = if let Some(user_ctx) = self.task_notes.user_ctx() {
            let user_io_stats = user_ctx.fetch_traffic_stats(
                self.ctx.server_config.name(),
                self.ctx.server_stats.share_extra_tags(),
            );
            for s in &user_io_stats {
                s.io.ftp_over_http.add_in_bytes(origin_header_size);
            }
            wrapper_stats.push_user_io_stats(user_io_stats);

            let user = user_ctx.user();
            if let Some(limiter) = user.tcp_all_upload_speed_limit() {
                limiter.try_consume(origin_header_size);
                clt_r.add_global_limiter(limiter.clone());
            }
            if let Some(limiter) = user.tcp_all_download_speed_limit() {
                clt_w.add_global_limiter(limiter.clone());
            }

            let user_config = user_ctx.user_config();
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

        let wrapper_stats = Arc::new(wrapper_stats);

        clt_w.reset_stats(wrapper_stats.clone());
        clt_r.reset_buffer_stats(wrapper_stats);
        if let Some(limit_config) = &limit_config {
            clt_w.reset_local_limit(limit_config.shift_millis, limit_config.max_south);
            clt_r.reset_local_limit(limit_config.shift_millis, limit_config.max_north);
        }
    }

    /// FTP-over-HTTP 主流程：
    /// 1. 认证用户存在时依次做限速检查、并发许可获取、协议/目标 ACL 检查（用户级先、服务器级后）；
    /// 2. 设置客户端 socket 选项并装配限速与统计；
    /// 3. 按 HTTP 方法分发：DELETE=删除、GET=列目录或下载、PUT=上传（支持 fixed-length /
    ///    read-until-end / chunked 三种请求体），其余方法返回 501。
    async fn run_ftp<CDR, CDW>(
        &mut self,
        clt_r: &mut HttpClientReader<CDR>,
        clt_w: &mut HttpClientWriter<CDW>,
    ) -> ServerTaskResult<()>
    where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Send + Unpin,
    {
        // TODO fetch ftp custom upstream keepalive config
        let tcp_client_misc_opts;

        if let Some(user_ctx) = self.task_notes.user_ctx() {
            let user_ctx = user_ctx.clone();

            // 用户请求速率限制：超限回复 429
            if user_ctx.check_rate_limit().is_err() {
                self.reply_too_many_requests(clt_w).await;
                return Err(ServerTaskError::ForbiddenByRule(
                    ServerTaskForbiddenError::RateLimited,
                ));
            }

            // 获取并发存活许可（限制同时进行的任务数）；失败回复 429。
            // permit 存入 task_notes，在 post_stop/drop 时释放。
            match user_ctx.acquire_request_semaphore() {
                Ok(permit) => self.task_notes.user_req_alive_permit = Some(permit),
                Err(_) => {
                    self.reply_too_many_requests(clt_w).await;
                    return Err(ServerTaskError::ForbiddenByRule(
                        ServerTaskForbiddenError::FullyLoaded,
                    ));
                }
            }

            // 用户级协议 ACL：是否允许 FTP-over-HTTP
            let action = user_ctx.check_proxy_request(ProxyRequestType::FtpOverHttp);
            self.handle_user_protocol_acl_action(action, clt_w).await?;

            // 用户级目标 ACL：是否允许访问该上游 FTP 服务器
            let action = user_ctx.check_upstream(self.ftp_notes.upstream());
            self.handle_user_upstream_acl_action(action, clt_w).await?;

            // server level dst host/port acl rules
            // 服务器级目标 ACL（兜底规则）
            let action = self.ctx.check_upstream(self.ftp_notes.upstream());
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            // TODO merge user custom upstream keepalive config
            // 合并用户与服务器两级的 TCP socket 选项（TCP keepalive 等）
            tcp_client_misc_opts = user_ctx
                .user_config()
                .tcp_client_misc_opts(&self.ctx.server_config.tcp_misc_opts);
        } else {
            // 无用户上下文（服务器未启用认证）：只走服务器级 ACL
            // server level dst host/port acl rules
            let action = self.ctx.check_upstream(self.ftp_notes.upstream());
            self.handle_server_upstream_acl_action(action, clt_w)
                .await?;

            tcp_client_misc_opts = Cow::Borrowed(&self.ctx.server_config.tcp_misc_opts);
        }

        // set client side socket options
        // 注意：这里作用于客户端连接（HTTP 隧道）的 socket
        self.ctx
            .cc_info
            .tcp_sock_set_raw_opts(&tcp_client_misc_opts, true)
            .map_err(|_| {
                ServerTaskError::InternalServerError("failed to set client socket options")
            })?;

        self.setup_clt_limit_and_stats(clt_r, clt_w);

        match self.req.method {
            Method::DELETE => {
                if self.req.body_type().is_some() {
                    return self
                        .reply_bad_request(clt_w, "http body is not allowed in ftp del request")
                        .await;
                }
                // 建连（含 FTP 握手）-> 登录（USER/PASS）-> 删除目标路径
                let mut ftp_client = self.setup_ftp_client(clt_w, false).await?;
                self.login(&mut ftp_client, clt_w).await?;
                self.delete_path(&mut ftp_client, clt_w).await
            }
            Method::GET => {
                if self.req.body_type().is_some() {
                    return self
                        .reply_bad_request(clt_w, "http body is not allowed in ftp get request")
                        .await;
                }
                // 建连 -> 登录 -> 自动判定是目录（列表）还是文件（下载）
                let mut ftp_client = self.setup_ftp_client(clt_w, false).await?;
                self.login(&mut ftp_client, clt_w).await?;
                self.list_or_download(&mut ftp_client, clt_w).await
            }
            Method::PUT => {
                if self
                    .req
                    .end_to_end_headers
                    .contains_key(http::header::RANGE)
                {
                    return self
                        .reply_bad_request(clt_w, "Content-Range is not allowed in PUT request")
                        .await;
                }

                if let Some(body_type) = self.req.body_type() {
                    // 建立控制连接并完成 FTP 握手；上传的数据连接在 store_file_start 阶段才创建
                    let mut ftp_client = self.setup_ftp_client(clt_w, false).await?;
                    self.login(&mut ftp_client, clt_w).await?;

                    // 按请求体形态选择 reader 适配为纯字节流，再灌入 FTP 数据连接
                    match body_type {
                        HttpBodyType::ContentLength(size) => {
                            let mut body_reader = HttpBodyReader::new_fixed_length(clt_r, size);
                            self.upload(&mut ftp_client, clt_w, &mut body_reader, Some(size))
                                .await
                        }
                        HttpBodyType::ReadUntilEnd => {
                            // 无长度界定：以客户端连接关闭作为 body 结束，故必须断开
                            let mut body_reader = HttpBodyReader::new_read_until_end(clt_r);
                            self.should_close = true;
                            self.upload(&mut ftp_client, clt_w, &mut body_reader, None)
                                .await
                        }
                        HttpBodyType::Chunked => {
                            let mut body_reader = HttpBodyDecodeReader::new_chunked(
                                clt_r,
                                self.ctx.server_config.body_line_max_len,
                            );
                            self.upload(&mut ftp_client, clt_w, &mut body_reader, None)
                                .await?;
                            // 上传完成后仍需（带超时）读完 chunked trailer 头，保持 HTTP 协议状态正确
                            tokio::time::timeout(
                                self.ctx.server_config.timeout.recv_req_header,
                                body_reader.trailer(128),
                            )
                            .await
                            .map_err(|_| {
                                ServerTaskError::ClientAppTimeout(
                                    "time out to read HTTP body trailer",
                                )
                            })?
                            .map_err(|e| {
                                ServerTaskError::ClientAppError(anyhow!(
                                    "invalid chunked body: {e}"
                                ))
                            })?;
                            if !body_reader.finished() {
                                // there may be trailer headers
                                self.should_close = true;
                            }
                            Ok(())
                        }
                    }
                } else {
                    self.reply_bad_request(clt_w, "no body found").await
                }
            }
            _ => self.reply_unimplemented(clt_w).await,
        }
    }

    /// 回复 400：请求不符合 FTP-over-HTTP 约定（如不允许携带 body）
    async fn reply_bad_request<'b, W>(
        &'b mut self,
        clt_w: &'b mut W,
        reason: &'static str,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::bad_request(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
        Err(ServerTaskError::InvalidClientProtocol(reason))
    }

    /// 回复 501：不支持的 HTTP 方法
    async fn reply_unimplemented<W>(&mut self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::unimplemented(self.req.version);
        // no custom header is set
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
        Err(ServerTaskError::UnimplementedProtocol)
    }

    /// 回复 503：上游 FTP 服务不可用（如 421 应答）
    async fn reply_service_unavailable<W>(&mut self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut rsp = HttpProxyClientResponse::service_unavailable(self.req.version);
        self.enable_custom_header_for_local_reply(&mut rsp);
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
        Err(ServerTaskError::UpstreamAppUnavailable)
    }

    /// 回复 502：与上游 FTP 协商失败（命令错误、登录异常等）
    async fn reply_bad_gateway<W>(&mut self, clt_w: &mut W, reason: String) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut rsp = HttpProxyClientResponse::bad_gateway(self.req.version);
        self.enable_custom_header_for_local_reply(&mut rsp);
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
        }
        self.should_close = true;
        Err(ServerTaskError::UpstreamNotNegotiated(reason))
    }

    /// 回复 404：目标文件/目录不存在（FTP 550 等）
    async fn reply_file_unavailable<W>(&mut self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut rsp =
            HttpProxyClientResponse::resource_not_found(self.req.version, self.should_close);
        self.enable_custom_header_for_local_reply(&mut rsp);
        match rsp.reply_err_to_request(clt_w).await {
            Ok(_) => {
                self.ftp_notes.rsp_status = rsp.status();
                Err(ServerTaskError::Finished)
            }
            Err(e) => {
                self.should_close = true;
                Err(ServerTaskError::ClientTcpWriteFailed(e))
            }
        }
    }

    /// 回复 416：Range 请求不可满足。
    /// valid_start_size 为 Some 时（FTP 服务器未告知文件总长的兜底场景）在响应中附带
    /// Content-Range 辅助头，此时视为正常结束；否则判为客户端非法 range。
    async fn reply_range_not_satisfiable<W>(
        &mut self,
        clt_w: &mut W,
        valid_start_size: Option<u64>,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut rsp = HttpProxyClientResponse::range_not_satisfiable(
            self.req.version,
            self.should_close,
            valid_start_size,
        );
        self.enable_custom_header_for_local_reply(&mut rsp);
        match rsp.reply_err_to_request(clt_w).await {
            Ok(_) => {
                self.ftp_notes.rsp_status = rsp.status();
                if valid_start_size.is_some() {
                    Err(ServerTaskError::Finished)
                } else {
                    Err(ServerTaskError::InvalidClientProtocol("invalid range"))
                }
            }
            Err(e) => {
                self.should_close = true;
                Err(ServerTaskError::ClientTcpWriteFailed(e))
            }
        }
    }

    /// 回复 401 并携带 WWW-Authenticate：FTP 登录失败/需要账号。
    /// realm 格式仿照 apache2 mod_proxy_ftp（ftp://user@host）。
    async fn reply_unauthorized<W>(&mut self, clt_w: &mut W, reason: String) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        // create the realm string as apache2 mod_proxy_ftp
        let realm = if let Some(user) = self.ftp_notes.username() {
            format!("ftp://{}@{}", user.to_encoded(), self.ftp_notes.upstream())
        } else {
            format!("ftp://{}", self.ftp_notes.upstream())
        };
        let mut rsp = HttpProxyClientResponse::need_login(
            self.req.version,
            // 请求带 body 时不能保持连接（body 尚未消费），必须关闭
            self.should_close || self.req.body_type().is_some(),
            &realm,
        );
        self.enable_custom_header_for_local_reply(&mut rsp);
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.ftp_notes.rsp_status = rsp.status();
            self.should_close = rsp.should_close();
        } else {
            self.should_close = true;
        }
        Err(ServerTaskError::UpstreamNotNegotiated(reason))
    }

    /// 创建 FTP 客户端：通过 escaper 取得 FTP 连接上下文（决定直连或经隧道），
    /// 然后连接上游 FTP 控制端口并完成握手（读取 220 欢迎应答等）。
    /// body_pending 表示客户端请求体还未发完：此时失败应答需要以关闭连接收场。
    /// 失败时按 FTP 握手错误（如 421/需要登录）映射为对应 HTTP 应答。
    async fn setup_ftp_client<'b, W>(
        &'b mut self,
        clt_w: &'b mut W,
        body_pending: bool,
    ) -> ServerTaskResult<HttpProxyFtpClient>
    where
        W: AsyncWrite + Unpin,
    {
        let task_conf = TcpConnectTaskConf {
            upstream: self.ftp_notes.upstream(),
        };
        let escaper_connect_context = self
            .ctx
            .escaper
            .new_ftp_connect_context(Arc::clone(&self.ctx.escaper), &task_conf, &self.task_notes)
            .await;
        let ftp_connection_provider =
            HttpProxyFtpConnectionProvider::new(&self.task_stats, escaper_connect_context);

        self.task_notes.stage = ServerTaskStage::Connecting;
        // 建连并读取 FTP 服务就绪应答；后续 PASV/PORT 协商由该客户端内部完成
        match FtpClient::connect_to(
            self.ftp_notes.upstream().clone(),
            ftp_connection_provider,
            &self.task_notes,
            &self.ctx.server_config.ftp_client_config,
        )
        .await
        {
            Ok(client) => {
                self.task_notes.stage = ServerTaskStage::Connected;
                client
                    .connection_provider()
                    .connect_context()
                    .fetch_control_tcp_notes(&mut self.ftp_notes.control_tcp_notes);

                if self.ctx.server_config.flush_task_log_on_connected
                    && let Some(log_ctx) = self.get_log_context()
                {
                    log_ctx.log_connected();
                }

                Ok(client)
            }
            Err((e, ftp_connection_provider)) => {
                // 建连/握手失败：仍回收 TCP 备注（供日志），并按 FTP 错误类型
                // （超时、拒绝、401 待认证等）映射为对应的 HTTP 错误应答
                ftp_connection_provider
                    .connect_context()
                    .fetch_control_tcp_notes(&mut self.ftp_notes.control_tcp_notes);
                let mut rsp = HttpProxyClientResponse::from_ftp_connect_error(
                    &e,
                    self.req.version,
                    self.should_close || body_pending,
                );
                self.enable_custom_header_for_local_reply(&mut rsp);
                if rsp.reply_err_to_request(clt_w).await.is_ok() {
                    self.ftp_notes.rsp_status = rsp.status();
                    self.should_close = rsp.should_close();
                } else {
                    self.should_close = true;
                }
                Err(e.into())
            }
        }
    }

    /// FTP 登录（USER/PASS 认证）：用户名/密码取自请求 URL 或客户端 Basic 认证
    /// （封装在 ftp_notes 中）。失败时按错误类型映射 HTTP 应答：
    /// 服务不可用->503，未登录/需要账号->401，其它命令错误->502。
    async fn login<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        match ftp_client
            .new_user_session(self.ftp_notes.username(), self.ftp_notes.password())
            .await
        {
            Ok(_) => {
                self.task_notes.stage = ServerTaskStage::LoggedIn;
                Ok(())
            }
            Err(e) => match e {
                FtpSessionOpenError::RawCommandError(_) => {
                    self.reply_bad_gateway(clt_w, format!("user login failed: {e:?}"))
                        .await
                }
                FtpSessionOpenError::ServiceNotAvailable => {
                    self.reply_service_unavailable(clt_w).await
                }
                FtpSessionOpenError::NotLoggedIn | FtpSessionOpenError::AccountIsNeeded => {
                    self.reply_unauthorized(clt_w, format!("user login failed: {e:?}"))
                        .await
                }
            },
        }
    }

    /// 处理 DELETE：按路径形态删除目录（RMD）、删除文件（DELE）；
    /// 路径类型未知（AutoDetect）时先用 MLST/SIZE 探明属性，再决定删文件还是删目录。
    async fn delete_path<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let r = match &self.ftp_notes.ftp_path {
            FtpRequestPath::DefaultDir(_) => {
                return self
                    .reply_bad_request(clt_w, "path is required in ftp delete request")
                    .await;
            }
            FtpRequestPath::ListOnly(dir) => ftp_client.remove_dir(dir).await,
            FtpRequestPath::FileOnly(file) => ftp_client.delete_file(file).await,
            FtpRequestPath::AutoDetect(path) => match ftp_client.fetch_file_facts(path).await {
                Ok(facts) => {
                    if facts.maybe_file() && facts.size().is_some() {
                        ftp_client.delete_file(path).await
                    } else {
                        ftp_client.remove_dir(path).await
                    }
                }
                Err(e) => Err(e),
            },
        };

        match r {
            Ok(_) => {
                self.task_notes.stage = ServerTaskStage::Replying;
                let mut rsp = HttpProxyClientResponse::ok(self.req.version, self.should_close);
                self.enable_custom_header_for_local_reply(&mut rsp);
                rsp.reply_ok_header(clt_w).await.map_err(|e| {
                    self.should_close = true;
                    ServerTaskError::ClientTcpWriteFailed(e)
                })?;

                self.task_notes.stage = ServerTaskStage::Finished;
                self.ftp_notes.rsp_status = rsp.status();
                Ok(())
            }
            Err(FtpFileStatError::FileUnavailable) => self.reply_file_unavailable(clt_w).await,
            Err(FtpFileStatError::ServiceNotAvailable) => {
                self.reply_service_unavailable(clt_w).await
            }
            Err(e) => {
                self.reply_bad_gateway(clt_w, format!("ftp delete failed: {e:?}"))
                    .await
            }
        }
    }

    /// 处理 GET 的分支选择：当路径类型待定（URL 不以 "/" 结尾，或带 ;type=a/i 参数）时，
    /// 先取文件属性（MLST 等），确认是文件则走下载，否则走目录列表。
    async fn list_or_download<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        if self.ftp_notes.ftp_path.detect_fact() {
            match ftp_client
                .fetch_file_facts(self.ftp_notes.ftp_path.as_str())
                .await
            {
                Ok(facts) => {
                    if facts.maybe_file() && facts.size().is_some() {
                        return self.download_file(ftp_client, &facts, clt_w).await;
                    }
                }
                Err(FtpFileStatError::FileUnavailable) => {
                    return self.reply_file_unavailable(clt_w).await;
                }
                Err(FtpFileStatError::ServiceNotAvailable) => {
                    return self.reply_service_unavailable(clt_w).await;
                }
                Err(e) => {
                    return self
                        .reply_bad_gateway(clt_w, format!("ftp stat failed: {e:?}"))
                        .await;
                }
            }
        }
        self.list_entry(ftp_client, clt_w).await
    }

    /// 目录列表（发送 LIST 命令）：先在 FTP 侧完成 PASV/PORT 协商并启动数据连接，
    /// 再向客户端回 200 响应头（可分块则 chunked，否则无长度结尾模式），
    /// 最后逐行接收列表数据转发写出（底层库负责断行、编码校验与行数限制）。
    async fn list_entry<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        match ftp_client
            .list_directory_detailed_start(self.ftp_notes.ftp_path.as_str(), &self.task_notes)
            .await
        {
            Ok(data_stream) => {
                // 记录本次数据连接（PASV/PORT 协商结果）的 TCP 备注，供日志/自定义头使用
                ftp_client
                    .connection_provider()
                    .connect_context()
                    .fetch_transfer_tcp_notes(&mut self.ftp_notes.transfer_tcp_notes);

                self.task_notes.stage = ServerTaskStage::Replying;
                // chunked=true 表示可用分块传输编码；false（如 HTTP/1.0）则靠关闭连接界定 body
                let (mut rsp, chunked) = HttpProxyClientResponse::auto_chunked_ok(
                    self.req.version,
                    self.should_close,
                    &mime::TEXT_PLAIN,
                );
                self.enable_custom_header_for_local_reply(&mut rsp);
                rsp.reply_ok_header(clt_w).await.map_err(|e| {
                    self.should_close = true;
                    ServerTaskError::ClientTcpWriteFailed(e)
                })?;
                self.ftp_notes.rsp_status = rsp.status();

                self.task_notes.mark_relaying();
                let ret = if chunked {
                    let mut receiver = super::ChunkedListWriter::new(
                        clt_w,
                        self.ctx.server_config.tcp_copy.buffer_size(),
                    );
                    self.receive_list_data(ftp_client, data_stream, &mut receiver)
                        .await
                } else {
                    let mut receiver = super::EndingListWriter::new(
                        clt_w,
                        self.ctx.server_config.tcp_copy.buffer_size(),
                    );
                    self.receive_list_data(ftp_client, data_stream, &mut receiver)
                        .await
                };
                if ret.is_err() {
                    // close the client side connection as we have failed to write body
                    self.should_close = true;
                }
                ret
            }
            Err(FtpFileRetrieveStartError::ServiceNotAvailable) => {
                self.reply_service_unavailable(clt_w).await
            }
            Err(FtpFileRetrieveStartError::FileUnavailable) => {
                self.reply_file_unavailable(clt_w).await
            }
            Err(e) => {
                self.reply_bad_gateway(clt_w, format!("ftp list start failed: {e:?}"))
                    .await
            }
        }
    }

    /// 接收列表数据到 receiver：底层库从数据连接逐行读入并回调。
    /// 若因 receiver 写客户端失败而中止，取出暂存的 IO 错误向上返回；
    /// 其它 FTP 侧错误也要先 flush 已有缓冲，保证客户端拿到完整的结束标记。
    async fn receive_list_data<R>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        data_stream: BoxFtpRemoteConnection,
        receiver: &mut R,
    ) -> ServerTaskResult<()>
    where
        R: ListWriter,
    {
        match ftp_client
            .list_directory_detailed_receive(data_stream, receiver)
            .await
        {
            Ok(()) => {
                receiver
                    .flush_buf()
                    .await
                    .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                self.task_notes.stage = ServerTaskStage::Finished;
                Ok(())
            }
            Err(e) => {
                if let FtpFileListError::LocalIoCallbackFailed = e
                    && let Some(io_err) = receiver.take_io_error()
                {
                    return Err(ServerTaskError::ClientTcpWriteFailed(io_err));
                }

                receiver
                    .flush_buf()
                    .await
                    .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                Err(ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))
            }
        }
    }

    /// 解析请求头中的 Range: bytes=start-end，返回 (start, end)。
    /// 仅支持单个范围；不支持 suffix 形式（"-500" 时 start 解析为 None 退化为整文件下载）。
    /// 多处 RANGE 头、非 bytes= 前缀或多范围一律视为无效，返回 (None, None)。
    fn get_download_range(&self) -> (Option<u64>, Option<u64>) {
        let mut start: Option<u64> = None;
        let mut end: Option<u64> = None;
        let headers = self.req.end_to_end_headers.get_all(http::header::RANGE);
        for v in headers {
            if start.is_some() || end.is_some() {
                // we don't support multiple ranges
                return (None, None);
            }

            // HEADERVALUE 来自已校验的 HTTP 解析器，此处按 UTF-8 读取是安全的
            let value = unsafe { std::str::from_utf8_unchecked(v.as_bytes()) };
            let value = value.trim();
            if !value.starts_with("bytes=") {
                return (None, None);
            }

            let ranges = &value[6..];
            if ranges.is_empty() {
                return (None, None);
            }
            for r in ranges.split(',') {
                let range = r.trim();
                match memchr::memrchr(b'-', range.as_bytes()) {
                    Some(p) => {
                        start = if p > 0 {
                            u64::from_str(&range[0..p]).map(Some).unwrap_or(None)
                        } else {
                            None
                        };

                        end = if p + 1 < range.len() {
                            u64::from_str(&range[p + 1..]).map(Some).unwrap_or(None)
                        } else {
                            None
                        };
                    }
                    None => return (None, None),
                }
            }
        }
        (start, end)
    }

    /// GET 下载入口：带有效 Range 时走部分下载（REST + 206），否则整文件下载。
    async fn download_file<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        file_facts: &FtpFileFacts,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        if let (Some(start), end) = self.get_download_range() {
            self.download_file_from_position(ftp_client, file_facts, start, end, clt_w)
                .await
        } else {
            self.download_full_file(ftp_client, file_facts, clt_w).await
        }
    }

    /// 整文件下载（RETR）：FTP 侧启动传输后，按是否从服务器拿到文件总长（SIZE 命令）
    /// 决定响应形态——有总长回 Content-Length 定长 body，无总长则回不带长度的响应并
    /// 强制关闭连接。数据经 receive_file_data 从数据连接直拷到客户端。
    async fn download_full_file<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        file_facts: &FtpFileFacts,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        match ftp_client
            .retrieve_file_start(self.ftp_notes.ftp_path.as_str(), None, &self.task_notes)
            .await
        {
            Ok((data_stream, file_transfer_size)) => {
                ftp_client
                    .connection_provider()
                    .connect_context()
                    .fetch_transfer_tcp_notes(&mut self.ftp_notes.transfer_tcp_notes);

                self.task_notes.stage = ServerTaskStage::Replying;
                let mime = file_facts
                    .media_type()
                    .unwrap_or(&mime::APPLICATION_OCTET_STREAM);
                if let Some(size) = file_transfer_size {
                    let mut rsp = HttpProxyClientResponse::sized_ok(
                        self.req.version,
                        self.should_close,
                        size,
                        mime,
                    );
                    self.enable_custom_header_for_local_reply(&mut rsp);
                    rsp.reply_ok_header(clt_w).await.map_err(|e| {
                        self.should_close = true;
                        ServerTaskError::ClientTcpWriteFailed(e)
                    })?;
                    self.ftp_notes.rsp_status = rsp.status();

                    self.task_notes.mark_relaying();

                    match self
                        .receive_file_data(
                            ftp_client,
                            // 定长模式：用 SizedReader 截断，防止 FTP 多发数据溢出 HTTP body
                            SizedReader::new(data_stream, size),
                            false,
                            clt_w,
                        )
                        .await
                    {
                        Ok(copied_size) => {
                            if copied_size != size {
                                self.should_close = true;
                                Err(ServerTaskError::UpstreamAppError(anyhow!(
                                    "copied {} bytes different than expected {}",
                                    copied_size,
                                    size
                                )))
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => {
                            // close the client side connection as we have failed to write body
                            self.should_close = true;
                            Err(e)
                        }
                    }
                } else {
                    let mut rsp = HttpProxyClientResponse::ending_ok(
                        self.req.version,
                        self.should_close,
                        mime,
                    );
                    self.enable_custom_header_for_local_reply(&mut rsp);
                    self.should_close = true; // always close the connection
                    rsp.reply_ok_header(clt_w)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    self.ftp_notes.rsp_status = rsp.status();

                    self.task_notes.mark_relaying();

                    match self
                        .receive_file_data(ftp_client, data_stream, false, clt_w)
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            // close the client side connection as we have failed to write body
                            self.should_close = true;
                            Err(e)
                        }
                    }
                }
            }
            Err(FtpFileRetrieveStartError::ServiceNotAvailable) => {
                self.reply_service_unavailable(clt_w).await
            }
            Err(FtpFileRetrieveStartError::FileUnavailable) => {
                self.reply_file_unavailable(clt_w).await
            }
            Err(e) => {
                self.reply_bad_gateway(clt_w, format!("ftp retrieve start failed: {e:?}"))
                    .await
            }
        }
    }

    /// Range 部分下载：FTP 侧用 REST 从 start_size 处开始传输（回 206 Partial Content）。
    /// 文件总长已知时，end 缺省取总长末尾，按 end-start+1 拷贝指定区间；当区间未覆盖到
    /// 文件末尾时，拷满后需 ABOR 中止 FTP 传输以尽快释放数据连接。
    /// 若服务器未回文件总长（不支持 SIZE），无法校验 Range，回 416 并附 start 参考信息。
    async fn download_file_from_position<W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        file_facts: &FtpFileFacts,
        start_size: u64,
        end_size: Option<u64>,
        clt_w: &mut W,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        match ftp_client
            .retrieve_file_start(
                self.ftp_notes.ftp_path.as_str(),
                Some(start_size),
                &self.task_notes,
            )
            .await
        {
            Ok((data_stream, file_transfer_size)) => {
                ftp_client
                    .connection_provider()
                    .connect_context()
                    .fetch_transfer_tcp_notes(&mut self.ftp_notes.transfer_tcp_notes);

                self.task_notes.stage = ServerTaskStage::Replying;
                let mime = file_facts
                    .media_type()
                    .unwrap_or(&mime::APPLICATION_OCTET_STREAM);
                if let Some(file_size) = file_transfer_size {
                    let end_size = end_size.unwrap_or(file_size - 1);
                    if end_size < start_size {
                        return self.reply_range_not_satisfiable(clt_w, None).await;
                    }
                    let file_copy_size = end_size - start_size + 1;

                    let mut rsp = HttpProxyClientResponse::sized_partial_content(
                        self.req.version,
                        self.should_close,
                        start_size,
                        end_size,
                        file_size,
                        mime,
                    );
                    self.enable_custom_header_for_local_reply(&mut rsp);
                    rsp.reply_ok_header(clt_w).await.map_err(|e| {
                        self.should_close = true;
                        ServerTaskError::ClientTcpWriteFailed(e)
                    })?;
                    self.ftp_notes.rsp_status = rsp.status();

                    self.task_notes.mark_relaying();

                    match self
                        .receive_file_data(
                            ftp_client,
                            SizedReader::new(data_stream, file_copy_size),
                            file_size != end_size + 1,
                            clt_w,
                        )
                        .await
                    {
                        Ok(copied_size) => {
                            if copied_size != file_copy_size {
                                self.should_close = true;
                                Err(ServerTaskError::UpstreamAppError(anyhow!(
                                    "copied {} bytes different than expected {}",
                                    copied_size,
                                    file_copy_size
                                )))
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => {
                            // close the client side connection as we have failed to write body
                            self.should_close = true;
                            Err(e)
                        }
                    }
                } else {
                    if let Some(end_size) = end_size
                        && end_size < start_size
                    {
                        return self.reply_range_not_satisfiable(clt_w, None).await;
                    }
                    self.reply_range_not_satisfiable(clt_w, Some(start_size))
                        .await
                }
            }
            Err(FtpFileRetrieveStartError::ServiceNotAvailable) => {
                self.reply_service_unavailable(clt_w).await
            }
            Err(FtpFileRetrieveStartError::FileUnavailable) => {
                self.reply_file_unavailable(clt_w).await
            }
            Err(e) => {
                self.reply_bad_gateway(clt_w, format!("ftp retrieve start failed: {e:?}"))
                    .await
            }
        }
    }

    /// 从 FTP 数据连接向 HTTP 客户端拷贝下载数据的主循环，四种事件源（biased 优先级）：
    /// 1. 数据拷贝结束：按需 ABOR（should_abort）或等待 FTP 传输完成应答（226），
    ///    并核对拷贝量与 Content-Length 一致；
    /// 2. FTP 控制连接提前可读：说明服务器在传输未收完时发出了应答（如报错或传输结束），
    ///    先把应答消费掉，再在 transfer_end_wait_timeout 内等待剩余数据排空，超时则报错；
    /// 3. 周期日志 tick；
    /// 4. 空闲 tick：连续空闲达到 max_idle_count 判定超时（据缓冲是否排空区分客户端还是
    ///    服务器超时），同时检查用户封禁与服务器退出策略。
    async fn receive_file_data<'b, S, W>(
        &'b mut self,
        ftp_client: &'b mut HttpProxyFtpClient,
        mut data_stream: S,
        should_abort: bool, // 区间未覆盖到文件末尾时，拷满后需要 ABOR 终止传输
        clt_w: &'b mut W,
    ) -> ServerTaskResult<u64>
    where
        S: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut data_copy =
            StreamCopy::new(&mut data_stream, clt_w, &self.ctx.server_config.tcp_copy);

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut log_interval = self.ctx.get_log_interval();
        let mut idle_count = 0;
        loop {
            tokio::select! {
                biased;

                r = &mut data_copy => {
                    if should_abort {
                        // 请求区间已到结尾但文件未传完：发 ABOR 让服务器停止本次传输
                        ftp_client.abort_transfer()
                            .await
                            .map_err(|e| ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))?;
                    } else {
                        // 正常读满：等待控制连接上的传输结束应答（226/250）
                        ftp_client.wait_retrieve_end_reply()
                            .await
                            .map_err(|e| ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))?;
                    }
                    r.map_err(|e| match e {
                        StreamCopyError::ReadFailed(e) => ServerTaskError::UpstreamReadFailed(e),
                        StreamCopyError::WriteFailed(e) => ServerTaskError::ClientTcpWriteFailed(e),
                    })?;

                    self.task_notes.stage = ServerTaskStage::Finished;
                    return Ok(data_copy.copied_size());
                }
                r = ftp_client.wait_control_read_ready() => {
                    // 数据连接还没读完，控制连接却已有应答：服务器提前终止了传输
                    if let Err(e) = r {
                        return Err(ServerTaskError::UpstreamAppError(anyhow::Error::new(e)));
                    }
                    ftp_client.wait_retrieve_end_reply()
                        .await
                        .map_err(|e| ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))?;

                    // 应答已收到，给数据连接一个短超时排空尾部数据
                    let wait_timeout = ftp_client.transfer_end_wait_timeout();
                    return match tokio::time::timeout(wait_timeout, &mut data_copy).await {
                        Ok(Ok(_)) => {
                            self.task_notes.stage = ServerTaskStage::Finished;
                            Ok(data_copy.copied_size())
                        }
                        Ok(Err(StreamCopyError::ReadFailed(e))) => Err(ServerTaskError::UpstreamReadFailed(e)),
                        Ok(Err(StreamCopyError::WriteFailed(e))) => Err(ServerTaskError::ClientTcpWriteFailed(e)),
                        Err(_) => Err(ServerTaskError::UpstreamAppTimeout("timeout to wait transfer end")),
                    };
                }
                _ = log_interval.tick() => {
                    // 周期性输出任务进度日志
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
                n = idle_interval.tick() => {
                    // 空闲检测：n 为经过的空闲周期数；双向都无流量才累计
                    if data_copy.is_idle() {
                        idle_count += n;

                        if let Some(user_ctx) = self.task_notes.user_ctx() {
                            let user = user_ctx.user();
                            if user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }
                        }

                        // 连续空闲超限：读侧无缓存数据 => 上游超时；否则为客户端写侧（限速/慢客户端）超时
                        if idle_count >= self.max_idle_count {
                            return if data_copy.no_cached_data() {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while reading data"))
                            } else {
                                Err(ServerTaskError::ClientAppTimeout("idle while writing data"))
                            };
                        }
                    } else {
                        idle_count = 0;

                        data_copy.reset_active();
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
    }

    /// 上传前处理 "Expect: 100-continue"：HTTP/1.1+ 且带该头时先回 1xx 继续应答，
    /// 客户端才会开始发送 body（HTTP/0.9/1.0 直接跳过）。
    async fn check_and_send_continue<W>(&mut self, clt_w: &mut W) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        if matches!(
            self.req.version,
            http::Version::HTTP_09 | http::Version::HTTP_10
        ) {
            return Ok(());
        }

        if let Some(v) = self.req.end_to_end_headers.get(http::header::EXPECT)
            && let Ok(s) = std::str::from_utf8(v.as_bytes())
            && s.to_lowercase().eq("100-continue")
            && let Err(e) = HttpProxyClientResponse::reply_continue(self.req.version, clt_w).await
        {
            self.should_close = true;
            return Err(ServerTaskError::ClientTcpWriteFailed(e));
        }

        Ok(())
    }

    /// 处理 PUT 上传：FTP 侧启动 STOR 传输（含 PASV/PORT 数据连接建立），把请求 body
    /// 拷入数据连接；成功后核对拷贝字节数与声明的 file_size 一致，回 200。
    /// file_size 为 None（不定长/chunked）时不做长度校验。
    async fn upload<R, W>(
        &mut self,
        ftp_client: &mut HttpProxyFtpClient,
        clt_w: &mut W,
        body_reader: &mut R,
        file_size: Option<u64>,
    ) -> ServerTaskResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match ftp_client
            .store_file_start(self.ftp_notes.ftp_path.as_str(), &self.task_notes)
            .await
        {
            Ok(data_stream) => {
                ftp_client
                    .connection_provider()
                    .connect_context()
                    .fetch_transfer_tcp_notes(&mut self.ftp_notes.transfer_tcp_notes);

                self.check_and_send_continue(clt_w).await?;

                self.task_notes.mark_relaying();

                match self
                    .send_file_data(ftp_client, data_stream, body_reader)
                    .await
                {
                    Ok(copied_size) => {
                        if let Some(file_size) = file_size
                            && copied_size != file_size
                        {
                            return self.reply_bad_gateway(
                                    clt_w,
                                    format!(
                                        "uploaded {copied_size} bytes different than expected {file_size}"
                                    ),
                                ).await;
                        }

                        let mut rsp =
                            HttpProxyClientResponse::ok(self.req.version, self.should_close);
                        self.enable_custom_header_for_local_reply(&mut rsp);
                        match rsp.reply_ok_header(clt_w).await {
                            Ok(_) => {
                                self.ftp_notes.rsp_status = rsp.status();
                                self.task_notes.stage = ServerTaskStage::Finished;
                                Ok(())
                            }
                            Err(e) => {
                                self.should_close = true;
                                Err(ServerTaskError::ClientTcpWriteFailed(e))
                            }
                        }
                    }
                    Err(e) => {
                        self.should_close = true;
                        // 上传失败：能映射出 HTTP 错误码的先把错误应答发给客户端再返回错误
                        if let Some(mut rsp) =
                            HttpProxyClientResponse::from_task_err(&e, self.req.version, true)
                        {
                            self.enable_custom_header_for_local_reply(&mut rsp);
                            rsp.reply_err_to_request(clt_w)
                                .await
                                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                            self.ftp_notes.rsp_status = rsp.status();
                        }
                        Err(e)
                    }
                }
            }
            Err(FtpFileStoreStartError::ServiceNotAvailable) => {
                self.reply_service_unavailable(clt_w).await
            }
            Err(FtpFileStoreStartError::FileUnavailable) => {
                self.reply_file_unavailable(clt_w).await
            }
            Err(e) => {
                self.reply_bad_gateway(clt_w, format!("ftp retrieve start failed: {e:?}"))
                    .await
            }
        }
    }

    /// 从 HTTP 请求 body 向 FTP 数据连接发送上传数据的主循环，事件源与
    /// receive_file_data 相同（拷贝结束则关闭数据连接并等待 STOR 完成应答 226；
    /// 控制连接提前应答视为上传被服务器中断；空闲/周期日志处理一致，
    /// 但空闲超时的归属方向相反：读侧是客户端、写侧是上游）。
    async fn send_file_data<'b, S, R>(
        &'b mut self,
        ftp_client: &'b mut HttpProxyFtpClient,
        mut data_stream: S,
        body_reader: &mut R,
    ) -> ServerTaskResult<u64>
    where
        S: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let mut data_copy = StreamCopy::new(
            body_reader,
            &mut data_stream,
            &self.ctx.server_config.tcp_copy,
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut log_interval = self.ctx.get_log_interval();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut data_copy => {
                    let copied_size = data_copy.copied_size();
                    // 先释放数据连接（close 通知服务器 body 结束），再等传输结束应答
                    drop(data_stream);

                    ftp_client.wait_store_end_reply()
                        .await
                        .map_err(|e| ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))?;
                    r.map_err(|e| match e {
                        StreamCopyError::ReadFailed(e) => ServerTaskError::ClientTcpReadFailed(e),
                        StreamCopyError::WriteFailed(e) => ServerTaskError::UpstreamWriteFailed(e),
                    })?;
                    return Ok(copied_size);
                }
                r = ftp_client.wait_control_read_ready() => {
                    // 上传未结束而控制连接已有应答：服务器提前报错或结束了传输
                    if let Err(e) = r {
                        return Err(ServerTaskError::UpstreamAppError(anyhow::Error::new(e)));
                    }
                    ftp_client.wait_store_end_reply()
                        .await
                        .map_err(|e| ServerTaskError::UpstreamAppError(anyhow::Error::new(e)))?;

                    return Err(ServerTaskError::UpstreamAppError(
                        anyhow!("unexpected server end reply after {} bytes sent)", data_copy.copied_size())
                    ));
                }
                _ = log_interval.tick() => {
                    // 周期性输出任务进度日志
                    if let Some(log_ctx) = self.get_log_context() {
                        log_ctx.log_periodic();
                    }
                }
                n = idle_interval.tick() => {
                    // 空闲检测；上传方向读侧是客户端、写侧是上游，与下载相反
                    if data_copy.is_idle() {
                        idle_count += n;

                        if let Some(user_ctx) = self.task_notes.user_ctx() {
                            let user = user_ctx.user();
                            if user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }
                        }

                        // 连续空闲超限：无缓存数据 => 客户端不发数据；否则为上游写不动
                        if idle_count >= self.max_idle_count {
                            return if data_copy.no_cached_data() {
                                Err(ServerTaskError::ClientAppTimeout("idle while reading data"))
                            } else {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while sending data"))
                            };
                        }
                    } else {
                        idle_count = 0;

                        data_copy.reset_active();
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
    }
}
