/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 源站内容检测/拦截的主状态机。
//!
//! [`ImapInterceptObject`] 持有客户端与源站之间的双向 IO，按 IMAP 协议状态
//! （未认证 not_authenticated → 已认证 authenticated → 登出 logout）逐行转发
//! 并改写命令/响应。子模块分工：greeting（服务端问候）、capability（能力协商
//! 过滤）、forward（字面量数据与 ICAP 改写的转发）、ext（按行收发的 IO 扩展）。
//! 检测结束后可能返回新的 [`StreamInspection`] 状态（如 STARTTLS 升级），
//! 或返回 `None` 表示本流检测终止。

use std::time::Duration;

use anyhow::anyhow;
use tokio::io::AsyncWriteExt;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_imap_proto::CommandPipeline;
use g3_imap_proto::response::ByeResponse;
use g3_io_ext::{IdleInterval, LineRecvVec, OnceBufReader, StreamCopyConfig};
use g3_slog_types::{LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use super::StartTlsProtocol;
#[cfg(feature = "quic")]
use crate::audit::DetourAction;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{
    BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamInspection, StreamTransitTask,
};
use crate::log::task::TaskEvent;
use crate::serve::{ServerTaskError, ServerTaskResult};

mod ext;
use ext::{CommandLineReceiveExt, ResponseLineReceiveExt};

// CAPABILITY 协商过滤：仅放行代理支持的扩展能力
mod capability;
use capability::Capability;

// 服务端问候（连接建立后的第一条 untagged 响应）处理
mod greeting;
use greeting::Greeting;

// 未认证状态下的命令/响应中继
mod not_authenticated;
use not_authenticated::InitiationStatus;

// 已认证状态下的命令/响应中继
mod authenticated;
use authenticated::CloseReason;

// 字面量数据传输与 ICAP 消息改写转发
mod forward;
use forward::ResponseAction;

// LOGOUT 收尾流程
mod logout;

/// 双向行缓冲：分别缓存从源站收到的响应行和从客户端收到的命令行，
/// 行内可能残留尚未消费的字节（如字面量数据的一部分）
struct ImapRelayBuf {
    rsp_recv_buf: LineRecvVec,
    cmd_recv_buf: LineRecvVec,
}

/// 以拦截审计日志格式记录当前检测对象的最终结局（正常结束或出错）
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "SmtpConnection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "server_bye" => $obj.server_bye,
                "client_logout" => $obj.client_logout,
            );
        }
    };
}

/// 客户端与源站之间的四个方向 IO 句柄，整体存放便于在 bypass/detour/intercept
/// 各分支中一次性 `take()` 移交所有权
struct ImapIo {
    pub(crate) clt_r: BoxAsyncRead,
    pub(crate) clt_w: BoxAsyncWrite,
    /// 带一次性预读缓冲的源站读端：问候之前可能已有管道（pipelined）响应数据
    pub(crate) ups_r: OnceBufReader<BoxAsyncRead>,
    pub(crate) ups_w: BoxAsyncWrite,
}

/// IMAP 拦截检测主对象：驱动整条 问候 → 未认证 → 已认证 的状态机
pub(crate) struct ImapInterceptObject<SC: ServerConfig> {
    /// 尚未被移交出去的 IO 句柄；进入具体中继阶段后置为 None
    io: Option<ImapIo>,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    /// 本流是否由 STARTTLS 升级而来（升级后不应再出现 STARTTLS 命令）
    from_starttls: bool,
    /// 客户端命令与源站响应的配对管线，用于识别带标签响应属于哪条命令
    cmd_pipeline: CommandPipeline,
    /// 连接最终由源站 BYE/关闭发起（用于审计结局）
    server_bye: bool,
    /// 客户端已发出 LOGOUT（正常登出）
    client_logout: bool,
    /// 客户端是否已通过认证（AUTHENTICATE/Login 成功）
    authenticated: bool,
    /// 当前是否已 SELECT/EXAMINE 了邮箱（决定 FETCH/SEARCH 等命令是否合法）
    mailbox_selected: bool,
    /// 协商得到的服务器能力集合，用于改写 CAPABILITY 响应
    capability: Capability,
}

impl<SC: ServerConfig> ImapInterceptObject<SC> {
    /// 新建检测对象，IO 句柄与认证状态均由调用方后续设置
    pub(crate) fn new(ctx: StreamInspectContext<SC>, upstream: UpstreamAddr) -> Self {
        ImapInterceptObject {
            io: None,
            ctx,
            upstream,
            from_starttls: false,
            cmd_pipeline: CommandPipeline::default(),
            server_bye: false,
            client_logout: false,
            authenticated: false,
            mailbox_selected: false,
            capability: Capability::default(),
        }
    }

    /// 标记本流是 STARTTLS 升级之后重新开始的 IMAP 会话，跳过问候阶段
    pub(crate) fn set_from_starttls(&mut self) {
        self.from_starttls = true;
    }

    /// 移交四个方向的 IO 句柄，供 [`Self::intercept`] 后续消费
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) {
        let io = ImapIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 记录单向（客户端或源站）半关闭的审计日志；无拦截日志器时静默跳过
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "SmtpConnection",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
            );
        }
    }
}

// 透明转发/分流阶段复用的转发任务参数：限速、空闲检测、退出策略均来自服务器配置
impl<SC: ServerConfig> StreamTransitTask for ImapInterceptObject<SC> {
    fn copy_config(&self) -> StreamCopyConfig {
        self.ctx.server_config.limited_copy_config()
    }

    fn idle_check_interval(&self) -> IdleInterval {
        self.ctx.idle_wheel.register()
    }

    fn max_idle_count(&self) -> usize {
        self.ctx.max_idle_count
    }

    fn log_client_shutdown(&self) {
        self.log_partial_shutdown(TaskEvent::ClientShutdown);
    }

    fn log_upstream_shutdown(&self) {
        self.log_partial_shutdown(TaskEvent::UpstreamShutdown);
    }

    fn log_periodic(&self) {
        // TODO: 周期性统计日志暂未实现
    }

    fn log_flush_interval(&self) -> Option<Duration> {
        self.ctx.server_config.task_log_flush_interval()
    }

    fn quit_policy(&self) -> &ServerQuitPolicy {
        self.ctx.server_quit_policy.as_ref()
    }

    fn user(&self) -> Option<&User> {
        self.ctx.user()
    }
}

impl<SC> ImapInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 检测入口：按针对该源站的检测动作分发到拦截/分流/直通/阻断四条路径。
    /// 返回 `Some(StreamInspection)` 表示流要切换到另一个协议检测状态
    /// （如 STARTTLS）；返回 `None` 表示流已处理完毕
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let r = match self.ctx.imap_inspect_action(self.upstream.host()) {
            ProtocolInspectAction::Intercept => self.do_intercept().await,
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await.map(|_| None),
            ProtocolInspectAction::Bypass => self.do_bypass().await.map(|_| None),
            ProtocolInspectAction::Block => self.do_block().await.map(|_| None),
        };
        // 无论成败都落一条拦截审计日志，记录 bye/登出等最终状态
        match r {
            Ok(obj) => {
                intercept_log!(self, "finished");
                Ok(obj)
            }
            Err(e) => {
                intercept_log!(self, "{e}");
                Err(e)
            }
        }
    }

    /// 分流：把本流交给远端（QUIC）检测引擎处理；远端不可用或要求跳过时退回直通
    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        let Some(client) = self.ctx.audit_handle.stream_detour_client() else {
            return self.do_bypass().await;
        };

        let mut detour_stream = match client.open_detour_stream().await {
            Ok(s) => s,
            Err(e) => {
                // 无法建立分流通道：向客户端回 BYE 内部错误后终止
                self.close_on_detour_error().await;
                return Err(ServerTaskError::InternalAdapterError(e));
            }
        };

        let detour_ctx = client.build_context(
            &self.ctx.server_config,
            &self.ctx.server_quit_policy,
            &self.ctx.idle_wheel,
            &self.ctx.task_notes,
            &self.upstream,
            g3_dpi::Protocol::Imap,
        );

        match detour_ctx.check_detour_action(&mut detour_stream).await {
            Ok(DetourAction::Continue) => {
                // 远端决定接管：双向原始字节全部改由分流通道转发
                let ImapIo {
                    clt_r,
                    clt_w,
                    ups_r,
                    ups_w,
                } = self.io.take().unwrap();

                detour_ctx
                    .relay(clt_r, clt_w, ups_r, ups_w, detour_stream)
                    .await
            }
            Ok(DetourAction::Bypass) => {
                detour_stream.finish();
                self.do_bypass().await
            }
            Ok(DetourAction::Block) => {
                detour_stream.finish();
                self.do_block().await
            }
            Err(e) => {
                detour_stream.finish();
                self.close_on_detour_error().await;
                Err(ServerTaskError::InternalAdapterError(e))
            }
        }
    }

    /// 分流出错时的善后：断开源站连接，并向客户端回 BYE "internal error"
    #[cfg(feature = "quic")]
    async fn close_on_detour_error(&mut self) {
        let ImapIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            // 异步关闭源站写端，避免阻塞向客户端发送 BYE
            let _ = ups_w.shutdown().await;
        });

        if ByeResponse::reply_internal_error(&mut clt_w).await.is_ok() {
            let _ = clt_w.shutdown().await;
        }
    }

    /// 直通：不再解析协议，客户端与源站之间原始字节透明互转
    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let ImapIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断：向客户端回 BYE "blocked" 并双向断开，以错误结束本任务
    async fn do_block(&mut self) -> ServerTaskResult<()> {
        let ImapIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            // 先断开源站侧，防止客户端在等待 BYE 期间继续收到数据
            let _ = ups_w.shutdown().await;
        });

        ByeResponse::reply_blocked(&mut clt_w)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        clt_w
            .shutdown()
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        Err(ServerTaskError::InternalAdapterError(anyhow!(
            "imap blocked by inspection policy"
        )))
    }

    /// 标记连接最终由源站主动关闭（审计结局区分 server_bye 与 client_logout）
    fn mark_close_by_server(&mut self) {
        self.server_bye = true;
    }

    /// 完整协议拦截：解析问候 → （可选）未认证状态中继 → 已认证状态中继。
    /// 返回 `Some` 仅发生在 STARTTLS 升级到其它检测对象时
    async fn do_intercept(&mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let ImapIo {
            clt_r,
            mut clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let interception_config = self.ctx.imap_interception();

        // 把源站预读数据回填进行缓冲，避免已到达的响应行丢失
        let (initial_data, mut ups_r) = ups_r.into_parts();
        let rsp_recv_buf = if let Some(data) = initial_data {
            LineRecvVec::with_data(&data, interception_config.response_line_max_size)
        } else {
            LineRecvVec::with_capacity(interception_config.response_line_max_size)
        };
        let mut relay_buf = ImapRelayBuf {
            rsp_recv_buf,
            cmd_recv_buf: LineRecvVec::with_capacity(interception_config.command_line_max_size),
        };

        if self.from_starttls {
            // TLS 升级后源站不再重发问候，直接从未认证状态开始
            return self
                .start_initiation(clt_r, clt_w, ups_r, ups_w, relay_buf)
                .await;
        }

        let mut greeting = Greeting::default();
        if let Err(e) = greeting
            .relay(
                &mut ups_r,
                &mut clt_w,
                &mut relay_buf.rsp_recv_buf,
                interception_config.greeting_timeout,
            )
            .await
        {
            // 问候失败时若尚未向客户端发出任何字节，补一个 BYE 说明原因
            greeting.reply_no_service(&e, &mut clt_w).await;
            return Err(e.into());
        }
        if greeting.close_service() {
            // 源站问候即 * BYE，无后续交互
            self.mark_close_by_server();
            return Ok(None);
        }
        if greeting.pre_authenticated() {
            // 预认证问候（如 PREAUTH）：跳过未认证状态直接进入已认证
            self.capability = greeting.into_capability();
            self.enter_authenticated(clt_r, clt_w, ups_r, ups_w, relay_buf)
                .await?;
            Ok(None)
        } else {
            self.capability = greeting.into_capability();
            self.start_initiation(clt_r, clt_w, ups_r, ups_w, relay_buf)
                .await
        }
    }

    /// 进入未认证（not authenticated）状态中继，并按结束原因做状态转移
    async fn start_initiation(
        &mut self,
        mut clt_r: BoxAsyncRead,
        mut clt_w: BoxAsyncWrite,
        mut ups_r: BoxAsyncRead,
        mut ups_w: BoxAsyncWrite,
        mut relay_buf: ImapRelayBuf,
    ) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        match self
            .relay_not_authenticated(
                &mut clt_r,
                &mut clt_w,
                &mut ups_r,
                &mut ups_w,
                &mut relay_buf,
            )
            .await?
        {
            InitiationStatus::ClientClose => {
                // 客户端发出 LOGOUT：等待源站回完 tagged 结果与 * BYE 再结束
                self.handle_client_logout(&mut clt_w, &mut ups_r, &mut relay_buf.rsp_recv_buf)
                    .await?;
                Ok(None)
            }
            InitiationStatus::ServerClose => {
                self.mark_close_by_server();
                Ok(None)
            }
            InitiationStatus::LocalClose(e) => {
                // 本机决定断开：先向源站补发 LOGOUT 礼貌收尾，再上报错误
                self.start_server_logout(&mut ups_r, &mut ups_w, &mut relay_buf.rsp_recv_buf)
                    .await;
                Err(e)
            }
            InitiationStatus::StartTls => {
                if let Some(tls_interception) = self.ctx.tls_interception() {
                    // 策略允许 TLS 拦截：把流交给 STARTTLS 检测对象继续处理
                    let mut start_tls_obj = crate::inspect::start_tls::StartTlsInterceptObject::new(
                        self.ctx.clone(),
                        self.upstream.clone(),
                        tls_interception,
                        StartTlsProtocol::Imap,
                    );
                    start_tls_obj.set_io(clt_r, clt_w, ups_r, ups_w);
                    Ok(Some(StreamInspection::StartTls(start_tls_obj)))
                } else {
                    // 不做 TLS 拦截：STARTTLS 之后全是加密字节，只能透明转发到结束
                    self.transit_transparent(clt_r, clt_w, ups_r, ups_w)
                        .await
                        .map(|_| None)
                }
            }
            InitiationStatus::Authenticated => {
                self.enter_authenticated(clt_r, clt_w, ups_r, ups_w, relay_buf)
                    .await?;
                Ok(None)
            }
        }
    }

    /// 进入已认证（authenticated）状态中继，直到任一方向关闭
    async fn enter_authenticated(
        &mut self,
        mut clt_r: BoxAsyncRead,
        mut clt_w: BoxAsyncWrite,
        mut ups_r: BoxAsyncRead,
        mut ups_w: BoxAsyncWrite,
        mut relay_buf: ImapRelayBuf,
    ) -> ServerTaskResult<()> {
        match self
            .relay_authenticated(
                &mut clt_r,
                &mut clt_w,
                &mut ups_r,
                &mut ups_w,
                &mut relay_buf,
            )
            .await?
        {
            CloseReason::Client => {
                self.handle_client_logout(&mut clt_w, &mut ups_r, &mut relay_buf.rsp_recv_buf)
                    .await?;
                let _ = ups_w.shutdown().await;
                let _ = clt_w.shutdown().await;
                Ok(())
            }
            CloseReason::Server => {
                self.mark_close_by_server();
                let _ = ups_w.shutdown().await;
                let _ = clt_w.shutdown().await;
                Ok(())
            }
            CloseReason::Local(e) => {
                self.start_server_logout(&mut ups_r, &mut ups_w, &mut relay_buf.rsp_recv_buf)
                    .await;
                Err(e)
            }
        }
    }
}
