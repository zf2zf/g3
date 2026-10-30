/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 邮件协议拦截（MITM）主状态机。
//!
//! [`SmtpInterceptObject`] 是 SMTP 检测流水线的入口：先读取源站问候响应，
//! 再经历发起阶段（EHLO/HELO）、命令转发阶段，并在 MAIL 命令成功后进入
//! 事务（邮件正文传输）阶段，循环直至会话结束。
//! 根据 [`g3_dpi::ProtocolInspectAction`] 的策略结果，可选择拦截、旁路、
//! 阻断或（QUIC 特性下）绕行检测；遇到 STARTTLS 则切换到 TLS 拦截状态机。

use std::time::Duration;

use anyhow::anyhow;
use tokio::io::AsyncWriteExt;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_io_ext::{IdleInterval, LineRecvBuf, OnceBufReader, StreamCopyConfig};
use g3_slog_types::{LtHost, LtUpstreamAddr, LtUuid};
use g3_smtp_proto::command::Command;
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseParser};
use g3_types::net::{Host, UpstreamAddr};

use super::{StartTlsProtocol, StreamTransitTask};
#[cfg(feature = "quic")]
use crate::audit::DetourAction;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamInspection};
use crate::log::task::TaskEvent;
use crate::serve::{ServerTaskError, ServerTaskResult};

mod ext;
use ext::{CommandLineRecvExt, ResponseLineRecvExt, ResponseParseExt};

mod greeting;
use greeting::Greeting;

mod ending;
use ending::{EndQuitServer, EndWaitClient};

mod initiation;
use initiation::{InitializedExtensions, Initiation};

mod forward;
use forward::{Forward, ForwardNextAction};

mod transaction;
use transaction::Transaction;

/// 中继会话复用的行读写缓冲：命令行缓冲（客户端方向）与响应行缓冲（源站方向）。
#[derive(Default)]
struct SmtpRelayBuf {
    cmd_recv_buf: LineRecvBuf<{ Command::MAX_LINE_SIZE }>,
    rsp_recv_buf: LineRecvBuf<{ ResponseParser::MAX_LINE_SIZE }>,
}

// 记录一条 SMTP 拦截日志，自动附带会话公共字段（任务 id、深度、源站、客户端主机、事务数）。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "SmtpConnection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "client_host" => $obj.client_host.as_ref().map(LtHost),
                "transaction_count" => $obj.transaction_count,
            );
        }
    };
}

/// SMTP 会话的四条 IO 半端：客户端读/写、源站读（带一次性预读缓冲）/写。
struct SmtpIo {
    pub(crate) clt_r: BoxAsyncRead,
    pub(crate) clt_w: BoxAsyncWrite,
    pub(crate) ups_r: OnceBufReader<BoxAsyncRead>,
    pub(crate) ups_w: BoxAsyncWrite,
}

/// SMTP 拦截主状态机对象，贯穿 greeting/initiation/forward/transaction/ending 各阶段。
pub(crate) struct SmtpInterceptObject<SC: ServerConfig> {
    io: Option<SmtpIo>,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    from_starttls: bool,
    client_host: Option<Host>,
    transaction_count: usize,
}

impl<SC: ServerConfig> SmtpInterceptObject<SC> {
    /// 创建拦截对象；此时 IO 尚未注入（`io` 为 None），需后续调用 [`set_io`] 填充。
    pub(crate) fn new(ctx: StreamInspectContext<SC>, upstream: UpstreamAddr) -> Self {
        SmtpInterceptObject {
            io: None,
            ctx,
            upstream,
            from_starttls: false,
            client_host: None,
            transaction_count: 0,
        }
    }

    /// 标记本会话是经 STARTTLS 升级而来：升级后问候/发起阶段已完成，可直接进入命令转发循环。
    pub(crate) fn set_from_starttls(&mut self) {
        self.from_starttls = true;
    }

    /// 注入四条 IO 半端，供 [`intercept`] 及各阶段消费。
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) {
        let io = SmtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 记录单侧（客户端或源站）关闭事件日志。
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "SmtpConnection",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
                "client_host" => self.client_host.as_ref().map(LtHost),
            );
        }
    }
}

impl<SC: ServerConfig> StreamTransitTask for SmtpInterceptObject<SC> {
    // 限流复制配置：控制单任务的最大拷贝速率与缓冲区大小。
    fn copy_config(&self) -> StreamCopyConfig {
        self.ctx.server_config.limited_copy_config()
    }

    // 注册空闲检测定时器。
    fn idle_check_interval(&self) -> IdleInterval {
        self.ctx.idle_wheel.register()
    }

    // 连续空闲达到该次数即判定超时。
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
        // TODO
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

impl<SC> SmtpInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// SMTP 拦截总入口：依据审计策略（intercept/detour/bypass/block）分发。
    /// 返回 `Some(StreamInspection)` 表示需切换到其它检测状态机（如 StartTls），
    /// 返回 `None` 表示会话已在本状态机内处理完毕。
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let r = match self.ctx.smtp_inspect_action(self.upstream.host()) {
            ProtocolInspectAction::Intercept => self.do_intercept().await,
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await.map(|_| None),
            ProtocolInspectAction::Bypass => self.do_bypass().await.map(|_| None),
            ProtocolInspectAction::Block => self.do_block().await.map(|_| None),
        };
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

    /// QUIC 绕行：把流量转交给远端检测适配器，由其决定 continue/bypass/block。
    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        let Some(client) = self.ctx.audit_handle.stream_detour_client() else {
            return self.do_bypass().await;
        };

        let mut detour_stream = match client.open_detour_stream().await {
            Ok(s) => s,
            Err(e) => {
                // 绕行流建立失败：向客户端回 500 并关闭连接
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
            g3_dpi::Protocol::Smtp,
        );

        match detour_ctx.check_detour_action(&mut detour_stream).await {
            Ok(DetourAction::Continue) => {
                // 远端放行：拿回原始 IO 做透明中继
                let SmtpIo {
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

    /// 绕行失败时的善后：关闭源站写端，向客户端回 500 内部错误并等待其 QUIT。
    #[cfg(feature = "quic")]
    async fn close_on_detour_error(&mut self) {
        let SmtpIo {
            clt_r,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        let local_ip = self.ctx.task_notes.server_addr.ip();

        if ResponseEncoder::internal_server_error(local_ip)
            .write(&mut clt_w)
            .await
            .is_ok()
        {
            let _ = EndWaitClient::new(local_ip)
                .run_to_end(
                    clt_r,
                    clt_w,
                    self.ctx.smtp_interception().command_wait_timeout,
                )
                .await;
        }
    }

    /// 旁路：不做协议解析，直接双向透明中继。
    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let SmtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断：关闭源站写端，向客户端回 554 本地阻断响应，再等待其发出 QUIT。
    async fn do_block(&mut self) -> ServerTaskResult<()> {
        let SmtpIo {
            clt_r,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        let local_ip = self.ctx.task_notes.server_addr.ip();

        ResponseEncoder::local_service_blocked(local_ip)
            .write(&mut clt_w)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        EndWaitClient::new(local_ip)
            .run_to_end(
                clt_r,
                clt_w,
                self.ctx.smtp_interception().command_wait_timeout,
            )
            .await?;
        Err(ServerTaskError::InternalAdapterError(anyhow!(
            "smtp blocked by inspection policy"
        )))
    }

    /// 拦截核心流程：先中继问候响应，再进入发起阶段和命令转发循环。
    /// `from_starttls` 为真时跳过问候/发起阶段，直接进入命令转发。
    async fn do_intercept(&mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let SmtpIo {
            clt_r,
            mut clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        if self.from_starttls {
            return self
                .start_initiation(clt_r, clt_w, ups_r.into_inner(), ups_w)
                .await;
        }

        let interception_config = self.ctx.smtp_interception();
        let local_ip = self.ctx.task_notes.server_addr.ip();

        // 阶段一：问候（greeting）——源站先主动发送 220/421 响应，解析并记录源站主机名
        let mut greeting = Greeting::new(local_ip);
        let ups_r = match greeting
            .relay(ups_r, &mut clt_w, interception_config.greeting_timeout)
            .await
        {
            Ok(ups_r) => ups_r,
            Err(e) => {
                // 问候失败：尽量向客户端补发 421 不可用响应再终止
                greeting.reply_no_service(&e, &mut clt_w).await;
                return Err(e.into());
            }
        };
        let (code, host) = greeting.into_parts();
        self.upstream.set_host(host);
        if code == ReplyCode::NO_SERVICE {
            // 源站直接返回 421（服务不可用）：单向关闭源站，本地等待客户端 QUIT
            let quit_wait_timeout = interception_config.quit_wait_timeout;
            tokio::spawn(async move {
                let _ = EndQuitServer::run_to_end(ups_r, ups_w, quit_wait_timeout).await;
            });
            return EndWaitClient::new(local_ip)
                .run_to_end(clt_r, clt_w, interception_config.command_wait_timeout)
                .await
                .map(|_| None);
        }

        self.start_initiation(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 发起阶段 + 命令转发主循环。
    /// 先完成 EHLO/HELO 协商（ [`start_initiation`] 命名源于进入发起阶段），拿到客户端主机名
    /// 与服务端扩展；随后循环转发客户端命令，遇到 MAIL 则进入 [`Transaction`] 事务处理邮件正文，
    /// 遇到 STARTTLS 则切换到 TLS 拦截状态机，遇到 QUIT/反向连接则会话结束。
    async fn start_initiation(
        &mut self,
        mut clt_r: BoxAsyncRead,
        mut clt_w: BoxAsyncWrite,
        mut ups_r: BoxAsyncRead,
        mut ups_w: BoxAsyncWrite,
    ) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let local_ip = self.ctx.task_notes.server_addr.ip();
        let interception_config = self.ctx.smtp_interception();

        // 阶段二：发起（initiation）——EHLO/HELO 交换，解析服务端扩展能力
        let mut initiation = Initiation::new(interception_config, local_ip, self.from_starttls);
        initiation
            .relay(&mut clt_r, &mut clt_w, &mut ups_r, &mut ups_w)
            .await?;
        let (client_host, mut server_ext) = initiation.into_parts();
        self.client_host = Some(client_host);

        let mut relay_buf = SmtpRelayBuf::default();

        // 阶段三：命令转发循环，每轮根据当前扩展能力决定允许的命令
        loop {
            let allow_odmr = server_ext.allow_odmr(interception_config);
            let allow_starttls = server_ext.allow_starttls(self.from_starttls);
            let mut forward =
                Forward::new(interception_config, local_ip, allow_odmr, allow_starttls);
            let next_action = forward
                .relay(
                    &mut relay_buf,
                    &mut clt_r,
                    &mut clt_w,
                    &mut ups_r,
                    &mut ups_w,
                )
                .await?;
            match next_action {
                // 客户端 QUIT：两侧优雅关闭，会话结束
                ForwardNextAction::Quit => {
                    let _ = ups_w.shutdown().await;
                    let _ = clt_w.shutdown().await;
                    return Ok(None);
                }
                // STARTTLS：升级到 TLS 拦截；无 MITM 配置则退化为透明中继
                ForwardNextAction::StartTls => {
                    return if let Some(tls_interception) = self.ctx.tls_interception() {
                        let mut start_tls_obj =
                            crate::inspect::start_tls::StartTlsInterceptObject::new(
                                self.ctx.clone(),
                                self.upstream.clone(),
                                tls_interception,
                                StartTlsProtocol::Smtp,
                            );
                        start_tls_obj.set_io(clt_r, clt_w, ups_r, ups_w);
                        Ok(Some(StreamInspection::StartTls(start_tls_obj)))
                    } else {
                        self.transit_transparent(clt_r, clt_w, ups_r, ups_w)
                            .await
                            .map(|_| None)
                    };
                }
                // 反向连接（ODMR 的 ATRN）：无法内容拦截，转为透明中继
                ForwardNextAction::ReverseConnection => {
                    return self
                        .transit_transparent(clt_r, clt_w, ups_r, ups_w)
                        .await
                        .map(|_| None);
                }
                // EHLO 重新协商：更新服务端扩展能力
                ForwardNextAction::SetExtensions(ext) => server_ext = ext,
                // MAIL 命令成功：进入事务（transaction）阶段处理 RCPT/DATA/BDAT
                ForwardNextAction::MailTransport(param) => {
                    let allow_chunking = server_ext.allow_chunking(interception_config);
                    let allow_burl = server_ext.allow_burl(interception_config);

                    let transaction_id = self.transaction_count;
                    self.transaction_count += 1;
                    let mut transaction = Transaction::new(
                        &self.ctx,
                        transaction_id,
                        local_ip,
                        allow_chunking,
                        allow_burl,
                        param,
                    );
                    transaction
                        .relay(
                            &mut relay_buf,
                            &mut clt_r,
                            &mut clt_w,
                            &mut ups_r,
                            &mut ups_w,
                        )
                        .await?;
                    if transaction.quit() {
                        // 事务中收到 QUIT：结束整个会话
                        let _ = ups_w.shutdown().await;
                        let _ = clt_w.shutdown().await;
                        return Ok(None);
                    }
                }
            }
        }
    }
}
