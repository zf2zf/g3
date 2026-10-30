/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 基于 HTTP/1 协议切换（upgrade）的 WebSocket 检测对象。
//!
//! 当客户端经 HTTP/1 `Upgrade: websocket` 握手进入 `Websocket` 检测阶段后，由
//! [`H1WebsocketInterceptObject`] 接管该双向字节流。它读取 `StreamInspectContext`
//! 得出的检测动作（拦截/转接/放行/阻断），并在四条底层异步流（客户端读写、上游
//! 读写）之上完成帧转发或关闭握手。协议切换后的 WebSocket 帧已是端到端的不透明
//! 字节，故本对象对帧本身透明转发，仅在策略要求时注入关闭帧终止会话。

use std::time::Duration;

use anyhow::anyhow;
use tokio::io::AsyncWriteExt;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_io_ext::{IdleInterval, LimitedWriteExt, StreamCopyConfig};
use g3_slog_types::{LtHttpHeaderValue, LtUpstreamAddr, LtUuid};
use g3_types::net::{UpstreamAddr, WebSocketNotes};

use super::{ClientCloseFrame, ServerCloseFrame};
#[cfg(feature = "quic")]
use crate::audit::DetourAction;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamTransitTask};
use crate::log::task::TaskEvent;
use crate::serve::{ServerTaskError, ServerTaskResult};

/// 输出一条 WebSocket 拦截审计日志。
///
/// 统一附带拦截类型、任务 id、检测深度、上游地址以及 WebSocket 握手记录（资源名、
/// Origin、子协议、版本）等上下文字段；仅当上下文启用拦截日志时才实际写日志。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H1Websocket",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "ws_resource_name" => $obj.ws_notes.resource_name(),
                "ws_origin" => $obj.ws_notes.origin().map(LtHttpHeaderValue),
                "ws_sub_protocol" => $obj.ws_notes.sub_protocol().map(LtHttpHeaderValue),
                "ws_version" => $obj.ws_notes.version().map(LtHttpHeaderValue),
            );
        }
    };
}

/// 协议切换完成后持有的四条底层异步流：客户端读/写、上游读/写。
///
/// 采用拆分（split）后的独立读写句柄，使双向转发可并发进行。各方向转发在
/// `transit_transparent` 中会借用这些句柄，故用 `Option` 包裹、由 `take()` 一次性
/// 取出，避免同一句柄被重复移交。
struct H1WebsocketIo {
    pub(crate) clt_r: BoxAsyncRead,
    pub(crate) clt_w: BoxAsyncWrite,
    pub(crate) ups_r: BoxAsyncRead,
    pub(crate) ups_w: BoxAsyncWrite,
}

/// HTTP/1 upgrade 通道的 WebSocket 检测/拦截对象。
///
/// 在 `src/inspect` 检测状态机中对应 `Websocket` 阶段，负责依据策略对已升级的
/// WebSocket 流执行转发或终止。
pub(crate) struct H1WebsocketInterceptObject<SC: ServerConfig> {
    /// 底层 I/O 句柄；尚未建立或已被 `take()` 走时为 `None`。
    io: Option<H1WebsocketIo>,
    /// 检测上下文：提供审计句柄、检测策略查询、日志与空闲检测等资源。
    pub(crate) ctx: StreamInspectContext<SC>,
    /// 上游服务地址，用于查询检测动作与写审计日志。
    upstream: UpstreamAddr,
    /// 协议切换握手阶段记录的 WebSocket 元信息（资源名、Origin、子协议、版本）。
    ws_notes: WebSocketNotes,
}

impl<SC: ServerConfig> H1WebsocketInterceptObject<SC> {
    /// 新建检测对象，此时尚未绑定底层 I/O（`io` 为 `None`）。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upstream: UpstreamAddr,
        ws_notes: WebSocketNotes,
    ) -> Self {
        H1WebsocketInterceptObject {
            io: None,
            ctx,
            upstream,
            ws_notes,
        }
    }

    /// 绑定协议切换后的四条底层流，供后续 `intercept` 转发/关闭时使用。
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = H1WebsocketIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 记录单向半关闭（partial shutdown）事件，任务事件类型由调用方传入。
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "H1Websocket",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
                "ws_resource_name" => self.ws_notes.resource_name(),
                "ws_origin" => self.ws_notes.origin().map(LtHttpHeaderValue),
                "ws_sub_protocol" => self.ws_notes.sub_protocol().map(LtHttpHeaderValue),
                "ws_version" => self.ws_notes.version().map(LtHttpHeaderValue),
            );
        }
    }
}

/// 将本对象适配为通用的流转发任务：向转发引擎提供拷贝配置、空闲检测参数与日志回调。
impl<SC: ServerConfig> StreamTransitTask for H1WebsocketInterceptObject<SC> {
    fn copy_config(&self) -> StreamCopyConfig {
        self.ctx.server_config.limited_copy_config()
    }

    /// 注册到空闲定时器，返回周期性空闲检查间隔。
    fn idle_check_interval(&self) -> IdleInterval {
        self.ctx.idle_wheel.register()
    }

    /// 允许连续空闲的检查次数上限，超出后转发任务视为超时结束。
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

    /// 周期性刷新任务日志的间隔；`None` 表示不做定期刷新。
    fn log_flush_interval(&self) -> Option<Duration> {
        self.ctx.server_config.task_log_flush_interval()
    }

    fn quit_policy(&self) -> &ServerQuitPolicy {
        self.ctx.server_quit_policy.as_ref()
    }

    /// 关联的认证用户；未认证时为 `None`。
    fn user(&self) -> Option<&User> {
        self.ctx.user()
    }
}

impl<SC: ServerConfig> H1WebsocketInterceptObject<SC> {
    /// 检测入口：按上游主机名查询 WebSocket 检测动作并分派到对应处理分支，
    /// 最终依据结果输出"完成"或错误审计日志。返回 `Ok(())` 表示流正常结束。
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<()> {
        let r = match self.ctx.websocket_inspect_action(self.upstream.host()) {
            ProtocolInspectAction::Intercept => self.do_intercept().await,
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await,
            ProtocolInspectAction::Bypass => self.do_bypass().await,
            ProtocolInspectAction::Block => self.do_block().await,
        };
        match r {
            Ok(_) => {
                intercept_log!(self, "finished");
                Ok(())
            }
            Err(e) => {
                intercept_log!(self, "{e}");
                Err(e)
            }
        }
    }

    /// 转接（detour）：将 WebSocket 握手元信息作为负载交给外部审计服务，由其决定
    /// 后续动作——继续（relay 三方转发）、放行（bypass）或阻断（block）。
    ///
    /// 若上下文未配置转接客户端（`stream_detour_client()` 返回 `None`），则退化为
    /// 放行；打开转接流失败或转接决策出错时，向两端注入关闭帧并返回内部适配错误。
    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        let Some(client) = self.ctx.audit_handle.stream_detour_client() else {
            return self.do_bypass().await;
        };

        // 建立到审计服务的转接流；失败即中止，并向客户端/上游发送关闭帧。
        let mut detour_stream = match client.open_detour_stream().await {
            Ok(s) => s,
            Err(e) => {
                self.close_on_detour_error().await;
                return Err(ServerTaskError::InternalAdapterError(e));
            }
        };

        // 组装转接上下文，并把序列化的 WebSocket 握手记录作为负载送给审计服务。
        let mut detour_ctx = client.build_context(
            &self.ctx.server_config,
            &self.ctx.server_quit_policy,
            &self.ctx.idle_wheel,
            &self.ctx.task_notes,
            &self.upstream,
            g3_dpi::Protocol::Websocket,
        );
        detour_ctx.set_payload(self.ws_notes.serialize());

        match detour_ctx.check_detour_action(&mut detour_stream).await {
            Ok(DetourAction::Continue) => {
                // 审计服务要求接管：取出四条本地流，与转接流一起做三方中继转发。
                let H1WebsocketIo {
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
                // 审计服务放行：结束转接流后按普通透明转发继续。
                detour_stream.finish();
                self.do_bypass().await
            }
            Ok(DetourAction::Block) => {
                // 审计服务阻断：结束转接流后走阻断关闭路径。
                detour_stream.finish();
                self.do_block().await
            }
            Err(e) => {
                // 转接决策出错：关闭两端流并向客户端/上游注入关闭帧。
                detour_stream.finish();
                self.close_on_detour_error().await;
                Err(ServerTaskError::InternalAdapterError(e))
            }
        }
    }

    /// 转接出错时的关闭握手：向客户端发送状态码 1011（服务端内部错误）、向上游
    /// 发送状态码 1001（going away），随后各自关闭写方向。上游写入在后台任务中进行，
    /// 以免阻塞客户端侧的关闭。
    #[cfg(feature = "quic")]
    async fn close_on_detour_error(&mut self) {
        const SERVER_CLOSE_BYTES: [u8; 4] = ServerCloseFrame::encode_with_status_code(1011);
        const CLIENT_CLOSE_BYTES: [u8; 8] = ClientCloseFrame::encode_with_status_code(1001);

        let H1WebsocketIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            if ups_w.write_all_flush(&CLIENT_CLOSE_BYTES).await.is_ok() {
                let _ = ups_w.shutdown().await;
            }
        });

        if clt_w.write_all_flush(&SERVER_CLOSE_BYTES).await.is_ok() {
            let _ = clt_w.shutdown().await;
        }
    }

    /// 放行（bypass）：不检查帧内容，取出四条流后做透明双向转发。
    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let H1WebsocketIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断（block）：向客户端与上游各发送状态码 1001 的关闭帧后终止会话，
    /// 返回内部适配错误以表明被检测策略阻断。上游写入同样置于后台任务避免阻塞。
    async fn do_block(&mut self) -> ServerTaskResult<()> {
        const SERVER_CLOSE_BYTES: [u8; 4] = ServerCloseFrame::encode_with_status_code(1001);
        const CLIENT_CLOSE_BYTES: [u8; 8] = ClientCloseFrame::encode_with_status_code(1001);

        let H1WebsocketIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            if ups_w.write_all_flush(&CLIENT_CLOSE_BYTES).await.is_ok() {
                let _ = ups_w.shutdown().await;
            }
        });

        if clt_w.write_all_flush(&SERVER_CLOSE_BYTES).await.is_ok() {
            let _ = clt_w.shutdown().await;
        }
        Err(ServerTaskError::InternalAdapterError(anyhow!(
            "websocket blocked by inspection policy"
        )))
    }

    /// 拦截（intercept）：对协议切换后的 WebSocket 帧做透明双向转发（帧内容不在本
    /// 对象内解析）。当前与放行共用 `transit_transparent`，语义上表示处于检测接管下。
    async fn do_intercept(&mut self) -> ServerTaskResult<()> {
        let H1WebsocketIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }
}
