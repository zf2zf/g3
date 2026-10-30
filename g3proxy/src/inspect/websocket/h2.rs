/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 基于 HTTP/2 的 WebSocket 检测对象。
//!
//! WebSocket 也可经由 HTTP/2 extended CONNECT 建立，此时双向数据以 HTTP/2 流
//! （`RecvStream`/`SendStream`）而非裸 TCP 字节承载。[`H2WebsocketInterceptObject`]
//! 在 `src/inspect` 检测状态机处于 `Websocket` 阶段时接管这条流，依据检测动作
//! 完成转发（经 `H2StreamReader`/`H2StreamWriter` 适配为通用异步读写流）、转接中继
//! 或注入关闭帧终止会话。

use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use h2::{RecvStream, SendStream};

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_h2::{H2StreamReader, H2StreamWriter};
use g3_io_ext::{IdleInterval, StreamCopyConfig};
use g3_slog_types::{LtHttpHeaderValue, LtUpstreamAddr, LtUuid};
use g3_types::net::{UpstreamAddr, WebSocketNotes};

use super::{ClientCloseFrame, ServerCloseFrame};
#[cfg(feature = "quic")]
use crate::audit::DetourAction;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{StreamInspectContext, StreamTransitTask};
use crate::log::task::TaskEvent;
use crate::serve::{ServerTaskError, ServerTaskResult};

/// 输出一条 H2 WebSocket 拦截审计日志。
///
/// 与 HTTP/1 版本同构，统一附带拦截类型、任务 id、检测深度、上游地址及 WebSocket
/// 握手记录等字段；仅当上下文启用拦截日志时才实际写日志。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2Websocket",
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

/// HTTP/2 通道的 WebSocket 检测/拦截对象。
///
/// I/O 句柄直接由 `intercept` 以参数传入（HTTP/2 流本身可独立读写），故这里无需
/// 像 HTTP/1 版本那样用 `Option` 字段预先持有。
pub(crate) struct H2WebsocketInterceptObject<SC: ServerConfig> {
    /// 检测上下文：提供审计句柄、检测策略查询、日志与空闲检测等资源。
    ctx: StreamInspectContext<SC>,
    /// 上游服务地址，用于查询检测动作与写审计日志。
    upstream: UpstreamAddr,
    /// 协议切换握手阶段记录的 WebSocket 元信息（资源名、Origin、子协议、版本）。
    ws_notes: WebSocketNotes,
}

impl<SC: ServerConfig> H2WebsocketInterceptObject<SC> {
    /// 新建检测对象；I/O 流在调用 `intercept` 时再传入。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upstream: UpstreamAddr,
        ws_notes: WebSocketNotes,
    ) -> Self {
        H2WebsocketInterceptObject {
            ctx,
            upstream,
            ws_notes,
        }
    }

    /// 记录单向半关闭（partial shutdown）事件，任务事件类型由调用方传入。
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "H2Websocket",
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
impl<SC: ServerConfig> StreamTransitTask for H2WebsocketInterceptObject<SC> {
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

impl<SC: ServerConfig> H2WebsocketInterceptObject<SC> {
    /// 检测入口：按上游主机名查询检测动作并分派到对应分支，随后依据结果输出
    /// "完成"或错误审计日志。HTTP/2 流的收尾由 h2 层负责，故此处不返回 `Result`。
    pub(crate) async fn intercept(
        mut self,
        clt_r: RecvStream,
        clt_w: SendStream<Bytes>,
        ups_r: RecvStream,
        ups_w: SendStream<Bytes>,
    ) {
        let r = match self.ctx.websocket_inspect_action(self.upstream.host()) {
            ProtocolInspectAction::Intercept => self.do_intercept(clt_r, clt_w, ups_r, ups_w).await,
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour(clt_r, clt_w, ups_r, ups_w).await,
            ProtocolInspectAction::Bypass => self.do_bypass(clt_r, clt_w, ups_r, ups_w).await,
            ProtocolInspectAction::Block => self.do_block(clt_w, ups_w).await,
        };
        match r {
            Ok(_) => {
                intercept_log!(self, "finished");
            }
            Err(e) => {
                intercept_log!(self, "{e}");
            }
        }
    }

    /// 转接（detour）：把 WebSocket 握手元信息交给外部审计服务，按其决策继续三方
    /// 中继、放行或阻断。未配置转接客户端时退化为放行；出错时注入关闭帧并返回错误。
    #[cfg(feature = "quic")]
    async fn do_detour(
        &mut self,
        clt_r: RecvStream,
        clt_w: SendStream<Bytes>,
        ups_r: RecvStream,
        ups_w: SendStream<Bytes>,
    ) -> ServerTaskResult<()> {
        let Some(client) = self.ctx.audit_handle.stream_detour_client() else {
            return self.do_bypass(clt_r, clt_w, ups_r, ups_w).await;
        };

        // 建立到审计服务的转接流；失败即中止并向两端注入关闭帧。
        let mut detour_stream = match client.open_detour_stream().await {
            Ok(s) => s,
            Err(e) => {
                self.close_on_detour_error(clt_w, ups_w);
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
                // 审计服务接管：把四条 HTTP/2 流适配为通用读写流后做三方中继转发。
                let clt_r = H2StreamReader::new(clt_r);
                let clt_w = H2StreamWriter::new(clt_w);
                let ups_r = H2StreamReader::new(ups_r);
                let ups_w = H2StreamWriter::new(ups_w);

                detour_ctx
                    .relay(clt_r, clt_w, ups_r, ups_w, detour_stream)
                    .await
            }
            Ok(DetourAction::Bypass) => {
                // 审计服务放行：结束转接流后按普通透明转发继续。
                detour_stream.finish();
                self.do_bypass(clt_r, clt_w, ups_r, ups_w).await
            }
            Ok(DetourAction::Block) => {
                // 审计服务阻断：结束转接流后走阻断关闭路径。
                detour_stream.finish();
                self.do_block(clt_w, ups_w).await
            }
            Err(e) => {
                // 转接决策出错：关闭转接流并向两端注入关闭帧。
                detour_stream.finish();
                self.close_on_detour_error(clt_w, ups_w);
                Err(ServerTaskError::InternalAdapterError(e))
            }
        }
    }

    /// 转接出错时的关闭握手：向客户端发送状态码 1011（服务端内部错误）、向上游
    /// 发送状态码 1001（going away）。这里以 `end_stream=true` 直接关闭对应 HTTP/2 流。
    #[cfg(feature = "quic")]
    fn close_on_detour_error(
        &mut self,
        mut clt_w: SendStream<Bytes>,
        mut ups_w: SendStream<Bytes>,
    ) {
        const SERVER_CLOSE_BYTES: [u8; 4] = ServerCloseFrame::encode_with_status_code(1011);
        const CLIENT_CLOSE_BYTES: [u8; 8] = ClientCloseFrame::encode_with_status_code(1001);

        let _ = ups_w.send_data(Bytes::from_static(&CLIENT_CLOSE_BYTES), true);
        let _ = clt_w.send_data(Bytes::from_static(&SERVER_CLOSE_BYTES), true);
    }

    /// 放行（bypass）：将 HTTP/2 流适配为通用读写流后做透明双向转发。
    async fn do_bypass(
        &mut self,
        clt_r: RecvStream,
        clt_w: SendStream<Bytes>,
        ups_r: RecvStream,
        ups_w: SendStream<Bytes>,
    ) -> ServerTaskResult<()> {
        let clt_r = H2StreamReader::new(clt_r);
        let clt_w = H2StreamWriter::new(clt_w);
        let ups_r = H2StreamReader::new(ups_r);
        let ups_w = H2StreamWriter::new(ups_w);

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断（block）：向客户端与上游各发送状态码 1001 的关闭帧（并结束对应流），
    /// 随后返回内部适配错误以表明被检测策略阻断。
    async fn do_block(
        &mut self,
        mut clt_w: SendStream<Bytes>,
        mut ups_w: SendStream<Bytes>,
    ) -> ServerTaskResult<()> {
        const SERVER_CLOSE_BYTES: [u8; 4] = ServerCloseFrame::encode_with_status_code(1001);
        const CLIENT_CLOSE_BYTES: [u8; 8] = ClientCloseFrame::encode_with_status_code(1001);

        let _ = ups_w.send_data(Bytes::from_static(&CLIENT_CLOSE_BYTES), true);
        let _ = clt_w.send_data(Bytes::from_static(&SERVER_CLOSE_BYTES), true);
        Err(ServerTaskError::InternalAdapterError(anyhow!(
            "websocket blocked by inspection policy"
        )))
    }

    /// 拦截（intercept）：对 HTTP/2 通道上的 WebSocket 帧做透明双向转发。当前与
    /// 放行共用 `transit_transparent`，语义上表示处于检测接管下。
    async fn do_intercept(
        &mut self,
        clt_r: RecvStream,
        clt_w: SendStream<Bytes>,
        ups_r: RecvStream,
        ups_w: SendStream<Bytes>,
    ) -> ServerTaskResult<()> {
        let clt_r = H2StreamReader::new(clt_r);
        let clt_w = H2StreamWriter::new(clt_w);
        let ups_r = H2StreamReader::new(ups_r);
        let ups_w = H2StreamWriter::new(ups_w);

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }
}
