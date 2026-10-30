/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/2 源站内容拦截的连接级状态机入口。
//!
//! [`H2InterceptObject`] 同时以 h2 客户端身份与源站握手、以 h2 服务端身份与
//! 客户端握手，然后按 [`StreamInspectContext`] 给出的检测动作进入四条路径之一：
//! 拦截（逐流分发到 [`stream`]，再由 connect/forward 子模块处理单流）、旁路
//! （不解析帧直接转发）、绕行（detour）或阻断。本文件只处理连接级事件：接受
//! 新流、上游连接关闭、PING 任务启停、空闲计数、用户封锁与服务退出检查。

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use async_recursion::async_recursion;
use bytes::Bytes;
use h2::{Reason, server::Connection};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::{Protocol, ProtocolInspectAction};
use g3_h2::H2BodyTransfer;
use g3_io_ext::{IdleInterval, OnceBufReader, StreamCopyConfig};
use g3_slog_types::{LtUpstreamAddr, LtUuid};
use g3_types::net::{TlsKeyLogBuffer, UpstreamAddr};

#[cfg(feature = "quic")]
use crate::audit::DetourAction;
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::inspect::{
    BoxAsyncRead, BoxAsyncWrite, InterceptionError, StreamInspectContext, StreamTransitTask,
};
use crate::log::task::TaskEvent;
use crate::serve::ServerTaskResult;

mod error;
pub(crate) use error::{H2InterceptionError, H2StreamTransferError};

mod stats;
use stats::H2ConcurrencyStats;

mod stream;

mod ping;
use ping::H2PingTask;

mod connect;
use connect::{H2ConnectTask, H2ExtendedConnectTask};

mod forward;
use forward::H2ForwardTask;

/// 以 "H2Connection" 为拦截类型输出连接级日志，附带任务 ID、检测深度、
/// 目的地址以及子任务总数/存活数等复用字段。未配置检测日志器时不输出。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2Connection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "total_sub_task" => $obj.stats.get_total_task(),
                "alive_sub_task" => $obj.stats.get_alive_task(),
            );
        }
    };
}

/// 整条 H2 拦截连接持有的四向 IO：客户端读/写与源站读/写。
/// 各拦截分支（拦截/旁路/阻断）通过 take() 取出后按需要消费或丢弃。
struct H2InterceptIo {
    /// 客户端方向的字节流读取器（带首次缓冲，保证握手前探测字节可回放）
    clt_r: OnceBufReader<BoxAsyncRead>,
    /// 客户端方向的字节流写入器
    clt_w: BoxAsyncWrite,
    /// 源站方向的字节流读取器
    ups_r: BoxAsyncRead,
    /// 源站方向的字节流写入器
    ups_w: BoxAsyncWrite,
}

/// HTTP/2 连接拦截主状态机：一条被检测的 H2 连接对应一个实例。
/// 在 do_intercept 中它会拆出源站侧 h2::client 连接与客户端侧 h2::server
/// 连接，并把每个客户端逻辑流派发给独立子任务处理。
pub(crate) struct H2InterceptObject<SC: ServerConfig> {
    /// 连接双向 IO，进入具体拦截分支时被 take() 走；为 None 表示已消费
    io: Option<H2InterceptIo>,
    /// 检测上下文：审计句柄、任务记录、空闲轮盘、服务配置等
    ctx: StreamInspectContext<SC>,
    /// 存活/累计子任务计数，供空闲判定与日志使用
    stats: Arc<H2ConcurrencyStats>,
    /// 本连接要访问的目的源站地址
    upstream: UpstreamAddr,
    /// TLS 密钥日志缓冲，透传给子任务供 ICAP 解密流量使用
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC: ServerConfig> H2InterceptObject<SC> {
    /// 创建拦截对象，此时 IO 尚未挂载（需后续 set_io 注入）。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upstream: UpstreamAddr,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        let stats = Arc::new(H2ConcurrencyStats::default());
        H2InterceptObject {
            io: None,
            ctx,
            stats,
            upstream,
            keylog_buffer,
        }
    }

    /// 挂载已完成协议探测（H2 preface 已识别）的双向 IO，必须在 intercept 前调用。
    pub(crate) fn set_io(
        &mut self,
        clt_r: OnceBufReader<BoxAsyncRead>,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = H2InterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 记录单侧半关闭事件（客户端或源站），供审计侧还原连接拆除顺序。
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "H2Connection",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
            );
        }
    }
}

// 向通用转发框架（transit_transparent 等）暴露本拦截对象的传输策略与日志钩子。
impl<SC: ServerConfig> StreamTransitTask for H2InterceptObject<SC> {
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

impl<SC> H2InterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 拦截入口：查询本连接（按目的主机）的 H2 检测动作并分发到
    /// 拦截/绕行/旁路/阻断四条路径，最后统一输出成功或失败日志。
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<()> {
        let r = match self.ctx.h2_inspect_action(self.upstream.host()) {
            ProtocolInspectAction::Intercept => self
                .do_intercept()
                .await
                .map_err(|e| InterceptionError::H2(e).into_server_task_error(Protocol::Http2)),
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await,
            ProtocolInspectAction::Bypass => self.do_bypass().await,
            ProtocolInspectAction::Block => self
                .do_block()
                .await
                .map_err(|e| InterceptionError::H2(e).into_server_task_error(Protocol::Http2)),
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

    /// 绕行路径：把连接交给外部检测服务（detour）判定。判定为 Continue 时
    /// 由 detour 侧接管并中继原始字节流；Bypass/Block 则回落到本地旁路/阻断。
    /// 注意 detour 全程不解析 H2 帧，原始连接对它保持透明。
    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        use crate::serve::ServerTaskError;

        // 未配置 detour 客户端时等同旁路
        let Some(client) = self.ctx.audit_handle.stream_detour_client() else {
            return self.do_bypass().await;
        };

        let mut detour_stream = match client.open_detour_stream().await {
            Ok(s) => s,
            Err(e) => {
                // 打不开 detour 流：无法判定，直接向客户端回 GOAWAY 终止会话
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
            Protocol::Http2,
        );

        match detour_ctx.check_detour_action(&mut detour_stream).await {
            Ok(DetourAction::Continue) => {
                let H2InterceptIo {
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
                self.do_block()
                    .await
                    .map_err(|e| InterceptionError::H2(e).into_server_task_error(Protocol::Http2))
            }
            Err(e) => {
                detour_stream.finish();
                self.close_on_detour_error().await;
                Err(ServerTaskError::InternalAdapterError(e))
            }
        }
    }

    /// detour 判定失败时的收尾：与源站方向直接关闭，仅与客户端完成 h2 握手后
    /// 立刻发送 abrupt GOAWAY（INTERNAL_ERROR），让客户端收到明确的会话错误，
    /// 而不是未拆封的原始连接。
    #[cfg(feature = "quic")]
    async fn close_on_detour_error(&mut self) {
        let H2InterceptIo {
            clt_r,
            clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        // 源站侧不再转发任何数据，后台优雅关闭写端即可
        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        let http_config = self.ctx.h2_interception();
        let mut server_builder = h2::server::Builder::new();
        server_builder
            .max_header_list_size(http_config.max_header_list_size)
            .max_concurrent_streams(1)
            .max_frame_size(http_config.max_frame_size())
            .max_send_buffer_size(http_config.max_send_buffer_size);

        // 握手加超时保护；客户端握手失败或超时都静默放弃（错误原因已在上层记录）
        match tokio::time::timeout(
            http_config.client_handshake_timeout,
            server_builder.handshake::<_, Bytes>(tokio::io::join(clt_r, clt_w)),
        )
        .await
        {
            Ok(Ok(mut h2c)) => {
                h2c.abrupt_shutdown(Reason::INTERNAL_ERROR);
                // TODO add timeout
                let _ = poll_fn(|ctx| h2c.poll_closed(ctx)).await;
            }
            Ok(Err(_)) => {}
            Err(_) => {}
        };
    }

    /// 旁路路径：不解析任何 H2 帧，退化为 TCP 级的双向透明转发。
    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let H2InterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断路径：不向源站转发数据（直接关闭上游写端），只与客户端完成 h2
    /// 握手并立即以 HTTP_1_1_REQUIRED 发送 GOAWAY——该错误码约定客户端应
    /// 降级到 HTTP/1.1 重试，便于在 H1 通道上给出更友好的阻断页。
    async fn do_block(&mut self) -> Result<(), H2InterceptionError> {
        let H2InterceptIo {
            clt_r,
            clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        let http_config = self.ctx.h2_interception();
        let mut server_builder = h2::server::Builder::new();
        server_builder
            .max_header_list_size(http_config.max_header_list_size)
            .max_concurrent_streams(1)
            .max_frame_size(http_config.max_frame_size())
            .max_send_buffer_size(http_config.max_send_buffer_size);

        let mut h2c = match tokio::time::timeout(
            http_config.client_handshake_timeout,
            server_builder.handshake::<_, Bytes>(tokio::io::join(clt_r, clt_w)),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(H2InterceptionError::client_handshake_failed(e)),
            Err(_) => return Err(H2InterceptionError::ClientHandshakeTimeout),
        };

        h2c.abrupt_shutdown(Reason::HTTP_1_1_REQUIRED);

        // TODO add timeout
        let _ = poll_fn(|ctx| h2c.poll_closed(ctx)).await;

        // 无论 GOAWAY 是否送达客户端，本连接都以"被阻断"作为最终结论
        Err(H2InterceptionError::ClientConnectionBlocked)
    }

    /// 核心拦截路径：在客户端与源站之间各建立一个 h2 会话，之后进入
    /// 连接级事件循环。客户端的每个新逻辑流都被 spawn 为独立的
    /// [`stream::transfer`] 子任务，实现流级复用与检测。
    /// 标注 #[async_recursion] 是因为更深层的嵌套拦截（如 CONNECT 隧道内
    /// 再解析 H2）会递归回到整条 inspect 流水线。
    #[async_recursion]
    async fn do_intercept(&mut self) -> Result<(), H2InterceptionError> {
        let H2InterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let http_config = self.ctx.h2_interception();
        // 先作为 h2 客户端与源站握手：max_concurrent_streams(0) 表示本代理
        // 不接受源站发起的任何流（服务端推送等）
        let mut client_builder = h2::client::Builder::new();
        client_builder
            .enable_push(false) // server push is deprecated by chrome and nginx
            .max_header_list_size(http_config.max_header_list_size)
            .max_concurrent_streams(0)
            .max_frame_size(http_config.max_frame_size())
            .max_send_buffer_size(http_config.max_send_buffer_size)
            .initial_window_size(http_config.stream_window_size())
            .initial_connection_window_size(http_config.connection_window_size());

        let (h2s, mut h2s_connection) = match tokio::time::timeout(
            http_config.upstream_handshake_timeout,
            client_builder.handshake(tokio::io::join(ups_r, ups_w)),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(H2InterceptionError::upstream_handshake_failed(e)),
            Err(_) => return Err(H2InterceptionError::UpstreamHandshakeTimeout),
        };

        // 启动后台 PING 保活任务；关闭本连接时通过 ping_quit_sender 通知其退出
        let (ping_quit_sender, ping_quit_receiver) = oneshot::channel();
        if let Some(ping) = h2s_connection.ping_pong() {
            let ping_task =
                H2PingTask::new(self.ctx.clone(), self.stats.clone(), self.upstream.clone());
            tokio::spawn(ping_task.into_running(ping, ping_quit_receiver));
        }
        // 代理侧允许客户端并发打开的流数，取源站通告值与本地配置的较小者，
        // 避免建出源站无法接受的流
        let max_concurrent_send_streams =
            u32::try_from(h2s_connection.max_concurrent_send_streams())
                .unwrap_or(u32::MAX)
                .min(http_config.max_concurrent_streams);
        // h2 连接驱动任务只有出错才退出，因此 close 通道只会收到错误值；
        // 正常关闭表现为通道被 drop（Recv 返回 Err）
        let (ups_close_sender, mut ups_close_receiver) = oneshot::channel();
        tokio::spawn(async move {
            if let Err(e) = h2s_connection.await {
                let _ = ups_close_sender.send(e);
            }
        });

        // 再作为 h2 服务端与客户端握手；仅当源站支持扩展 CONNECT 时才向客户端
        // 宣告 :protocol 伪头能力，保证伪协议协商端到端一致
        let mut server_builder = h2::server::Builder::new();
        server_builder
            .max_header_list_size(http_config.max_header_list_size)
            .max_concurrent_streams(max_concurrent_send_streams)
            .max_frame_size(http_config.max_frame_size())
            .max_send_buffer_size(http_config.max_send_buffer_size)
            .initial_window_size(http_config.stream_window_size())
            .initial_connection_window_size(http_config.connection_window_size());
        if h2s.is_extended_connect_protocol_enabled() {
            server_builder.enable_connect_protocol();
        }

        let mut h2c_connection = match tokio::time::timeout(
            http_config.client_handshake_timeout,
            server_builder.handshake(tokio::io::join(clt_r, clt_w)),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(H2InterceptionError::client_handshake_failed(e)),
            Err(_) => return Err(H2InterceptionError::ClientHandshakeTimeout),
        };

        // 连接级事件循环：三个分支按 biased 优先级排列——源站关闭最优先，
        // 其次是客户端开新流，最后才是空闲/策略检查
        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                ups_r = &mut ups_close_receiver => {
                    let _ = ping_quit_sender.send(());
                    return match ups_r {
                        Ok(e) => {
                            // 源站 h2 连接报错：先对客户端优雅 GOAWAY，
                            // 再把错误归类上抛
                            server_graceful_shutdown(h2c_connection).await;
                            if let Some(e) = e.get_io()
                                && e.kind() == std::io::ErrorKind::NotConnected {
                                    return Err(H2InterceptionError::UpstreamConnectionDisconnected);
                                }
                            Err(H2InterceptionError::UpstreamConnectionClosed(e))
                        }
                        Err(_) => {
                            // 发送端被 drop，说明源站连接正常关闭：视为任务成功
                            self.log_upstream_shutdown();
                            server_graceful_shutdown(h2c_connection).await;
                            Ok(())
                        }
                    };
                }
                clt_r = h2c_connection.accept() => {
                    match clt_r {
                        Some(Ok((clt_req, clt_send_rsp))) => {
                            // 客户端打开一个新逻辑流：克隆出流级上下文与 h2 客户端
                            // 句柄，spawn 独立的流转发任务（流级并发在此实现）
                            let h2s = h2s.clone();
                            let ctx = self.ctx.clone();
                            let stats = self.stats.clone();
                            let keylog_buffer = self.keylog_buffer.clone();
                            // 有新活动，重置空闲计数
                            idle_count = 0;
                            stats.add_task();
                            tokio::spawn(async move {
                                stream::transfer(clt_req, clt_send_rsp, h2s, ctx, keylog_buffer).await;
                                stats.del_task();
                            });
                            continue;
                        }
                        Some(Err(e)) => {
                            // 客户端侧 h2 服务端出错：释放 h2s 句柄让所有流随之关闭，
                            // 并停掉 PING 任务
                            drop(h2s);
                            let _ = ping_quit_sender.send(());
                            // accept() 内部已调用过 h2c_connection.poll_closed()

                            // NotConnected 表示客户端直接断开，属正常收尾
                            if let Some(e) = e.get_io()
                                && e.kind() == std::io::ErrorKind::NotConnected {
                                    return Ok(());
                                }
                            return Err(H2InterceptionError::ClientConnectionClosed(e));
                        }
                        None => {
                            // accept() 返回 None：客户端已发 GOAWAY 并关闭连接，
                            // 释放 h2s、停 PING，等源站侧流自然收尾
                            drop(h2s);
                            let _ = ping_quit_sender.send(());
                            self.log_client_shutdown();
                            let _ = poll_fn(|cx| h2c_connection.poll_closed(cx)).await;
                            return Ok(());
                        }
                    }
                }
                n = idle_interval.tick() => {
                    // 空闲检测：仅在所有子任务都不存活时才累计空闲次数，
                    // 连续空闲超过 max_idle_count 即对客户端 abrupt GOAWAY
                    if self.stats.get_alive_task() <= 0 {
                        idle_count += n;

                        if idle_count > self.ctx.max_idle_count {
                            let _ = ping_quit_sender.send(());
                            server_abrupt_shutdown(h2c_connection, Reason::NO_ERROR).await;

                            return Err(H2InterceptionError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        idle_count = 0;
                    }

                    // 周期性检查用户是否被封锁：用 ENHANCE_YOUR_CALM 提示客户端降速
                    if self.ctx.belongs_to_blocked_user() {
                        let _ = ping_quit_sender.send(());
                        server_abrupt_shutdown(h2c_connection, Reason::ENHANCE_YOUR_CALM).await;

                        return Err(H2InterceptionError::CanceledAsUserBlocked);
                    }

                    // 服务被要求强制退出：优雅关闭后以取消错误结束
                    if self.ctx.server_force_quit() {
                        let _ = ping_quit_sender.send(());
                        server_graceful_shutdown(h2c_connection).await;

                        return Err(H2InterceptionError::CanceledAsServerQuit)
                    }

                    // 服务进入下线流程：仅停止接受新流，存量流继续跑完
                    if self.ctx.server_offline() {
                        h2c_connection.graceful_shutdown();
                    }
                }
            }
        }
    }
}

/// 对 h2 服务端会话做优雅关闭（GOAWAY），并拒绝关闭完成前到达的新流。
async fn server_graceful_shutdown<T>(mut h2c: Connection<T, Bytes>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    h2c.graceful_shutdown();
    server_refuse_until_closed(h2c).await;
}

/// 对 h2 服务端会话发 abrupt GOAWAY（带指定错误码），并拒绝剩余新流。
/// 与优雅关闭的区别：已发出的请求也不会再收到响应。
async fn server_abrupt_shutdown<T>(mut h2c: Connection<T, Bytes>, reason: Reason)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    h2c.abrupt_shutdown(reason);
    server_refuse_until_closed(h2c).await;
}

/// GOAWAY 之后继续驱动会话直到底层连接关闭；期间客户端若还开新流，
/// 一律以 REFUSED_STREAM 重置，确保客户端能明确感知失败并重试/降级。
async fn server_refuse_until_closed<T>(mut h2c: Connection<T, Bytes>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(r) = h2c.accept().await {
        match r {
            Ok((_req, mut send_rsp)) => {
                send_rsp.send_reset(Reason::REFUSED_STREAM);
            }
            Err(_) => return,
        }
    }

    let _ = poll_fn(|cx| h2c.poll_closed(cx)).await;
}
