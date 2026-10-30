/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 裸 TCP 流的协议检测与转发。
//!
//! 这是整条检测流水线的最底层：流尚未被识别为具体应用层协议时，先由本模块
//! 读取首段数据交给 `g3_dpi` 的 `ProtocolInspector` 识别，再按识别结果转移到
//! TLS / HTTP / SMTP / FTP 等更具体的拦截对象，或直接以透明双向拷贝继续转发。
//!
//! 主要类型：
//! - [`StreamTransitTask`]：为各类"仅转发"任务提供统一的双向拷贝/空闲检测框架
//! - [`UnknownStreamTransitTask`]：协议未知/检测超时场景下的转发任务实现
//! - [`transit_with_inspection`]：本模块检测循环的入口
//! - [`StreamInspection::into_loop_inspection`]：驱动整张状态机的总循环

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::{MaybeProtocol, ProtocolInspectionConfig, ProtocolInspector};
use g3_io_ext::{IdleInterval, OptionalInterval, StreamCopy, StreamCopyConfig, StreamCopyError};
use g3_slog_types::LtUuid;
use g3_types::net::UpstreamAddr;

use super::{StreamInspectContext, StreamInspection};
use crate::auth::User;
use crate::config::server::ServerConfig;
use crate::log::task::TaskEvent;
use crate::serve::{ServerTaskError, ServerTaskForbiddenError, ServerTaskResult};

mod object;
pub(crate) use object::StreamInspectObject;

/// 纯转发（无协议语义）任务的公共能力契约。
///
/// 实现者只需提供拷贝配置、日志与空闲/退出策略等参数，即可获得
/// [`StreamTransitTask::transit_transparent`] 等默认方法提供的
/// 双向拷贝、半关闭（single direction closed）后续跑、空闲计数与超时判定逻辑。
pub(crate) trait StreamTransitTask {
    /// 单方向数据拷贝使用的缓冲区与速率限制配置
    fn copy_config(&self) -> StreamCopyConfig;
    /// 空闲检测定时器（使用共享的 timing wheel 注册，避免每条任务一个 timer）
    fn idle_check_interval(&self) -> IdleInterval;
    /// 允许的最大空闲周期数，超过则判定为空闲超时并终止任务
    fn max_idle_count(&self) -> usize;
    /// 记录"客户端方向已关闭"事件日志
    fn log_client_shutdown(&self);
    /// 记录"源站方向已关闭"事件日志
    fn log_upstream_shutdown(&self);
    /// 周期性刷新任务统计日志
    fn log_periodic(&self);
    /// 周期日志的刷新间隔；返回 `None` 表示不输出周期日志
    fn log_flush_interval(&self) -> Option<Duration>;
    /// 服务优雅退出策略，用于判断是否需要强制中断当前转发
    fn quit_policy(&self) -> &ServerQuitPolicy;
    /// 当前任务关联的认证用户；匿名/免认证场景为 `None`。
    /// 用户存在时，其单独配置的 `task_max_idle_count` 会覆盖默认的
    /// [`StreamTransitTask::max_idle_count`]
    fn user(&self) -> Option<&User>;

    /// 以透明方式双向转发客户端与源站之间的字节流，直到任务结束。
    ///
    /// 四个方向的分片在此处组合成两个 [`StreamCopy`] 任务并同时 select，
    /// 任意一方先关闭后不会立即结束整个任务，而是继续等待另一方向把剩余
    /// 数据传完（见 [`StreamTransitTask::transit_transparent2`]）。
    async fn transit_transparent<CR, CW, UR, UW>(
        &self,
        mut clt_r: CR,
        mut clt_w: CW,
        mut ups_r: UR,
        mut ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let copy_config = self.copy_config();
        let clt_to_ups = StreamCopy::new(&mut clt_r, &mut ups_w, &copy_config);
        let ups_to_clt = StreamCopy::new(&mut ups_r, &mut clt_w, &copy_config);

        self.transit_transparent2(clt_to_ups, ups_to_clt).await
    }

    /// 双向同时转发的核心循环。
    ///
    /// 与 [`StreamTransitTask::transit_transparent`] 的区别在于接收已经构建好的
    /// 两个 `StreamCopy`（便于调用方在传入前给某一路加上缓冲读取器等包装）。
    /// 状态转移：
    /// - 客户端→源站方向先读完：关闭源站写端，转入只跑"源站→客户端"的
    ///   [`StreamTransitTask::transit_south`]
    /// - 源站→客户端方向先读完：关闭客户端写端，转入只跑"客户端→源站"的
    ///   [`StreamTransitTask::transit_north`]
    /// - 任一方向出错：立即返回对应的 `ServerTaskError`，尽力把已缓冲数据 flush 出去
    async fn transit_transparent2<CR, CW, UR, UW>(
        &self,
        mut clt_to_ups: StreamCopy<'_, CR, UW>,
        mut ups_to_clt: StreamCopy<'_, UR, CW>,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut idle_interval = self.idle_check_interval();
        // 未配置刷新间隔时 OptionalInterval::tick() 永远挂起，等价于关闭周期日志
        let mut log_interval = self
            .log_flush_interval()
            .map(|log_interval| {
                let interval =
                    tokio::time::interval_at(Instant::now() + log_interval, log_interval);
                OptionalInterval::with(interval)
            })
            .unwrap_or_default();
        let mut idle_count = 0;
        // 用户级配置优先于服务级配置，便于对个别用户放宽/收紧空闲上限
        let max_idle_count = self
            .user()
            .and_then(|u| u.task_max_idle_count())
            .unwrap_or(self.max_idle_count());
        loop {
            tokio::select! {
                r = &mut clt_to_ups => {
                    return match r {
                        Ok(_) => {
                            // 客户端不再发数据：半关闭上游写端，让源站读到 EOF
                            let _ = clt_to_ups.writer().shutdown().await;
                            self.log_client_shutdown();
                            self.transit_south(ups_to_clt, log_interval, idle_interval, idle_count, max_idle_count).await
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ServerTaskError::ClientTcpReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => {
                            // 上游已写不出去，先把反向数据尽量推给客户端再报错
                            let _ = ups_to_clt.write_flush().await;
                            Err(ServerTaskError::UpstreamWriteFailed(e))
                        }
                    };
                }
                r = &mut ups_to_clt => {
                    return match r {
                        Ok(_) => {
                            // 源站不再发数据：半关闭客户端写端，让客户端读到 EOF
                            let _ = ups_to_clt.writer().shutdown().await;
                            self.log_upstream_shutdown();
                            self.transit_north(clt_to_ups, log_interval, idle_interval, idle_count, max_idle_count).await
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ServerTaskError::UpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => {
                            // 客户端已收不了，先把反向数据尽量推给上游再报错
                            let _ = clt_to_ups.write_flush().await;
                            Err(ServerTaskError::ClientTcpWriteFailed(e))
                        }
                    };
                }
                _ = log_interval.tick() => {
                    self.log_periodic();
                }
                n = idle_interval.tick() => {
                    // 只有两个方向同时空闲才累加空闲计数，否则视为仍在活动
                    if clt_to_ups.is_idle() && ups_to_clt.is_idle() {
                        idle_count += n;

                        if let Some(user) = self.user()
                            && user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }

                        if idle_count >= max_idle_count {
                            return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        idle_count = 0;

                        clt_to_ups.reset_active();
                        ups_to_clt.reset_active();
                    }

                    // 空闲检查时也顺带确认用户封禁与服务退出，保证长连接能被及时掐断
                    if let Some(user) = self.user()
                        && user.is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    if self.quit_policy().force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }

    /// 单向续跑阶段（北向）：源站已关闭发送，只需把客户端剩余数据推给上游。
    ///
    /// `idle_interval` / `idle_count` / `max_idle_count` 由
    /// [`StreamTransitTask::transit_transparent2`] 带入，使空闲统计跨阶段累计。
    async fn transit_north<CR, UW>(
        &self,
        mut clt_to_ups: StreamCopy<'_, CR, UW>,
        mut log_interval: OptionalInterval,
        mut idle_interval: IdleInterval,
        mut idle_count: usize,
        max_idle_count: usize,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            tokio::select! {
                r = &mut clt_to_ups => {
                    return match r {
                        Ok(_) => {
                            // 客户端数据读完，半关闭上游写端让源站读到 EOF 后正常收尾
                            let _ = clt_to_ups.writer().shutdown().await;
                            Ok(())
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ServerTaskError::ClientTcpReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::UpstreamWriteFailed(e)),
                    };
                }
                _ = log_interval.tick() => {
                    self.log_periodic();
                }
                n = idle_interval.tick() => {
                    // 此刻只剩一个方向，因此只检查它的空闲状态
                    if clt_to_ups.is_idle() {
                        idle_count += n;

                        if let Some(user) = self.user()
                            && user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }

                        if idle_count >= max_idle_count {
                            return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        idle_count = 0;

                        clt_to_ups.reset_active();
                    }

                    if let Some(user) = self.user()
                        && user.is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    if self.quit_policy().force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }

    /// 单向续跑阶段（南向）：客户端已关闭发送，只需把上游剩余数据回吐给客户端。
    ///
    /// 与 [`StreamTransitTask::transit_north`] 方向相反，同样继承上一阶段的空闲计数。
    async fn transit_south<CW, UR>(
        &self,
        mut ups_to_clt: StreamCopy<'_, UR, CW>,
        mut log_interval: OptionalInterval,
        mut idle_interval: IdleInterval,
        mut idle_count: usize,
        max_idle_count: usize,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        loop {
            tokio::select! {
                r = &mut ups_to_clt => {
                    return match r {
                        Ok(_) => {
                            // 上游数据读完，半关闭客户端写端通知会话结束
                            let _ = ups_to_clt.writer().shutdown().await;
                            Ok(())
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ServerTaskError::UpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::ClientTcpWriteFailed(e)),
                    };
                }
                _ = log_interval.tick() => {
                    self.log_periodic();
                }
                n = idle_interval.tick() => {
                    // 此刻只剩一个方向，因此只检查它的空闲状态
                    if ups_to_clt.is_idle() {
                        idle_count += n;

                        if let Some(user) = self.user()
                            && user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }

                        if idle_count >= max_idle_count {
                            return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        idle_count = 0;

                        ups_to_clt.reset_active();
                    }

                    if let Some(user) = self.user()
                        && user.is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    if self.quit_policy().force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }
}

/// 裸 TCP 流检测的入口：装配 [`StreamInspectObject`] 并驱动整条检测循环。
///
/// 入参是已建好连接的客户端读/写半部与源站读/写半部，此处统一装箱成
/// `BoxAsyncRead/BoxAsyncWrite` 以擦除具体传输类型（普通 TCP、Unix socket 等）。
///
/// `explicit_protocol` 用于上游已明确告知协议的场景（显式协议提示），
/// 此时 `ProtocolInspector` 无需嗅探即可按该协议处理；为 `None` 时由 g3_dpi 自行识别。
pub(crate) async fn transit_with_inspection<CR, CW, UR, UW, SC>(
    clt_r: CR,
    clt_w: CW,
    ups_r: UR,
    ups_w: UW,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    explicit_protocol: Option<MaybeProtocol>,
) -> ServerTaskResult<()>
where
    CR: AsyncRead + Send + Sync + Unpin + 'static,
    CW: AsyncWrite + Send + Sync + Unpin + 'static,
    UR: AsyncRead + Send + Sync + Unpin + 'static,
    UW: AsyncWrite + Send + Sync + Unpin + 'static,
    SC: ServerConfig + Send + Sync + 'static,
{
    // 检测器按连接复用：识别出的协议会写回 inspector 内部状态供后续层读取
    let inspector = ctx.protocol_inspector(explicit_protocol);

    let mut obj = StreamInspectObject::new(ctx, upstream);
    obj.set_io(
        Box::new(clt_r),
        Box::new(clt_w),
        Box::new(ups_r),
        Box::new(ups_w),
    );
    StreamInspection::StreamInspect(obj)
        .into_loop_inspection(inspector)
        .await
}

/// 协议识别落到"无法归类"分支的原因，仅用于拦截日志归因。
enum InspectStatus {
    /// 识别出了协议，但该协议没有对应的拦截实现，按 bypass 转发
    Bypass,
    /// DPI 采样数据不足以判定协议（识别结果为 `Protocol::Unknown`）
    Unknown,
    /// 在检测超时窗口内没有读到足够的首段数据（识别结果为 `Protocol::Timeout`）
    Timeout,
}

impl InspectStatus {
    /// 转换成日志中输出的稳定字符串标识
    fn as_str(&self) -> &'static str {
        match self {
            InspectStatus::Bypass => "Bypass",
            InspectStatus::Unknown => "Unknown",
            InspectStatus::Timeout => "Timeout",
        }
    }
}

/// "协议无法确定"场景下的转发任务：不做任何协议解析，只做双向拷贝。
///
/// 它借用检测上下文（而非持有），因此在转发期间 `ctx` 仍可被上层用于日志与统计。
struct UnknownStreamTransitTask<'a, SC: ServerConfig> {
    ctx: &'a StreamInspectContext<SC>,
    inspect_status: InspectStatus,
}

impl<SC: ServerConfig> UnknownStreamTransitTask<'_, SC> {
    /// 记录半关闭事件：说明当前是哪一侧先结束，以及协议识别为何没有落地
    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "TransitUnknown",
                "inspect_status" => self.inspect_status.as_str(),
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
            );
        }
    }
}

/// 转发参数全部取自检测上下文：使用服务级的限速拷贝配置与共享空闲定时器。
impl<SC: ServerConfig> StreamTransitTask for UnknownStreamTransitTask<'_, SC> {
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
        // TODO 协议未知场景暂无周期统计日志可输出
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

impl<SC> StreamInspectContext<SC>
where
    SC: ServerConfig,
{
    /// 协议检测配置（缓冲区大小、各类超时、最大检测深度等），来自审计句柄
    #[inline]
    fn protocol_inspection(&self) -> &ProtocolInspectionConfig {
        self.audit_handle.protocol_inspection()
    }

    /// 是否已达最大嵌套检测层数。
    ///
    /// 每完成一层检测 `inspection_depth` 递增；超过配置上限后不再继续识别新协议，
    /// 防止 STARTTLS → TLS → HTTP → CONNECT → … 之类的无限嵌套检测消耗资源。
    #[inline]
    fn skip_next_inspection(&self) -> bool {
        self.inspection_depth >= self.protocol_inspection().max_depth()
    }

    /// 以"协议未知"状态透明转发。
    ///
    /// 若用户策略禁止未知协议（常见于合规要求严格的租户），直接以
    /// `ProtoBanned` 拒绝，而不是放行一条无法审计的流量。
    pub(super) async fn transit_inspect_unknown<CR, CW, UR, UW>(
        &self,
        clt_r: CR,
        clt_w: CW,
        ups_r: UR,
        ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // 匿名流量没有用户级策略可查，只在有认证用户时做协议封禁判定
        if let Some(user_ctx) = &self.task_notes.user_ctx
            && user_ctx.user.audit().prohibit_unknown_protocol
        {
            user_ctx.forbidden_stats.add_proto_banned();
            return Err(ServerTaskError::ForbiddenByRule(
                ServerTaskForbiddenError::ProtoBanned,
            ));
        }

        let task = UnknownStreamTransitTask {
            ctx: self,
            inspect_status: InspectStatus::Unknown,
        };
        task.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 以"检测超时"状态透明转发。
    ///
    /// 与 [`StreamInspectContext::transit_inspect_unknown`] 的区别仅在归因：
    /// 这里是首段数据在检测窗口内迟迟没有到达，DPI 无法给出结论。
    /// 同样受用户级 `prohibit_timeout_protocol` 策略约束。
    pub(super) async fn transit_inspect_timeout<CR, CW, UR, UW>(
        &self,
        clt_r: CR,
        clt_w: CW,
        ups_r: UR,
        ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if let Some(user_ctx) = &self.task_notes.user_ctx
            && user_ctx.user.audit().prohibit_timeout_protocol
        {
            user_ctx.forbidden_stats.add_proto_banned();
            return Err(ServerTaskError::ForbiddenByRule(
                ServerTaskForbiddenError::ProtoBanned,
            ));
        }

        let task = UnknownStreamTransitTask {
            ctx: self,
            inspect_status: InspectStatus::Timeout,
        };
        task.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 以"绕过检测"状态透明转发：协议已识别但当前无对应拦截实现
    /// （或该协议的检测未开启），因此不再检查用户级协议封禁策略。
    pub(super) async fn transit_inspect_bypass<CR, CW, UR, UW>(
        &self,
        clt_r: CR,
        clt_w: CW,
        ups_r: UR,
        ups_w: UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let task = UnknownStreamTransitTask {
            ctx: self,
            inspect_status: InspectStatus::Bypass,
        };
        task.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }
}

impl<SC> StreamInspection<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 驱动整条源站内容检测流水线的状态机循环。
    ///
    /// 每一轮处理当前 `StreamInspection` 变体：要么终结任务（`return`）、
    /// 要么产出新的检测对象继续下一轮（`obj = ...`）、要么整条链路完成（`break`）。
    ///
    /// `inspector` 在轮次之间复用，因此每次跨协议转移都必须显式调整它的状态：
    /// - 进入 TLS 拦截后（内层已是 TLS 记录层）需 `set_no_explicit_ssl`，
    ///   告知 DPI 不要再期待"明文里出现 SSL"这类显式升级信号
    /// - 回到明文协议前需 `reset_state` / `unset_no_explicit_ssl`，
    ///   否则 DPI 会残留上一层的识别结果
    pub(crate) async fn into_loop_inspection(
        self,
        mut inspector: ProtocolInspector,
    ) -> ServerTaskResult<()> {
        let mut obj = self;

        loop {
            match obj {
                // 协议未知：直接透明转发，是大多数分支的最终落点
                StreamInspection::StreamUnknown(stream) => {
                    return stream.transit_inspect_unknown().await;
                }
                StreamInspection::StreamInspect(stream) => {
                    // 嵌套层数超上限则放弃继续识别，按未知协议转发以免无限递归
                    if stream.ctx.skip_next_inspection() {
                        return stream.transit_inspect_unknown().await;
                    }

                    obj = stream.transit_with_inspection(&mut inspector).await?;
                    // 明文裸流上不再存在 STARTTLS 之类显式升级协商的预期
                    inspector.unset_no_explicit_ssl();
                }
                StreamInspection::TlsModern(tls) => {
                    let result = tls.intercept(&mut inspector).await;
                    obj = result?;
                    // TLS 卸载后内层是明文协议，重置识别器并允许再次解析内层协议
                    inspector.reset_state();
                    inspector.set_no_explicit_ssl();
                }
                #[cfg(feature = "vendored-tongsuo")]
                StreamInspection::TlsTlcp(tlcp) => {
                    obj = tlcp.intercept(&mut inspector).await?;
                    inspector.reset_state();
                    inspector.set_no_explicit_ssl();
                }
                StreamInspection::StartTls(start_tls) => {
                    obj = start_tls.intercept().await?;
                    // no need to reset inspector state as the protocol should be known
                    // （STARTTLS 后的内层协议已由外层判定，无需重新嗅探）
                }
                StreamInspection::H1(h1) => match h1.intercept().await? {
                    // HTTP 拦截可能派生出新的连接/协议（如 CONNECT 隧道、升级为 WebSocket）
                    Some(new_obj) => {
                        obj = new_obj;
                        inspector.reset_state();
                        inspector.unset_no_explicit_ssl();
                    }
                    // 请求处理完毕，整条任务正常结束
                    None => break,
                },
                // HTTP/2 与 WebSocket 自带完整的会话生命周期，直接终结
                StreamInspection::H2(h2) => {
                    return h2.intercept().await;
                }
                StreamInspection::Websocket(websocket) => {
                    return websocket.intercept().await;
                }
                StreamInspection::Smtp(smtp) => match smtp.intercept().await? {
                    Some(new_obj) => {
                        obj = new_obj;
                        // no need to reset inspector state as the protocol should be known
                        // （邮件协议后续内层协议已知，沿用当前识别器状态）
                    }
                    None => break,
                },
                StreamInspection::Imap(imap) => match imap.intercept().await? {
                    Some(new_obj) => {
                        obj = new_obj;
                        // no need to reset inspector state as the protocol should be known
                        // （同 SMTP：内层协议已知，无需重新嗅探）
                    }
                    None => break,
                },
                StreamInspection::Ftp(ftp) => match ftp.intercept().await? {
                    // FTP 控制通道可触发 STARTTLS 或数据通道检测
                    Some(new_obj) => {
                        obj = new_obj;
                    }
                    None => break,
                },
                StreamInspection::FtpUploadData(ftp_upload) => {
                    // 数据通道只用于内容检查，检查完即结束，不再产生新状态
                    ftp_upload.intercept().await?;
                    break;
                }
                // 检测链已终止且已把数据转发完毕
                StreamInspection::End => break,
            }
        }

        Ok(())
    }
}
