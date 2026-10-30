/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! HTTP CONNECT 隧道模式下的 FTP 控制连接检测。
//!
//! 本模块处理 HTTP CONNECT 模式下的 FTP 控制连接检测。
//! 上传命令（STOR/APPE）会被识别并写入全局状态，供后续数据连接建立时做 ICAP 审计；
//! 遇到 AUTH TLS（或隐式 FTPS）时标记域名并切换到 TLS 拦截状态机（FTPS MITM）。
//! 与原生 FTP 代理不同：这里不重写 PASV 响应，客户端直接连通 FTP 服务器。

use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_io_ext::{IdleInterval, OnceBufReader, StreamCopyConfig};
use g3_slog_types::{LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use crate::config::server::ServerConfig;
use crate::inspect::{
    BoxAsyncRead, BoxAsyncWrite, StartTlsProtocol, StreamInspectContext, StreamInspection,
    StreamTransitTask,
};
use crate::log::task::TaskEvent;
use crate::serve::ftp_proxy::ctl_common::{
    is_auth_tls_command, is_upload_command, read_ftp_response,
};
use crate::serve::ftp_proxy::upload_state::get_ftp_upload_state;
use crate::serve::{ServerTaskError, ServerTaskResult};

// 记录一条 FTP 拦截日志，自动附带会话公共字段（任务 id、检测深度、源站地址）。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "FtpConnection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
            );
        }
    };
}

/// FTP 控制连接的四条 IO 半端：客户端读/写、源站读（带一次性预读缓冲）/写。
struct FtpIo {
    pub(crate) clt_r: BoxAsyncRead,
    pub(crate) clt_w: BoxAsyncWrite,
    pub(crate) ups_r: OnceBufReader<BoxAsyncRead>,
    pub(crate) ups_w: BoxAsyncWrite,
}

/// FTP 控制连接拦截对象：在 HTTP CONNECT 隧道上逐条命令中继并识别上传/TLS 升级。
pub(crate) struct FtpInterceptObject<SC: ServerConfig> {
    io: Option<FtpIo>,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    /// 本连接是否来自 TLS 拦截（FTPS MITM）升级之后
    from_starttls: bool,
}

/// [`relay_control_channel`] 的退出动作。
enum FtpNextAction {
    /// 控制连接上观察到 AUTH TLS 成功（234），携带原始 IO 交给上层切换 TLS 拦截状态机。
    StartTls {
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    },
    /// 控制连接自然结束（EOF 或读写错误）。
    Finish,
}

impl<SC: ServerConfig> FtpInterceptObject<SC> {
    /// 创建拦截对象；此时 IO 尚未注入（`io` 为 None），需后续调用 [`set_io`] 填充。
    pub(crate) fn new(ctx: StreamInspectContext<SC>, upstream: UpstreamAddr) -> Self {
        FtpInterceptObject {
            io: None,
            ctx,
            upstream,
            from_starttls: false,
        }
    }

    /// 标记本控制连接建立于 FTPS（TLS 拦截）之上。
    pub(crate) fn set_from_starttls(&mut self) {
        self.from_starttls = true;
    }

    /// 注入四条 IO 半端，供 [`intercept`] 消费。
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) {
        let io = FtpIo {
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
                "intercept_type" => "FtpConnection",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
            );
        }
    }

    /// FTP 检测动作策略：当前恒定拦截（HTTP CONNECT 隧道下无法做内容级旁路判定）。
    fn ftp_inspect_action(&self) -> ProtocolInspectAction {
        ProtocolInspectAction::Intercept
    }
}

impl<SC: ServerConfig> StreamTransitTask for FtpInterceptObject<SC> {
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
        self.log_partial_shutdown(TaskEvent::ClientShutdown)
    }

    fn log_upstream_shutdown(&self) {
        self.log_partial_shutdown(TaskEvent::UpstreamShutdown)
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

    fn user(&self) -> Option<&crate::auth::User> {
        self.ctx.user()
    }
}

impl<SC> FtpInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// FTP 拦截总入口：依据策略分发到拦截/旁路/阻断/绕行。
    /// 返回 `Some(StreamInspection)` 表示需切换到其它检测状态机（如 StartTls），
    /// `None` 表示会话已在本状态机内处理完毕。
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let r = match self.ftp_inspect_action() {
            ProtocolInspectAction::Intercept => self.do_intercept().await,
            ProtocolInspectAction::Bypass => self.do_bypass().await.map(|_| None),
            ProtocolInspectAction::Block => self.do_block().await.map(|_| None),
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await.map(|_| None),
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

    /// 旁路：不做协议解析，直接双向透明中继。
    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let FtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    /// 阻断：关闭源站写端，向客户端回 421 服务不可用后终止任务。
    async fn do_block(&mut self) -> ServerTaskResult<()> {
        let FtpIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        clt_w
            .write_all(b"421 Service not available\r\n")
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        clt_w
            .shutdown()
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        Err(ServerTaskError::InternalAdapterError(anyhow!(
            "ftp blocked by inspection policy"
        )))
    }

    /// QUIC 绕行：FTP 暂无独立的绕行实现，退化为旁路。
    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        self.do_bypass().await
    }

    /// 拦截主流程：中继控制连接直到结束或需要 TLS 升级。
    /// 升级时若无 MITM 配置则直接结束（返回 `None`），不再回退透明中继，
    /// 因为客户端即将开始 TLS 握手，明文转发无意义。
    async fn do_intercept(&mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let FtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        match self
            .relay_control_channel(clt_r, clt_w, ups_r, ups_w)
            .await?
        {
            FtpNextAction::Finish => Ok(None),
            // AUTH TLS 成功：把 IO 交给 TLS 拦截状态机做 FTPS MITM
            FtpNextAction::StartTls {
                clt_r,
                clt_w,
                ups_r,
                ups_w,
            } => {
                if let Some(tls_interception) = self.ctx.tls_interception() {
                    let mut start_tls_obj = crate::inspect::start_tls::StartTlsInterceptObject::new(
                        self.ctx.clone(),
                        self.upstream.clone(),
                        tls_interception,
                        StartTlsProtocol::Ftp,
                    );
                    // StartTls 需要普通 BoxAsyncRead，故将 OnceBufReader 再装箱传入
                    start_tls_obj.set_io(clt_r, clt_w, Box::new(ups_r), ups_w);
                    Ok(Some(StreamInspection::StartTls(start_tls_obj)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// 通过 HTTP CONNECT 隧道中继 FTP 控制连接。
    /// 上传命令（STOR/APPE）会被标记到全局状态，供随后的数据连接做 ICAP 审计。
    ///
    /// 与原生 FTP 代理的关键差异：
    /// - 不重写 PASV 响应（客户端直连 FTP 服务器）
    /// - 上传命令在全局状态中标记，供数据连接检测使用
    async fn relay_control_channel(
        &self,
        clt_r: BoxAsyncRead,
        mut clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) -> ServerTaskResult<FtpNextAction> {
        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut ups_reader = ups_r;
        let mut ups_writer = ups_w;
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        let mut ups_buf = vec![0u8; 2048];

        const MAX_LINE_LENGTH: usize = 8192;

        let client_ip = self.ctx.task_notes.client_addr.ip();
        let ftp_server_ip = self.ctx.connect_notes.server_addr.ip();

        // 无论隐式 FTPS（990 端口）还是显式 FTPS（STARTTLS/AUTH TLS），
        // 都先按 (客户端IP, 服务器IP) 标记域名，数据连接建立时据此识别是否需 TLS 拦截
        let domain = match self.upstream.host() {
            g3_types::net::Host::Domain(d) => d.to_string(),
            g3_types::net::Host::Ip(ip) => ip.to_string(),
        };
        crate::serve::ftp_proxy::upload_state::get_ftp_upload_state().mark_ftps_domain(
            client_ip,
            ftp_server_ip,
            &domain,
        );

        let mut idle_interval = self.idle_check_interval();
        let mut idle_count = 0usize;
        // 用户可自定义空闲上限，缺省用服务器配置
        let max_idle_count = self
            .user()
            .and_then(|u| u.task_max_idle_count())
            .unwrap_or(self.max_idle_count());

        // 双工中继：命令方向按行解析（识别上传/AUTH TLS），响应方向按块透传
        loop {
            clt_line.clear();

            tokio::select! {
                            biased;

                            n = Self::read_line_limited(&mut clt_reader, &mut clt_line, MAX_LINE_LENGTH) => {
                                match n {
                                    Ok(0) => break,
                                    Ok(_n) => {
                                        idle_count = 0;

                                        if is_upload_command(&clt_line) {
                                            // STOR/APPE：解析命令名与路径记入全局上传状态，
                                            // 后续该 IP 对的数据连接将触发 ICAP 上传审计
                                            let cmd_str = std::str::from_utf8(&clt_line)
                                                .map(str::trim)
                                                .unwrap_or("");
                                            let mut parts = cmd_str.split_whitespace();
                                            let cmd_name = parts.next().unwrap_or("STOR").to_string();
                                            let ftp_path = parts.next().unwrap_or("").to_string();

                                            get_ftp_upload_state().mark_upload(
                                                client_ip,
                                                ftp_server_ip,
                                                &cmd_name,
                                                &ftp_path,
                                                0,
                                            );

                                            if ups_writer.write_all(&clt_line).await.is_err() {
                                                break;
                                            }
                                        } else if is_auth_tls_command(&clt_line) {
                                            // AUTH TLS：转发后读源站响应，234 表示可开始 TLS 握手，
                                            // 此时退出循环并把 IO 交给 TLS 拦截状态机
                                            if ups_writer.write_all(&clt_line).await.is_err() {
                                                break;
                                            }
                                            if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                                let _ = clt_w.write_all(&resp).await;
                                                if resp.starts_with(b"234") {
                                                    let clt_r = clt_reader.into_inner();
                                                    let ups_r = ups_reader;
                                                    let ups_w = ups_writer;
                                                    return Ok(FtpNextAction::StartTls {
                                                        clt_r,
                                                        clt_w,
                                                        ups_r,
                                                        ups_w,
                                                    });
                                                }
                                            }
                                        } else if ups_writer.write_all(&clt_line).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            n = ups_reader.read(&mut ups_buf) => {
                                // 源站响应原样转发给客户端，不做解析（数据通道信息由全局状态跟踪）
                                match n {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        idle_count = 0;
                                        if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            _ = idle_interval.tick() => {
                                idle_count += 1;

                                // 每个空闲周期复查用户封禁，支持运行中熔断
                                if let Some(user) = self.user() && (user.is_blocked()) {

                                    return Err(ServerTaskError::CanceledAsUserBlocked);
            }

                                if idle_count >= max_idle_count {
                                    return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                                }

                                if self.quit_policy().force_quit() {
                                    return Err(ServerTaskError::CanceledAsServerQuit)
                                }
                            }
                        }
        }

        Ok(FtpNextAction::Finish)
    }

    /// 带长度上限的按行读取（以 '\n' 结尾）：超限返回 InvalidData 错误，
    /// 防止恶意 FTP 客户端用超长命令行耗尽内存。返回实际读取的字节数，EOF 时为已读部分长度。
    async fn read_line_limited<R>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        max_len: usize,
    ) -> Result<usize, std::io::Error>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        let mut total = 0usize;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(total);
            }

            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if total + take > max_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "FTP line too long",
                    ));
                }
                buf.extend_from_slice(&available[..take]);
                reader.consume(take);
                return Ok(total + take);
            }

            let avail_len = available.len();
            if total + avail_len > max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FTP line too long",
                ));
            }
            buf.extend_from_slice(available);
            reader.consume(avail_len);
            total += avail_len;
        }
    }
}
