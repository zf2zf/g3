/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy task: native FTP control/data channel interception.
//!
//! The control channel is relayed verbatim with two special cases:
//!   * PASV / EPSV responses from upstream are rewritten to point at a
//!     local listener we open, so the data channel flows through us.
//!   * STOR / APPE / STOU triggers a data channel that is optionally
//!     audited via ICAP REQMOD before being forwarded upstream.
//!
//! FTP 代理任务：原生 FTP 控制/数据通道拦截。
//!
//! 控制通道基本原样转发，仅两种情况特殊处理：
//!   * 上游返回的 PASV / EPSV 应答会被改写成本机新开的监听地址，
//!     从而把数据通道牵引到本代理内部。
//!   * STOR / APPE / STOU 会触发一条数据通道，其中的内容可选择经
//!     ICAP REQMOD 审计后再转发给上游。

use std::net::Ipv4Addr;
use std::sync::Arc;

use slog::Logger;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use g3_daemon::server::ClientConnectionInfo;
use g3_daemon::stat::task::TcpStreamTaskStats;
use g3_openssl::SslConnector;
use g3_types::net::{OpensslClientConfig, UpstreamAddr};

use super::audit_bridge::{build_audit_context, run_ftp_upload_audit_or_relay};
use super::ctl_common::{
    is_data_channel_command, is_epsv_command, is_pasv_command, is_upload_command,
    parse_pasv_response, read_ftp_response, read_line_limited, rewrite_epsv_response,
    rewrite_pasv_response,
};
use super::stats::{FtpProxyControlTaskAliveGuard, FtpProxyServerStats};
use crate::audit::AuditContext;
use crate::config::server::ftp_proxy::{FtpProxyServerConfig, TlsUpstreamType};
use crate::escape::ArcEscaper;
use crate::module::tcp_connect::{TcpConnectTaskConf, TcpConnectTaskNotes, TlsConnectTaskConf};
use crate::serve::{ServerTaskError, ServerTaskNotes, ServerTaskStage};

/// 控制任务与其派生的数据通道任务共用的上下文。
///
/// 数据通道在独立的任务中处理，因此这里只放可跨任务共享的 `Arc` 句柄，
/// 避免借用主任务的所有权。
pub(crate) struct CommonTaskContext {
    /// 服务器配置（含 `audit_upload` 等开关）
    pub(crate) server_config: Arc<FtpProxyServerConfig>,
    pub(crate) server_stats: Arc<FtpProxyServerStats>,
    /// 退出策略：控制通道空闲 tick 时据此判断是否强制切断存量任务
    pub(crate) _server_quit_policy: Arc<g3_daemon::server::ServerQuitPolicy>,
    /// 空闲检测时间轮
    pub(crate) idle_wheel: Arc<g3_io_ext::IdleWheel>,
    pub(crate) escaper: ArcEscaper,
    /// 客户端连接信息（源地址、目的地址等）
    pub(crate) cc_info: ClientConnectionInfo,
    pub(crate) _task_logger: Option<Logger>,
    /// ICAP REQMOD 客户端；未启用上传审计或未配置审计器时为 None
    pub(crate) icap_client: Option<Arc<g3_icap_client::reqmod::IcapReqmodClient>>,
    /// 上游 TLS 客户端配置，仅在需要加密回源时存在
    pub(crate) tls_upstream_config: Option<Arc<OpensslClientConfig>>,
    /// 回源加密方式：明文 / 显式 FTPS / 隐式 FTPS
    pub(crate) tls_upstream_type: TlsUpstreamType,
}

/// 已协商好、等待客户端来连的被动模式数据通道。
///
/// `listener` 是改写给客户端的本机监听，`upstream_data_addr` 是上游真实的
/// 数据地址（从 PASV/EPSV 应答解析得到）。
struct PendingDataChannel {
    listener: Arc<tokio::net::TcpListener>,
    upstream_data_addr: std::net::SocketAddr,
}

/// 一条 FTP 控制连接的完整任务状态。
pub(crate) struct FtpProxyTask {
    ctx: CommonTaskContext,
    /// 本次会话选定的上游 FTP 服务器
    upstream: UpstreamAddr,
    /// 回源连接的过程记录（用于日志与指标）
    tcp_notes: TcpConnectTaskNotes,
    /// 任务阶段、耗时等通用记录
    task_notes: ServerTaskNotes,
    task_stats: Arc<TcpStreamTaskStats>,
    /// 审计上下文，建连与转发时会被借用上报信息
    _audit_ctx: AuditContext,
    /// 存活计数守卫，drop 时递减
    _task_guard: FtpProxyControlTaskAliveGuard,
    /// 允许连续空闲的 tick 次数，超过则断开
    max_idle_count: usize,
    /// Upstream FTP server IPv4 address, resolved after TCP connection.
    /// Used to resolve EPSV ports (EPSV returns only port; IP from 4-tuple).
    /// 上游 FTP 服务器的 IPv4 地址，取自控制连接的四元组。
    /// EPSV 应答只含端口，IP 需复用控制通道对端地址，故在此缓存。
    /// 取值时机见 `into_running` 开头。
    upstream_ip: std::net::Ipv4Addr,
    /// 任务是否已正式进入转发阶段
    started: bool,
}

impl Drop for FtpProxyTask {
    fn drop(&mut self) {
        if self.started {
            // mirrors other proxy tasks
            // 与其它代理任务保持一致：结束阶段的上报尚未实现，此处留空。
        }
    }
}

impl FtpProxyTask {
    /// 组装任务：解析 ICAP 客户端、登记存活计数，其余字段直接透传。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        server_quit_policy: Arc<g3_daemon::server::ServerQuitPolicy>,
        idle_wheel: Arc<g3_io_ext::IdleWheel>,
        escaper: ArcEscaper,
        cc_info: ClientConnectionInfo,
        upstream: UpstreamAddr,
        audit_ctx: AuditContext,
        task_logger: Option<Logger>,
        tls_upstream_config: Option<Arc<OpensslClientConfig>>,
        tls_upstream_type: TlsUpstreamType,
    ) -> Self {
        // 只有开启上传审计且审计器提供了 ICAP REQMOD 客户端时才建立审计链路
        let icap_client = if server_config.audit_upload {
            audit_ctx
                .handle()
                .and_then(|h| h.icap_reqmod_client().cloned())
                .map(Arc::new)
        } else {
            None
        };

        let task_notes = ServerTaskNotes::new(cc_info.clone(), None, std::time::Duration::ZERO);
        let task_stats = Arc::new(TcpStreamTaskStats::default());
        let task_guard = server_stats.add_control_task();
        let max_idle_count = server_config.task_idle_max_count;

        FtpProxyTask {
            ctx: CommonTaskContext {
                server_config,
                server_stats,
                _server_quit_policy: server_quit_policy,
                idle_wheel,
                escaper,
                cc_info,
                _task_logger: task_logger,
                icap_client,
                tls_upstream_config,
                tls_upstream_type,
            },
            upstream,
            tcp_notes: TcpConnectTaskNotes::default(),
            task_notes,
            task_stats,
            _audit_ctx: audit_ctx,
            _task_guard: task_guard,
            max_idle_count,
            upstream_ip: std::net::Ipv4Addr::UNSPECIFIED,
            started: false,
        }
    }

    /// 任务入口：接管客户端读写两端，回源建连后进入控制通道转发循环。
    pub(crate) async fn into_running<CR, CW>(mut self, clt_r: CR, clt_w: CW)
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        self.started = true;
        self.task_notes.stage = ServerTaskStage::Connecting;

        // Resolve the upstream FTP server IPv4 from tcp_notes.
        // This is needed for EPSV port resolution (EPSV returns port only;
        // the IP is inherited from the control TCP 4-tuple).
        // 从 tcp_notes 中取出上游 IPv4，供 EPSV 端口解析使用。
        // 注意：此处读取发生在回源建连之前，`tcp_notes.next` 尚未填充，
        // 因此 EPSV 场景下通常会退回到 UNSPECIFIED。
        let upstream_ip = self.tcp_notes.next.and_then(|next| {
            if let std::net::SocketAddr::V4(v4) = next {
                Some(*v4.ip())
            } else {
                None
            }
        });

        // Open the upstream control channel. On failure we silently return —
        // the client will see the connection reset.
        // 打开上游控制通道；失败时直接静默返回，客户端会观察到连接被重置。
        let (ups_r, ups_w) = match self.connect_upstream().await {
            Some(conn) => conn,
            None => return,
        };

        self.upstream_ip = upstream_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        self.task_notes.stage = ServerTaskStage::Relaying;
        let _ = self.relay_control(clt_r, clt_w, ups_r, ups_w).await;
    }

    /// Connect to upstream FTP server based on tls_upstream_type.
    /// Returns boxed trait objects to avoid lifetime issues with different stream types.
    /// 按回源加密方式选择具体的建连流程。
    /// 返回装箱的 trait 对象，以规避不同流类型带来的生命周期问题。
    async fn connect_upstream(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        match self.ctx.tls_upstream_type {
            TlsUpstreamType::PlainFtp => self.connect_plain_ftp().await,
            TlsUpstreamType::ExplicitFtps => self.connect_explicit_ftps().await,
            TlsUpstreamType::ImplicitFtps => self.connect_implicit_ftps().await,
        }
    }

    /// Connect to upstream using plain TCP.
    /// 明文 FTP 回源：走标准的 tcp_connect 流程（含日志、指标、故障转移）。
    async fn connect_plain_ftp(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let task_conf = TcpConnectTaskConf {
            upstream: &self.upstream,
        };

        let conn = self
            .ctx
            .escaper
            .tcp_setup_connection(
                &task_conf,
                &mut self.tcp_notes,
                &self.task_notes,
                self.task_stats.clone(),
                &mut self._audit_ctx,
            )
            .await
            .ok()?;

        Some(conn)
    }

    /// Connect to upstream using implicit FTPS (direct TLS connection).
    /// 隐式 FTPS 回源：建连即做 TLS 握手，无 FTP 层的 AUTH 命令。
    async fn connect_implicit_ftps(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let tls_config = self.ctx.tls_upstream_config.as_ref()?;
        let tls_name = self.upstream.host();
        let task_conf = TlsConnectTaskConf {
            tcp: TcpConnectTaskConf {
                upstream: &self.upstream,
            },
            tls_config,
            tls_name,
        };

        let conn = self
            .ctx
            .escaper
            .tls_setup_connection(
                &task_conf,
                &mut self.tcp_notes,
                &self.task_notes,
                self.task_stats.clone(),
                &mut self._audit_ctx,
            )
            .await
            .ok()?;

        // tls_setup_connection returns already split streams (Box<dyn AsyncRead>, Box<dyn AsyncWrite>)
        Some(conn)
    }

    /// Connect to upstream using explicit FTPS (AUTH TLS handshake).
    /// For explicit FTPS, we need to bypass the escaper's stream splitting
    /// because we need to send AUTH TLS before TLS handshake.
    /// 显式 FTPS 回源：先明文建连并发送 AUTH TLS，握手成功后再升级为 TLS。
    /// 因为要在 TLS 之前插入 FTP 命令，这里绕过 escaper 的流拆分逻辑自行建连。
    async fn connect_explicit_ftps(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let tls_config = self.ctx.tls_upstream_config.as_ref()?;
        let upstream = &self.upstream;

        // Step 1: Resolve hostname and connect to upstream port 21 (plain TCP)
        // For explicit FTPS, we need a single stream to send AUTH TLS
        // 步骤 1：解析域名并以明文 TCP 连上上游控制端口，
        // 此时需要一条未被拆分的完整流才能收发 AUTH TLS。
        let port = upstream.port();
        let host_str = upstream.host_str();
        let addr = tokio::net::lookup_host((host_str.as_ref(), port))
            .await
            .ok()?
            .next()?;
        let mut tcp_stream = tokio::net::TcpStream::connect(addr).await.ok()?;

        // Step 2: Read server greeting
        // 步骤 2：读取服务端欢迎应答（220），跳过它才能正确发出命令
        let _ = read_ftp_response(&mut tcp_stream).await;

        // Step 3: Send AUTH TLS command
        // 步骤 3：发送 AUTH TLS 请求升级到 TLS
        tcp_stream.write_all(b"AUTH TLS\r\n").await.ok()?;

        // Step 4: Read response - expect 234 (Ready for TLS)
        // 步骤 4：期望返回 234（可以开始 TLS），其它应答视为上游不接受加密
        let resp = read_ftp_response(&mut tcp_stream).await?;
        if !resp.starts_with(b"234 ") {
            // Not a 234 response, TLS negotiation not accepted
            return None;
        }

        // Step 5: Perform TLS handshake
        // 步骤 5：在已有的明文连接上完成 TLS 握手
        let tls_name = upstream.host();
        let ssl = tls_config.build_ssl(tls_name, port).ok()?;
        let ssl_connector = SslConnector::new(ssl, tcp_stream).ok()?;
        let ssl_stream = ssl_connector.connect().await.ok()?;

        // Step 6: Split the SSL stream for relay
        // 步骤 6：拆分 TLS 流，交回控制通道转发循环
        let (ups_r, ups_w) = tokio::io::split(ssl_stream);
        Some((Box::new(ups_r), Box::new(ups_w)))
    }

    /// Relay the FTP control channel between client and upstream.
    /// 在客户端与上游之间转发 FTP 控制通道。
    ///
    /// 整体策略：命令逐行读出后原样发给上游，上游的其它输出直接透传给客户端；
    /// 只有 PASV/EPSV（改写应答并预留本机监听）和需要数据通道的命令
    /// （STOR/APPE/STOU 上传、LIST/NLST/RETR 下载）会被拦截单独处理。
    /// 任一方向的 IO 错误都只结束任务，不做额外上报。
    async fn relay_control<CR, CW, UR, UW>(
        &mut self,
        clt_r: CR,
        mut clt_w: CW,
        mut ups_r: UR,
        mut ups_w: UW,
    ) -> Result<(), ServerTaskError>
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Forward server greeting (220) if it arrives quickly.
        // 先把上游的 220 欢迎应答转给客户端（若其已就绪）。
        if let Some(greeting) = read_ftp_response(&mut ups_r).await {
            self.ctx
                .server_stats
                .add_control_out_bytes(greeting.len() as u64);
            let _ = clt_w.write_all(&greeting).await;
        }

        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count: usize = 0;
        // 上一次 PASV/EPSV 协商出的待用数据通道，供后续取/存命令消费
        let mut pending_data: Option<PendingDataChannel> = None;
        let mut ups_buf = vec![0u8; 2048];

        loop {
            clt_line.clear();

            tokio::select! {
                            biased;

                            n = read_line_limited(&mut clt_reader, &mut clt_line) => {
                                match n {
                                    // 客户端主动关闭控制连接
                                    Ok(0) => return Ok(()),
                                    Ok(n) => {
                                        self.ctx.server_stats.add_control_in_bytes(n as u64);
                                        // 收到命令即视为活动，清零空闲计数
                                        idle_count = 0;

                                        // 上传命令：拦截数据通道，客户端 -> 上游，可选审计
                                        if is_upload_command(&clt_line) {
                                            if ups_w.write_all(&clt_line).await.is_err() {
                                                return Ok(());
                                            }
                                            handle_upload_data_channel(
                                                &mut clt_w,
                                                &mut ups_r,
                                                &self.ctx,
                                                self.max_idle_count,
                                                pending_data.take(),
                                                &clt_line,
                                            ).await;
                                            continue;
                                        } else if is_data_channel_command(&clt_line) {
                                            // LIST / NLST / RETR: need data channel, server → client direction.
                                            // 下载/列目录：数据通道方向为上游 -> 客户端
                                            if ups_w.write_all(&clt_line).await.is_err() {
                                                return Ok(());
                                            }
                                            // Forward the server's 150/125 "starting data connection" response.
                                            // 先透传 150/125 “正在打开数据连接”应答
                                            if let Some(resp) = read_ftp_response(&mut ups_r).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }
                                            // 消费 PASV/EPSV 阶段预留的监听，完成一次数据转发
                                            if let Some(pending) = pending_data.take() {
                                                handle_download_data_channel(
                                                    pending,
                                                    self.ctx.idle_wheel.clone(),
                                                    self.max_idle_count,
                                                ).await;
                                            }
                                            // Forward the server's 226 "transfer complete" response.
                                            // 再透传 226 “传输完成”应答
                                            if let Some(resp) = read_ftp_response(&mut ups_r).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }
                                            continue;
                                        } else if is_pasv_command(&clt_line) {
                                            // 客户端请求被动模式：向上游取回数据地址，
                                            // 在本机另开监听，并把应答改写成本机的监听地址。
                                            // 若已存在待用通道则不再重复协商，直接透传。
                                            if pending_data.is_none() {
                                                if ups_w.write_all(&clt_line).await.is_err() {
                                                    return Ok(());
                                                }
                                                if let Some(resp_bytes) = read_ftp_response(&mut ups_r).await {
                                                    if let Some(ups_data_addr) = parse_pasv_response(&resp_bytes, self.upstream_ip) && let Some(listener) = open_local_data_listener().await {

                                                        let rewritten = if is_epsv_command(&clt_line) {
                                                            // EPSV: keep (|||port|) format, just rewrite port.
                                                            // EPSV：保留 (|||port|) 管道格式，只替换端口
                                                            rewrite_epsv_response(&resp_bytes, listener.local_addr().map(|a| a.port()).unwrap_or(0))
                                                        } else {
                                                            // PASV: rewrite with proxy IP + listener port.
                                                            // PASV：替换为代理地址 + 监听端口
                                                            let proxy_addr = std::net::SocketAddr::V4(
                                                                std::net::SocketAddrV4::new(
                                                                    Ipv4Addr::LOCALHOST,
                                                                    listener.local_addr().map(|a| a.port()).unwrap_or(0),
                                                                ),
                                                            );
                                                            rewrite_pasv_response(&resp_bytes, Some(proxy_addr))
                                                        };
                                                        let _ = clt_w.write_all(&rewritten).await;
                                                        // 记下本机监听与上游真实数据地址，等待后续命令消费
                                                        pending_data = Some(PendingDataChannel {
                                                            listener: Arc::new(listener),
                                                            upstream_data_addr: ups_data_addr,
                                                        });
                                                        continue;
                                                    }
                                                    // 解析或建监听失败：原样透传上游应答，退化为直连数据通道
                                                    let _ = clt_w.write_all(&resp_bytes).await;
                                                }
                                                continue;
                                            } else if ups_w.write_all(&clt_line).await.is_err() {
                                                return Ok(());
                                            }
                                        } else if ups_w.write_all(&clt_line).await.is_err() {
                                            // 其余命令（USER/PASS/CWD/QUIT 等）原样透传
                                            return Ok(());
                                        }
                                    }
                                    Err(_) => return Ok(()),
                                }
                            }

                            n = ups_r.read(&mut ups_buf) => {
                                // 上游控制通道的其它输出（多为命令应答）直接透传给客户端
                                match n {
                                    Ok(0) => return Ok(()),
                                    Ok(n) => {
                                        self.ctx.server_stats.add_control_out_bytes(n as u64);
                                        if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                    Err(_) => return Ok(()),
                                }
                            }

                            _ = idle_interval.tick() => {
                                // 空闲检测：连续 tick 达到上限则断开；
                                // 服务器要求强制退出时立即断开
                                idle_count += 1;
                                if idle_count >= self.max_idle_count {
                                    return Ok(());
                                }
                                if self.ctx._server_quit_policy.force_quit() {
                                    return Ok(());
                                }
                            }
                        }
        }
    }
}

/// Opens a local listener on a random ephemeral port for the data channel.
/// 在随机临时端口上为数据通道开一个本机监听。
async fn open_local_data_listener() -> Option<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind("0.0.0.0:0").await.ok()
}

/// Extracts the FTP command (STOR / APPE / STOU) and the path from a client
/// command line. Used to forward rich metadata to the ICAP adapter.
/// 从客户端命令行中拆出 FTP 命令名（STOR/APPE/STOU）与文件路径，
/// 作为附加元数据传给 ICAP 适配器。
fn extract_cmd_path(line: &[u8]) -> (String, String) {
    // 去掉行尾的 \r / \n（其余空白保留）
    let trimmed: Vec<u8> = line
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() || *b != b'\r' && *b != b'\n')
        .collect();
    // 只按第一个空格切分：命令名之后的内容整体作为路径（路径本身可含空格）
    let mut parts = trimmed.splitn(2, |b| *b == b' ');
    let cmd = parts
        .next()
        .map(|s| String::from_utf8_lossy(s).to_string())
        .unwrap_or_else(|| "STOR".to_string());
    let path = parts
        .next()
        .map(|s| String::from_utf8_lossy(s).trim().to_string())
        .unwrap_or_default();
    (cmd, path)
}

/// Intercept an upload data channel: accept the client's PASV connection,
/// optionally audit the bytes through ICAP, and forward everything upstream.
/// 拦截上传数据通道：接受客户端连入本机监听，把字节边审计边转发给上游。
///
/// 流程：
///   1. 从命令中解析出命令名与路径，用于审计元数据；
///   2. accept 客户端的数据连接，并主动连接上游真实数据地址；
///   3. 组装数据通道五元组交给审计桥接处理；
///   4. 双向关闭数据连接后，把上游的最终应答（226/550 等）转给客户端。
async fn handle_upload_data_channel<CW, UR>(
    clt_w: &mut CW,
    ups_r: &mut UR,
    ctx: &CommonTaskContext,
    max_idle_count: usize,
    pending: Option<PendingDataChannel>,
    upload_cmd: &[u8],
) where
    CW: AsyncWrite + Send + Sync + Unpin,
    UR: AsyncRead + Send + Sync + Unpin,
{
    // 没有事先协商好被动模式监听时无法拦截，数据仍由客户端直连上游
    let Some(pdc) = pending else { return };

    let (cmd, path) = extract_cmd_path(upload_cmd);

    let (mut clt_conn, clt_addr) = match pdc.listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match tokio::net::TcpStream::connect(pdc.upstream_data_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };

    // 取本端地址以还原上游数据端点，失败则退回配置里的地址
    let server_addr = match ups_conn.local_addr() {
        Ok(a) => a,
        Err(_) => pdc.upstream_data_addr,
    };
    let data_tuple = g3_icap_client::reqmod::ConnectionTuple {
        server_addr: clt_addr,
        remote_addr: server_addr,
        protocol: g3_icap_client::reqmod::ConnectionProtocol::Tcp,
    };

    // 未配置 ICAP 时返回 None，审计桥接会退化为纯转发
    let audit_ctx = build_audit_context(ctx, max_idle_count, &cmd, &path, Some(data_tuple), None);

    let _ = run_ftp_upload_audit_or_relay(
        &mut clt_conn,
        &mut ups_conn,
        &ctx.idle_wheel,
        max_idle_count,
        audit_ctx,
    )
    .await;

    let _ = ups_conn.shutdown().await;
    let _ = clt_conn.shutdown().await;

    // 数据通道关闭后上游才会给出传输结果应答，此处补发给客户端
    if let Some(final_resp) = read_ftp_response(ups_r).await {
        let _ = clt_w.write_all(&final_resp).await;
    }
}

/// Handle a download data channel: accept the client's PASV connection,
/// and relay data from the upstream FTP server to the client.
/// Used for LIST, NLST, RETR commands.
/// 处理下载数据通道：接受客户端连入本机监听，把上游数据单向转发给客户端。
/// 用于 LIST、NLST、RETR 等命令。
async fn handle_download_data_channel(
    pending: PendingDataChannel,
    idle_wheel: Arc<g3_io_ext::IdleWheel>,
    max_idle_count: usize,
) {
    let (mut clt_conn, _) = match pending.listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match tokio::net::TcpStream::connect(pending.upstream_data_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            biased;

            res = ups_conn.read(&mut buf) => {
                match res {
                    // 上游关闭数据连接即代表传输结束
                    Ok(0) => break,
                    Ok(n) => {
                        idle_count = 0;
                        if clt_conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            _ = idle_interval.tick() => {
                idle_count += 1;
                if idle_count >= max_idle_count {
                    break;
                }
            }
        }
    }
    // 先 flush 再 shutdown，避免最后一批数据在关闭时丢失
    let _ = clt_conn.flush().await;
    let _ = clt_conn.shutdown().await;
    let _ = ups_conn.shutdown().await;
}
