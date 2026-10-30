/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP over HTTP CONNECT tunnel bridge.
//!
//! When an HTTP CONNECT tunnel carries FTP traffic, this bridge:
//!   1. intercepts the control channel to detect PASV/EPSV responses
//!      (rewriting them to point at a locally-bound data listener),
//!   2. detects STOR/STOU/APPE commands and copies the data channel
//!      through the shared ICAP REQMOD audit pipeline.
//!
//! This bridges reuses the same `run_ftp_upload_audit_or_relay`
//! function used by the native FTP proxy — keeping the audit path
//! consistent across both proxy modes.
//!
//! 承载 FTP 流量的 HTTP CONNECT 隧道桥接。
//!
//! 当 HTTP CONNECT 隧道里跑的是 FTP 流量时，本桥接会：
//!   1. 拦截控制通道，识别 PASV/EPSV 应答并改写成本机绑定的数据监听地址；
//!   2. 识别 STOR/STOU/APPE 命令，把数据通道送进共用的 ICAP REQMOD 审计链路。
//!
//! 这里复用原生 FTP 代理的 `run_ftp_upload_audit_or_relay`，
//! 使两种代理模式的审计行为保持一致。

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use slog::Logger;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use g3_daemon::server::ClientConnectionInfo;
use g3_io_ext::IdleWheel;

use super::audit_bridge::{FtpUploadAuditContext, run_ftp_upload_audit_or_relay};
use super::ctl_common::{
    is_data_channel_command, is_epsv_command, is_pasv_command, is_upload_command,
    parse_pasv_response, read_ftp_response, rewrite_epsv_response, rewrite_pasv_response,
};
use super::stats::FtpProxyServerStats;
use crate::audit::AuditContext;
use crate::config::server::ServerConfig;
use crate::config::server::ftp_proxy::FtpProxyServerConfig;
use crate::serve::ServerTaskNotes;

/// FTP-over-CONNECT 桥接实例。
///
/// 与原生代理不同：控制通道两端已经是隧道两端的流，本结构只负责在
/// 同一条 CONNECT 会话内做命令识别与数据通道牵引，不参与上游建连。
#[allow(dead_code)]
pub(crate) struct FtpOverConnectBridge {
    server_config: Arc<FtpProxyServerConfig>,
    #[allow(dead_code)]
    server_stats: Arc<FtpProxyServerStats>,
    /// ICAP REQMOD 客户端；未启用上传审计时为 None，数据通道退化为纯转发
    icap_client: Option<Arc<g3_icap_client::reqmod::IcapReqmodClient>>,
    idle_wheel: Arc<IdleWheel>,
    cc_info: ClientConnectionInfo,
    #[allow(dead_code)]
    task_logger: Option<Logger>,
    /// 上游 FTP 服务器 IPv4，用于补全 EPSV 应答中缺失的地址
    upstream_ip: Ipv4Addr,
    #[allow(dead_code)]
    task_notes: ServerTaskNotes,
}

#[allow(dead_code)]
impl FtpOverConnectBridge {
    /// 创建桥接实例：仅在开启上传审计且审计器提供 ICAP 客户端时才建立审计链路。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        idle_wheel: Arc<IdleWheel>,
        cc_info: ClientConnectionInfo,
        upstream_ip: Ipv4Addr,
        task_logger: Option<Logger>,
        audit_ctx: &AuditContext,
        task_notes: ServerTaskNotes,
    ) -> Self {
        let icap_client = if server_config.audit_upload {
            audit_ctx
                .handle()
                .and_then(|h| h.icap_reqmod_client().cloned())
                .map(Arc::new)
        } else {
            None
        };

        FtpOverConnectBridge {
            server_config,
            server_stats,
            icap_client,
            idle_wheel,
            cc_info,
            task_logger,
            upstream_ip,
            task_notes,
        }
    }

    /// Relay a CONNECT tunnel carrying FTP traffic. Control channel
    /// traffic is passed through verbatim, except for PASV/EPSV
    /// responses (rewritten) and STOR/APPE/STOU commands that trigger
    /// an audited data channel.
    /// 转发承载 FTP 的 CONNECT 隧道。控制通道流量基本原样透传，
    /// 仅 PASV/EPSV 应答会被改写，以及 STOR/APPE/STOU 会触发带审计的数据通道。
    pub(crate) async fn relay<CR, CW, UR, UW>(&self, clt_r: CR, mut clt_w: CW, ups_r: UR, ups_w: UW)
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Forward the server greeting if it arrives before any command.
        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut ups_reader = ups_r;
        let mut ups_writer = ups_w;
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        // (本机数据监听, 上游真实数据地址)，由 PASV/EPSV 协商后暂存
        let mut pending_data: Option<(Arc<TcpListener>, SocketAddr)> = None;
        let mut ups_buf = vec![0u8; 2048];

        loop {
            clt_line.clear();

            tokio::select! {
                            biased;

                            n = clt_reader.read_until(b'\n', &mut clt_line) => {
                                match n {
                                    Ok(0) => break,
                                    Ok(_n) => {
                                        if is_upload_command(&clt_line) {
                                            // Forward the STOR/APPE upstream and wait for
                                            // the "150 opening..." reply.
                                            // 先把 STOR/APPE 发给上游，并等待“正在打开数据连接”应答
                                            if ups_writer.write_all(&clt_line).await.is_err() {
                                                break;
                                            }
                                            if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }

                                            // Drain the data channel through the audit pipeline.
                                            // 把数据通道引流到审计链路
                                            if let Some((listener, ups_data_addr)) = pending_data.take() {
                                                let _ = self.process_upload(listener, ups_data_addr).await;
                                            }

                                            // Forward the "226 transfer complete..." reply.
                                            // 再透传“传输完成”应答
                                            if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }
                                        } else if is_data_channel_command(&clt_line) {
                                            // STOR/APPE/STOU/LIST/NLST/RETR all need the data channel.
                                            // Forward the command and wait for the server's 150 reply.
                                            // 取/存类命令都需要数据通道：转发命令并等待 150 应答
                                            if ups_writer.write_all(&clt_line).await.is_err() {
                                                break;
                                            }
                                            if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }

                                            // Consume the pending listener and relay data.
                                            // 消费掉预留的监听并按方向完成一次数据转发
                                            if let Some((listener, ups_data_addr)) = pending_data.take() {
                                                if is_upload_command(&clt_line) {
                                                    // Upload: client → server, audit-enabled path.
                                                    // 上传：客户端 -> 服务器，走可审计路径
                                                    let _ = self.process_upload(listener, ups_data_addr).await;
                                                } else {
                                                    // Download/List: server → client, plain relay path.
                                                    // 下载/列目录：服务器 -> 客户端，走普通转发路径
                                                    let _ = process_download(listener, ups_data_addr).await;
                                                }
                                            }

                                            // Forward the server's 226 "transfer complete" response.
                                            // 透传 226 “传输完成”应答
                                            if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                                let _ = clt_w.write_all(&resp).await;
                                            }
                                        } else if is_pasv_command(&clt_line) {
                                            // Client requests passive mode: open a listener and rewrite
                                            // the server's reply to point at us.
                                            // 客户端请求被动模式：本机开监听，并把服务端应答改写指向我们
                                            if pending_data.is_none() {
                                                if ups_writer.write_all(&clt_line).await.is_err() {
                                                    break;
                                                }
                                                if let Some(resp_bytes) = read_ftp_response(&mut ups_reader).await {
                                                    if let Some(ups_data_addr) = parse_pasv_response(&resp_bytes, self.upstream_ip) {
                                                        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
                                                        if let Ok(listener) = TcpListener::bind(bind_addr).await && let Ok(local_addr) = listener.local_addr() {

                                                            let rewritten = if is_epsv_command(&clt_line) {
                                                                // EPSV: keep the (|||port|) pipe format, just replace port.
                                                                // EPSV：保留 (|||port|) 管道格式，只替换端口
                                                                rewrite_epsv_response(&resp_bytes, local_addr.port())
                                                            } else {
                                                                // PASV: replace with proxy IP + listener port.
                                                                // PASV：替换为代理地址 + 监听端口
                                                                let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_addr.port()));
                                                                rewrite_pasv_response(&resp_bytes, Some(proxy_addr))
                                                            };
                                                            let _ = clt_w.write_all(&rewritten).await;
                                                            pending_data = Some((Arc::new(listener), ups_data_addr));
                                                            continue;
                                                        }
                                                    }
                                                    // Fall through: forward the original response if anything failed.
                                                    // 解析或监听创建失败：原样透传应答
                                                    let _ = clt_w.write_all(&resp_bytes).await;
                                                }
                                                continue;
                                            } else if ups_writer.write_all(&clt_line).await.is_err() {
                                                break;
                                            }
                                        } else if ups_writer.write_all(&clt_line).await.is_err() {
                                            // 其它命令原样透传
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            n = ups_reader.read(&mut ups_buf) => {
                                // 上游的其它输出（多为命令应答）直接透传给客户端
                                match n {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
        }
    }

    /// 处理一条上传数据通道：accept 客户端的数据连接，主动连上游数据地址，
    /// 然后边转发边做 ICAP 审计。
    async fn process_upload(&self, listener: Arc<TcpListener>, ups_data_addr: SocketAddr) {
        let (mut clt_conn, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut ups_conn = match TcpStream::connect(ups_data_addr).await {
            Ok(c) => c,
            Err(_) => return,
        };

        // CONNECT 模式下拿不到原始命令串（控制通道由隧道对端持有），
        // 因此命令名与路径只能填占位值，审计侧仅能按“存在一次上传”处理。
        let audit_ctx = self
            .icap_client
            .as_ref()
            .map(|client| FtpUploadAuditContext {
                icap_client: client.clone(),
                idle_wheel: self.idle_wheel.clone(),
                max_idle_count: 60, // 60 ticks × 1s interval = 60s idle timeout
                copy_config: self.server_config.limited_copy_config(),
                client_addr: Some(self.cc_info.client_addr()),
                ftp_command: "STOR".to_string(),
                ftp_path: "ftp-over-connect".to_string(),
                data_channel_tuple: None,
                keylog_buffer: None,
            });

        let _ = run_ftp_upload_audit_or_relay(
            &mut clt_conn,
            &mut ups_conn,
            &self.idle_wheel,
            60,
            audit_ctx,
        )
        .await;
        // 双向关闭，促使上游尽快给出 226 应答
        let _ = ups_conn.shutdown().await;
        let _ = clt_conn.shutdown().await;
    }
}

/// Download / directory-list data channel relay: server → client.
/// Used for LIST, NLST, RETR commands which read data from the FTP server.
/// 下载 / 列目录的数据通道转发：方向为服务器 -> 客户端。
/// 用于 LIST、NLST、RETR 等从 FTP 服务器读取数据的命令。
async fn process_download(listener: Arc<TcpListener>, ups_data_addr: SocketAddr) {
    let (mut clt_conn, _) = match listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match TcpStream::connect(ups_data_addr).await {
        Ok(c) => c,
        Err(_) => return,
    };

    // Server → client: copy all data from upstream to client.
    // 服务器 -> 客户端：把上游数据全部拷给客户端
    let _ = tokio::io::copy(&mut ups_conn, &mut clt_conn).await;
    let _ = clt_conn.shutdown().await;
}
