/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP REQMOD audit bridge for FTP uploads.
//!
//! When `audit_upload` is enabled, every byte sent by the FTP client on
//! a data channel (STOR, APPE, STOU) is simultaneously:
//!   * forwarded to the upstream FTP server — verbatim,
//!   * sent to the ICAP server — wrapped inside a synthesized HTTP
//!     REQMOD body with chunked transfer encoding.
//!
//! The bridge never blocks uploads on ICAP failures: if the ICAP
//! connection drops or times out, the upstream transfer continues
//! without audit data.
//!
//! FTP 上传的 ICAP REQMOD 审计桥接。
//!
//! 开启 `audit_upload` 后，FTP 客户端在数据通道（STOR / APPE / STOU）上发出的
//! 每一个字节都会同时被：
//!   * 原样转发给上游 FTP 服务器；
//!   * 包装成一个合成的 HTTP REQMOD 请求体（chunked 分块编码）发送给 ICAP 服务器。
//!
//! 该桥接绝不会因为 ICAP 故障而阻塞上传：ICAP 连接断开或超时时，
//! 上游传输照常继续，只是不再产生审计数据。

use std::net::SocketAddr;
use std::sync::Arc;

use log::warn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

use g3_io_ext::{IdleCheck, IdleInterval, IdleWheel, StreamCopyConfig};
use g3_types::net::TlsKeyLogBuffer;

use crate::config::server::ServerConfig;

/// 简化的空闲检查器：按“连续空闲 tick 次数”判断是否超时。
/// 供 ICAP 适配器内部的两段拷贝复用同样的空闲语义。
struct CountingIdleChecker {
    idle_wheel: Arc<IdleWheel>,
    max_idle_count: usize,
}

impl IdleCheck for CountingIdleChecker {
    fn interval_timer(&self) -> IdleInterval {
        self.idle_wheel.register()
    }

    fn check_quit(&self, idle_count: usize) -> bool {
        idle_count >= self.max_idle_count
    }

    /// 审计桥接不感知服务器强制退出，交由外层控制通道处理
    fn check_force_quit(&self) -> Option<g3_io_ext::IdleForceQuitReason> {
        None
    }
}

/// Context needed to perform ICAP audit of a single FTP upload data
/// channel. Built by `handle_upload_data_channel` in `task.rs` from
/// server-level `CommonTaskContext` and the parsed FTP command.
/// 对单条 FTP 上传数据通道做 ICAP 审计所需的上下文。
/// 由 `task.rs` 中的 `handle_upload_data_channel` 从服务器级的
/// `CommonTaskContext` 加上解析出的 FTP 命令拼装而来。
pub(crate) struct FtpUploadAuditContext {
    /// ICAP REQMOD 客户端
    pub(crate) icap_client: Arc<g3_icap_client::reqmod::IcapReqmodClient>,
    pub(crate) idle_wheel: Arc<g3_io_ext::IdleWheel>,
    /// 允许连续空闲的 tick 次数
    pub(crate) max_idle_count: usize,
    /// 流拷贝的速率/大小限制配置
    pub(crate) copy_config: StreamCopyConfig,
    pub(crate) client_addr: Option<SocketAddr>,
    /// FTP 命令名（STOR/APPE/STOU），作为 ICAP 头信息上报
    pub(crate) ftp_command: String,
    /// 上传路径，作为 ICAP 请求的 URI 信息上报
    pub(crate) ftp_path: String,
    /// Data channel 5-tuple: (g3proxy local addr, FTP server addr)
    /// 数据通道五元组：(g3proxy 本地地址, FTP 服务器地址)
    pub(crate) data_channel_tuple: Option<g3_icap_client::reqmod::ConnectionTuple>,
    /// TLS keylog buffer for the upstream TLS connection
    /// 上游 TLS 连接的密钥日志，供审计侧解密 FTPS 流量
    pub(crate) keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

/// Entry point for all FTP upload data channels.
///
/// * If `audit_ctx` is `Some`, build an `FtpUploadAdapter` and stream
///   through it (upload + ICAP audit simultaneously).
/// * If `audit_ctx` is `None`, fall back to a plain copy loop — no
///   extra allocations, no overhead.
/// 所有 FTP 上传数据通道的统一入口。
///
/// * `audit_ctx` 为 `Some` 时：构建 `FtpUploadAdapter`，在同一条流上完成
///   “上传转发 + ICAP 审计”。
/// * `audit_ctx` 为 `None` 时：退化为普通拷贝循环，无额外分配、无审计开销。
pub(crate) async fn run_ftp_upload_audit_or_relay<CR, UW>(
    clt_r: &mut CR,
    ups_w: &mut UW,
    idle_wheel: &Arc<IdleWheel>,
    max_idle_count: usize,
    audit_ctx: Option<FtpUploadAuditContext>,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin,
{
    match audit_ctx {
        Some(ac) => audit_and_forward(clt_r, ups_w, ac).await,
        None => raw_forward_with_idle(clt_r, ups_w, idle_wheel, max_idle_count).await,
    }
}

/// Bidirectional transfer for HTTP CONNECT tunnel mode.
/// Handles upload audit on client→upstream direction, while doing plain copy on upstream→client.
/// HTTP CONNECT 隧道模式的双向转发。
/// 客户端 -> 上游方向做上传审计，上游 -> 客户端方向只做普通拷贝。
pub(crate) async fn run_ftp_upload_audit_or_relay_bidi<CR, CW, UR, UW>(
    clt_r: CR,
    clt_w: CW,
    ups_r: UR,
    ups_w: UW,
    idle_wheel: Arc<IdleWheel>,
    max_idle_count: usize,
    audit_ctx: Option<FtpUploadAuditContext>,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin + 'static,
    CW: AsyncWrite + Send + Sync + Unpin + 'static,
    UR: AsyncRead + Send + Sync + Unpin + 'static,
    UW: AsyncWrite + Send + Sync + Unpin + 'static,
{
    if let Some(ac) = audit_ctx {
        // 审计模式：另起任务做上游->客户端的反向拷贝，本任务专注客户端->上游的审计
        let idle_wheel_clone = idle_wheel.clone();
        let mut upstream_to_client: JoinHandle<()> = tokio::spawn(async move {
            bidi_half_relay_with_idle(ups_r, clt_w, idle_wheel_clone, max_idle_count).await;
        });

        let mut clt_r = clt_r;
        let mut ups_w = ups_w;
        let result = audit_and_forward(&mut clt_r, &mut ups_w, ac).await;

        // Wait for the upstream-to-client relay to finish, with a timeout
        // to avoid leaking the task if the upstream never sends EOF.
        // 带超时地等待反向拷贝结束：上游可能不发 EOF，
        // 不 abort 会让任务泄漏。
        if tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            &mut upstream_to_client,
        )
        .await
        .is_err()
        {
            upstream_to_client.abort();
        }

        result
    } else {
        // 无审计：两个方向各起一个拷贝任务
        let idle_wheel_clone = idle_wheel.clone();
        let mut client_to_up = tokio::spawn(async move {
            bidi_half_relay_with_idle(clt_r, ups_w, idle_wheel_clone, max_idle_count).await;
        });
        let mut up_to_client = tokio::spawn(async move {
            bidi_half_relay_with_idle(ups_r, clt_w, idle_wheel, max_idle_count).await;
        });

        // Wait for both directions, but abort the other if one finishes first
        // to avoid leaking tasks that would block forever on a stalled peer.
        // 任一方向先结束就 abort 另一个，避免任务卡在对端上永久等待。
        tokio::select! {
            _ = &mut client_to_up => { up_to_client.abort(); }
            _ = &mut up_to_client => { client_to_up.abort(); }
        }
        None
    }
}

/// 单向拷贝，带空闲超时。读端与写端在独立任务中通过 channel 解耦。
async fn bidi_half_relay_with_idle<R, W>(
    r: R,
    w: W,
    idle_wheel: Arc<IdleWheel>,
    max_idle_count: usize,
) where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Decouple `r.read` from `w.write_all` so upstream backpressure on
    // `w` cannot stall the reader. Previously this loop did
    // `read -> write_all` serially in the same task; a slow upstream
    // socket send buffer would block the await, the client read would
    // stop, the kernel recv buffer on the client side would fill, and
    // the client kernel would advertise TCP ZeroWindow. With large
    // FTP uploads (>1 GiB) the client then stalled, retransmitted,
    // and looped forever.
    //
    // 把 `r.read` 与 `w.write_all` 拆到两个任务，使上游对 `w` 的反压不会拖住读端。
    // 此前是在同一个任务里串行 read -> write_all：上游 socket 发送缓冲变慢时
    // write_all 会挂起，客户端读随之停止，客户端内核接收缓冲被填满并通告
    // TCP 零窗口；大文件上传（>1 GiB）时客户端就会卡住、重传，如此循环不止。
    let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(8);

    let writer = tokio::spawn(async move {
        let mut w = w;
        let mut rx = chunk_rx;
        // Write timeout prevents the writer from hanging indefinitely
        // if the upstream socket stalls (e.g. TCP half-close).
        // 写出超时：防止上游 socket 卡死（例如 TCP 半关闭）时写任务无限挂起
        const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
        while let Some(chunk) = rx.recv().await {
            let write_result = tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&chunk)).await;
            match write_result {
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        let _ = w.flush().await;
        let _ = w.shutdown().await;
    });

    let mut r = r;
    let mut buf = vec![0u8; 32 * 1024];

    // Wait for the first data byte without idle timeout. In FTP passive
    // mode the data channel may connect long before actual file transfer
    // begins (STOR/150 response). Do not start idle checking until the
    // first byte arrives.
    //
    // 首个数据字节之前不做空闲判断：FTP 被动模式下，数据连接往往远早于
    // 实际传输（STOR/150）建立。必须等第一个字节到达后才开始计空闲。
    let first_read = r.read(&mut buf).await;

    match first_read {
        Ok(0) | Err(_) => {
            // EOF or error before any data: signal EOF to writer and exit.
            // 还没收到数据就 EOF/出错：通知写任务收尾后退出
            drop(chunk_tx);
            let _ = writer.await;
            return;
        }
        Ok(n) => {
            let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
            if chunk_tx.send(chunk).await.is_err() {
                drop(chunk_tx);
                let _ = writer.await;
                return;
            }
        }
    }

    // Now that data transfer has started, enable idle checking.
    // 数据传输已开始，此后启用空闲检测
    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;

    loop {
        tokio::select! {
            biased;

            res = r.read(&mut buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        idle_count = 0;
                        let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if chunk_tx.send(chunk).await.is_err() {
                            // writer task already exited (write error);
                            // no point keeping the relay alive.
                            break;
                        }
                    }
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
    // Drop the sender so the writer task sees EOF and finalizes
    // flush + shutdown of `w` once it has drained the channel.
    drop(chunk_tx);
    let _ = writer.await;
}

/// 不审计时的直传：客户端 -> 上游单向拷贝，带空闲超时。
/// 返回已转发的字节数；中途出错或空闲超时也会返回已累计的值。
async fn raw_forward_with_idle<CR, UW>(
    clt_r: &mut CR,
    ups_w: &mut UW,
    idle_wheel: &Arc<IdleWheel>,
    max_idle_count: usize,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin,
{
    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    let mut total: u64 = 0;
    loop {
        tokio::select! {
            biased;

            res = clt_r.read(&mut buf) => {
                match res {
                    // 客户端关闭数据连接：上传结束
                    Ok(0) => break,
                    Ok(n) => {
                        idle_count = 0;
                        if ups_w.write_all(&buf[..n]).await.is_err() {
                            return Some(total);
                        }
                        total += n as u64;
                    }
                    Err(_) => return Some(total),
                }
            }

            _ = idle_interval.tick() => {
                idle_count += 1;
                if idle_count >= max_idle_count {
                    return Some(total);
                }
            }
        }
    }
    let _ = ups_w.flush().await;
    Some(total)
}

/// 审计 + 转发的核心路径：把数据通道的字节同时交给 ICAP 适配器和上游连接。
/// 适配器创建失败时退化为纯转发，保证上传不受审计链路故障影响。
async fn audit_and_forward<CR, UW>(
    clt_r: &mut CR,
    ups_w: &mut UW,
    audit_ctx: FtpUploadAuditContext,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin,
{
    let idle_checker = CountingIdleChecker {
        idle_wheel: audit_ctx.idle_wheel.clone(),
        max_idle_count: audit_ctx.max_idle_count,
    };
    let mut adapter = match audit_ctx
        .icap_client
        .ftp_upload_audit_adapter(audit_ctx.copy_config, idle_checker)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "FTP ICAP adapter creation failed, fallback to forward-only: {}",
                e
            );
            // ICAP 不可用：放弃审计，仍然把文件传上去
            return raw_forward_with_idle(
                clt_r,
                ups_w,
                &audit_ctx.idle_wheel,
                audit_ctx.max_idle_count,
            )
            .await;
        }
    };
    if let Some(addr) = audit_ctx.client_addr {
        adapter.set_client_addr(addr);
    }
    /* added for connection tuple - data channel 5-tuple */
    // 数据通道五元组，便于审计侧还原真实收发端
    if let Some(tuple) = audit_ctx.data_channel_tuple {
        adapter.set_connection_tuple(tuple);
    }
    /* added for TLS keylog */
    // 密钥日志，使审计侧具备解密 FTPS 数据的能力
    if let Some(keylog) = audit_ctx.keylog_buffer {
        adapter.set_keylog_buffer(keylog);
    }

    let mut state = g3_icap_client::reqmod::ftp::new_adaptation_run_state();
    let end_state = adapter
        .audit_and_forward(
            &mut state,
            clt_r,
            ups_w,
            &audit_ctx.ftp_command,
            &audit_ctx.ftp_path,
        )
        .await;

    // 各类结束状态都返回已转发的字节数，由上层统一收尾；
    // 是否被 ICAP 判定为“阻断”由适配器内部处理，此处不再干预上传结果。
    match end_state {
        g3_icap_client::reqmod::ftp::FtpAdaptationEndState::OriginalTransferred {
            bytes, ..
        }
        | g3_icap_client::reqmod::ftp::FtpAdaptationEndState::OriginalTransferredAfterFallback {
            bytes,
            ..
        }
        | g3_icap_client::reqmod::ftp::FtpAdaptationEndState::OriginalTransferredInBackground {
            bytes,
        }
        | g3_icap_client::reqmod::ftp::FtpAdaptationEndState::AuditOnly { bytes, .. } => {
            let _ = ups_w.flush().await;
            let _ = ups_w.shutdown().await;
            Some(bytes)
        }
    }
}

/// Convenience constructor: builds an `FtpUploadAuditContext` from the
/// shared `CommonTaskContext` if an ICAP client is configured.
/// 便捷构造器：从任务共用的 `CommonTaskContext` 生成一份审计上下文。
/// 未配置 ICAP 客户端时返回 None，调用方据此退化为纯转发。
pub(crate) fn build_audit_context(
    ctx: &super::task::CommonTaskContext,
    max_idle_count: usize,
    ftp_command: &str,
    ftp_path: &str,
    data_channel_tuple: Option<g3_icap_client::reqmod::ConnectionTuple>,
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
) -> Option<FtpUploadAuditContext> {
    let icap_client = ctx.icap_client.as_ref()?.clone();

    Some(FtpUploadAuditContext {
        icap_client,
        idle_wheel: ctx.idle_wheel.clone(),
        max_idle_count,
        copy_config: ctx.server_config.limited_copy_config(),
        client_addr: Some(ctx.cc_info.client_addr()),
        ftp_command: ftp_command.to_string(),
        ftp_path: ftp_path.to_string(),
        data_channel_tuple,
        keylog_buffer,
    })
}
