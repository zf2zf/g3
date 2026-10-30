/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! 面向 ICAP 审计的 FTP 上传数据连接拦截。
//!
//! 本模块处理 TLS 拦截完成后的 FTPS 上传数据连接：当数据连接被识别为
//! 上传方向（控制连接上已出现 STOR/APPE 命令）时，对解密后的数据触发 ICAP 审计。
//! 上传标记与 FTPS 域名通过 [`crate::serve::ftp_proxy::upload_state`] 全局状态与控制连接侧交接。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple};
use g3_types::net::TlsKeyLogBuffer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext};
use crate::serve::ServerTaskResult;
use crate::serve::ftp_proxy::audit_bridge::{
    FtpUploadAuditContext, run_ftp_upload_audit_or_relay_bidi,
};
use crate::serve::ftp_proxy::upload_state::{PendingUploadInfo, get_ftp_upload_state};

/// 数据连接的四条 IO 半端（客户端读/写、源站读/写），均为解密后的明文流。
struct FtpUploadDataIo {
    clt_r: BoxAsyncRead,
    clt_w: BoxAsyncWrite,
    ups_r: BoxAsyncRead,
    ups_w: BoxAsyncWrite,
}

/// FTP 上传数据连接拦截对象。
pub(crate) struct FtpUploadDataInterceptObject<SC: ServerConfig> {
    io: Option<FtpUploadDataIo>,
    ctx: StreamInspectContext<SC>,
    /// 控制连接上记录的待审上传信息（命令名/路径）；为 None 表示尚未标记，需边收边查
    upload_info: Option<PendingUploadInfo>,
    /// 数据连接四元组，供 ICAP 请求头标注连接上下文；无则不带
    data_channel_tuple: Option<ConnectionTuple>,
    /// TLS 会话密钥日志缓冲区，供外部分析工具解密原始流量；未启用密钥日志时为 None
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC: ServerConfig> FtpUploadDataInterceptObject<SC> {
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upload_info: Option<PendingUploadInfo>,
        data_channel_tuple: Option<ConnectionTuple>,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        FtpUploadDataInterceptObject {
            io: None,
            ctx,
            upload_info,
            data_channel_tuple,
            keylog_buffer,
        }
    }

    /// 注入数据连接的四条 IO 半端。
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = FtpUploadDataIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }
}

impl<SC> FtpUploadDataInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 上传数据连接拦截入口。
    /// - IO 未注入：无事可做，直接返回；
    /// - 无上传信息：转入 [`intercept_pending`]，等数据到达后再查全局上传标记；
    /// - 有上传信息但无 ICAP 客户端：退化为双向透明中继；
    /// - 否则组装审计上下文，交给审计桥执行"检测后放行/阻断或透明中继"。
    pub(crate) async fn intercept(mut self) -> crate::serve::ServerTaskResult<()> {
        let io = match self.io.take() {
            Some(io) => io,
            None => return Ok(()),
        };

        let upload_info = match self.upload_info.take() {
            Some(info) => info,
            None => return Self::intercept_pending(self.ctx, io, self.keylog_buffer).await,
        };

        let icap_client = match self.ctx.audit_handle.icap_reqmod_client().cloned() {
            Some(client) => Arc::new(client),
            None => {
                // 无 ICAP 服务：数据原样双向中继
                let _ = run_ftp_upload_audit_or_relay_bidi(
                    io.clt_r,
                    io.clt_w,
                    io.ups_r,
                    io.ups_w,
                    self.ctx.idle_wheel.clone(),
                    self.ctx.max_idle_count,
                    None,
                )
                .await;
                return Ok(());
            }
        };

        let audit_ctx = FtpUploadAuditContext {
            icap_client,
            idle_wheel: self.ctx.idle_wheel.clone(),
            max_idle_count: self.ctx.max_idle_count,
            copy_config: self.ctx.server_config.limited_copy_config(),
            client_addr: Some(self.ctx.task_notes.client_addr),
            ftp_command: upload_info.ftp_command,
            ftp_path: upload_info.ftp_path,
            data_channel_tuple: self.data_channel_tuple,
            keylog_buffer: self.keylog_buffer.clone(),
        };

        let _ = run_ftp_upload_audit_or_relay_bidi(
            io.clt_r,
            io.clt_w,
            io.ups_r,
            io.ups_w,
            self.ctx.idle_wheel.clone(),
            self.ctx.max_idle_count,
            Some(audit_ctx),
        )
        .await;

        Ok(())
    }

    /// 上传信息尚未到达时的处理：先窥探第一个数据块，再据全局状态判定是否上传连接。
    /// FTP 被动模式下数据连接会在控制连接发出 STOR 之前就完成 TLS 握手，
    /// 因此这里等待首字节时不启用空闲超时，等真正开始传输文件数据后才交给带超时中继。
    async fn intercept_pending(
        ctx: StreamInspectContext<SC>,
        io: FtpUploadDataIo,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> ServerTaskResult<()> {
        let FtpUploadDataIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = io;

        let mut clt_r = clt_r;
        let mut clt_w = clt_w;
        let mut ups_r = ups_r;
        let mut ups_w = ups_w;

        let mut clt_buf = vec![0u8; 4096];
        let mut ups_buf = vec![0u8; 4096];

        // Wait for the first data byte without idle timeout. In FTP passive
        // mode the data channel connects and completes TLS *before* the
        // control channel sends STOR, so this wait can be arbitrarily long.
        // Only start idle checking once actual file data transfer begins.
        // 中文说明：见上方函数注释；空闲检测从首字节到达后的中继阶段才开始。
        tokio::select! {
        biased;

            res = clt_r.read(&mut clt_buf) => {
                match res {
                    Ok(0) => {
                        // 客户端先关闭：冲刷源站方向的剩余数据（限时 5s）后收尾
                        let _ = ups_w.shutdown().await;
                        let _ = tokio::time::timeout(
                            tokio::time::Duration::from_secs(5),
                            Self::drain_and_close_half(&mut ups_r, &mut clt_w),
                        ).await;
                        let _ = clt_w.shutdown().await;
                        Ok(())
                    }
                    Ok(n) => {
                        // Prepend the chunk we just read so the spawned
                        // relay task sees a continuous stream from byte 0.
                        // 把窥探到的首块数据回填到流开头，中继任务从第 0 字节起看到连续流
                        let clt_r = io::Cursor::new(clt_buf[..n].to_vec()).chain(clt_r);

                        // 数据已开始流动，此时再查控制连接是否已标记上传（consume 一次性消耗）
                        if let Some(upload_info) = check_ftp_upload_data(
                            ctx.task_notes.client_addr,
                            ctx.connect_notes.server_addr,
                        ) {
                            let icap_client = match ctx.audit_handle.icap_reqmod_client().cloned() {
                                Some(client) => Arc::new(client),
                                None => {
                                    // 无 ICAP：连同首块一起透明中继
                                    let _ = run_ftp_upload_audit_or_relay_bidi(
                                        clt_r, clt_w, ups_r, ups_w,
                                        ctx.idle_wheel.clone(),
                                        ctx.max_idle_count,
                                        None,
                                    ).await;
                                    return Ok(());
                                }
                            };

                            // 用本数据连接的实际两端构造 ICAP 连接四元组
                            let data_channel_tuple = ConnectionTuple {
                                server_addr: ctx.task_notes.client_addr,
                                remote_addr: ctx.connect_notes.server_addr,
                                protocol: ConnectionProtocol::Tcp,
                            };

                            let audit_ctx = FtpUploadAuditContext {
                                icap_client,
                                idle_wheel: ctx.idle_wheel.clone(),
                                max_idle_count: ctx.max_idle_count,
                                copy_config: ctx.server_config.limited_copy_config(),
                                client_addr: Some(ctx.task_notes.client_addr),
                                ftp_command: upload_info.ftp_command,
                                ftp_path: upload_info.ftp_path,
                                data_channel_tuple: Some(data_channel_tuple),
                                keylog_buffer: keylog_buffer.clone(),
                            };

                            let _ = run_ftp_upload_audit_or_relay_bidi(
                                Box::new(clt_r),
                                clt_w,
                                ups_r,
                                ups_w,
                                ctx.idle_wheel.clone(),
                                ctx.max_idle_count,
                                Some(audit_ctx),
                            ).await;
                        } else {
                            // 非上传数据连接（如下载）：直接透明中继
                            let _ = run_ftp_upload_audit_or_relay_bidi(
                                clt_r, clt_w, ups_r, ups_w,
                                ctx.idle_wheel.clone(),
                                ctx.max_idle_count,
                                None,
                            ).await;
                        }
                        Ok(())
                    }
                    Err(_) => {
                        // 读错误：两侧直接关闭，不做数据抢救
                        let _ = ups_w.shutdown().await;
                        let _ = clt_w.shutdown().await;
                        Ok(())
                    }
                }
            }

            res = ups_r.read(&mut ups_buf) => {
                // 源站方向先有数据：必为下载等非上传流量，无需审计，透明中继
                match res {
                    Ok(0) => {
                        let _ = clt_w.shutdown().await;
                        let _ = tokio::time::timeout(
                            tokio::time::Duration::from_secs(5),
                            Self::drain_and_close_half(&mut clt_r, &mut ups_w),
                        ).await;
                        let _ = ups_w.shutdown().await;
                        Ok(())
                    }
                    Ok(n) => {
                        // 同样回填首块保证流连续后透明中继
                        let ups_r = io::Cursor::new(ups_buf[..n].to_vec()).chain(ups_r);
                        let _ = run_ftp_upload_audit_or_relay_bidi(
                            clt_r,
                            clt_w,
                            Box::new(ups_r),
                            ups_w,
                            ctx.idle_wheel.clone(),
                            ctx.max_idle_count,
                            None,
                        ).await;
                        Ok(())
                    }
                    Err(_) => {
                        let _ = clt_w.shutdown().await;
                        let _ = ups_w.shutdown().await;
                        Ok(())
                    }
                }
            }
        }
    }

    /// 半关闭排空：把 `r` 一侧剩余数据全部转发给 `w` 直到 EOF/出错，最后 flush。
    /// 用于对端 FIN 后尽量交付已发出的数据，避免截断文件。
    async fn drain_and_close_half<R, W>(r: &mut R, w: &mut W)
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 8192];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = w.flush().await;
    }
}

/// 查询并消耗一对 IP 上的待审上传标记：控制连接曾发过 STOR/APPE 时返回上传信息，
/// 否则返回 None。一次性消耗保证同一标记只被一条数据连接使用。
pub(crate) fn check_ftp_upload_data(
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> Option<PendingUploadInfo> {
    get_ftp_upload_state().consume_upload(client_addr.ip(), server_addr.ip())
}

/// 查询一对 IP 对应的 FTPS 服务器域名，供数据连接做 TLS 拦截（SNI 等）时使用；
/// 控制连接未登记过该 IP 对时返回 None。
pub(crate) fn get_ftps_domain(client_addr: SocketAddr, server_addr: SocketAddr) -> Option<String> {
    get_ftp_upload_state().get_ftps_domain(client_addr.ip(), server_addr.ip())
}
