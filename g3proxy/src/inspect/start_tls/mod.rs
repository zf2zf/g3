/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! STARTTLS 类"明文升级"协议的检测与拦截。
//!
//! SMTP/IMAP/FTP 等协议先在明文信道上协商（如 `STARTTLS`/`TLS-C` 命令），
//! 随后在同一连接上直接切换为 TLS 记录层。本模块负责在这次切换处完成 TLS
//! 握手拦截（含国密 TLCP），握手成功后再把解密后的明文流交回对应协议的
//! 拦截对象继续检测。
//!
//! ClientHello 等已消费的不完整读取（incomplete read）字节通过
//! `OnceBufReader` 回灌，保证下游读到的是完整无损的字节流。
//!
//! 主要类型：[`StartTlsInterceptObject`]（检测对象）与 [`StartTlsProtocol`]
//! （被升级的承载协议）。当 SMTP/IMAP/FTP 拦截对象在控制信道上检测到升级命令时，
//! 检测状态机便转移到本模块。

use bytes::BytesMut;
use openssl::x509::X509VerifyResult;
use tokio::io::{AsyncRead, AsyncWrite};

use std::sync::Arc;

use g3_dpi::Protocol;
use g3_io_ext::{AsyncStream, OnceBufReader};
use g3_slog_types::{LtUpstreamAddr, LtUuid, LtX509VerifyResult};
use g3_types::net::{TlsKeyLogBuffer, TlsServiceType, UpstreamAddr};
use g3_udpdump::{ExportedPduDissectorHint, StreamDumpProxyAddresses};

#[cfg(not(feature = "vendored-tongsuo"))]
use super::tls::ParsedClientHello;
use super::{
    BoxAsyncRead, BoxAsyncWrite, InterceptionError, StreamInspectContext, StreamInspection,
    TlsInterceptionContext,
};
use crate::config::server::ServerConfig;
use crate::inspect::tls::TlsInterceptionError;
use crate::log::inspect::InspectSource;
use crate::log::inspect::stream::StreamInspectLog;
use crate::serve::ServerTaskResult;

// 国密 TLCP 升级流程仅在 tongsuo（带 SM2/SM3/SM4 的 OpenSSL 分支）构建下可用
#[cfg(feature = "vendored-tongsuo")]
mod tlcp;
// 标准 TLS 升级流程
mod tls;

/// 统一的 STARTTLS 拦截审计日志：固定附带拦截类型、任务 ID、检测层数、
/// 上游地址、承载协议与源站证书校验结果，成功与失败分支共用同一字段集合
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "StartTlsHandshake",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "protocol" => Protocol::from($obj.protocol).as_str(),
                "tls_server_verify" => $obj.server_verify_result.map(LtX509VerifyResult),
            );
        }
    };
}

/// 发生 TLS 升级的承载协议。
///
/// 决定升级完成后把明文流量交还给哪个协议拦截对象，以及伪造证书时使用的
/// `TlsServiceType`（不同协议的证书/会话复用要求不同）。
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum StartTlsProtocol {
    /// SMTP：`STARTTLS` 命令后升级
    Smtp,
    /// IMAP：`STARTTLS` 命令后升级
    #[allow(unused)]
    Imap,
    /// FTP：`AUTH TLS` 命令后升级（控制通道）
    Ftp,
}

impl From<StartTlsProtocol> for Protocol {
    /// 映射回 g3_dpi 的协议标识，供检测日志与识别器使用。
    /// 注意 FTP 对应的是控制通道协议 `FtpControl`，而非数据通道
    fn from(value: StartTlsProtocol) -> Self {
        match value {
            StartTlsProtocol::Smtp => Protocol::Smtp,
            StartTlsProtocol::Imap => Protocol::Imap,
            StartTlsProtocol::Ftp => Protocol::FtpControl,
        }
    }
}

impl From<StartTlsProtocol> for TlsServiceType {
    /// 映射为 TLS 客户端/服务类型，用于选择对应的 TLS 配置与伪造证书用途
    fn from(value: StartTlsProtocol) -> Self {
        match value {
            StartTlsProtocol::Smtp => TlsServiceType::Smtp,
            StartTlsProtocol::Imap => TlsServiceType::Imap,
            StartTlsProtocol::Ftp => TlsServiceType::Ftp,
        }
    }
}

/// STARTTLS 拦截阶段暂存的四路 IO 半部（明文 TCP 上的客户端/源站读写端）
struct StartTlsInterceptIo {
    pub(super) clt_r: BoxAsyncRead,
    pub(super) clt_w: BoxAsyncWrite,
    pub(super) ups_r: BoxAsyncRead,
    pub(super) ups_w: BoxAsyncWrite,
}

/// STARTTLS 升级阶段的拦截对象。
///
/// 由协议拦截对象（SMTP/IMAP/FTP）在检测到升级命令后创建，负责在切换点
/// 完成"对源站的 TLS 客户端握手 + 对客户端的 TLS 服务端握手"这一 MITM 过程，
/// 成功后把解密的双向明文流交给对应协议对象继续检测。
pub(crate) struct StartTlsInterceptObject<SC: ServerConfig> {
    /// 明文四路半部；握手消费后已被替换成 TLS 流，故此处用 `Option` 一次性取出
    io: Option<StartTlsInterceptIo>,
    ctx: StreamInspectContext<SC>,
    /// 上游地址。若 ClientHello 带 SNI，握手前会用 SNI 覆盖其中的主机名
    upstream: UpstreamAddr,
    tls_interception: TlsInterceptionContext,
    protocol: StartTlsProtocol,
    /// 源站证书校验结果；未完成与源站的 TLS 握手前为 `None`
    server_verify_result: Option<X509VerifyResult>,
    /// TLS 会话密钥缓冲区；审计未开启 keylog 时为 `None`
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC> StartTlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建 STARTTLS 拦截对象，此时明文 IO 尚未装配
    pub(super) fn new(
        ctx: StreamInspectContext<SC>,
        upstream: UpstreamAddr,
        tls: TlsInterceptionContext,
        protocol: StartTlsProtocol,
    ) -> Self {
        StartTlsInterceptObject {
            io: None,
            ctx,
            upstream,
            tls_interception: tls,
            protocol,
            server_verify_result: None,
            keylog_buffer: None,
        }
    }

    /// 装配升级点上的明文四路半部
    pub(super) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = StartTlsInterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 拦截入口：执行 STARTTLS 升级握手，并把结果统一转成带审计日志的返回值。
    ///
    /// 失败时把 `TlsInterceptionError` 包装成对应协议（按 `Protocol::TlsModern`
    /// 归因）的 `ServerTaskError` 上抛，让服务层按 TLS 失败统计。
    pub(super) async fn intercept(mut self) -> ServerTaskResult<StreamInspection<SC>> {
        match self.do_intercept().await {
            Ok(obj) => {
                intercept_log!(self, "ok");
                Ok(obj)
            }
            Err(e) => {
                // 失败同样落一条日志，便于区分是源站握手、证书签发还是客户端握手出错
                intercept_log!(self, "{e}");
                Err(InterceptionError::StartTls(e).into_server_task_error(Protocol::TlsModern))
            }
        }
    }

    /// 先读取客户端在升级点发出的 ClientHello（可能是不完整读取，需缓冲补齐），
    /// 再按其版本分派到普通 TLS 或国密 TLCP 流程。
    ///
    /// 读取完成后把（可能仍带残留数据的）四路 IO 放回 `self`，供后续分派取出。
    async fn do_intercept(&mut self) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        let StartTlsInterceptIo {
            mut clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let mut clt_r_buf = BytesMut::with_capacity(2048);
        let client_hello = self
            .tls_interception
            .read_client_hello(&mut clt_r, &mut clt_r_buf)
            .await?;

        self.set_io(clt_r, clt_w, ups_r, ups_w);
        if client_hello.version.is_tlcp() {
            self.do_intercept_tlcp(client_hello, clt_r_buf).await
        } else {
            self.do_intercept_tls(client_hello, clt_r_buf).await
        }
    }

    /// 非 tongsuo 构建下的 TLCP 兜底实现：无法解析国密握手，
    /// 因此把这条流降级为"协议未知"的裸流拦截对象，
    /// 由用户级 `prohibit_unknown_protocol` 策略决定是否封禁。
    #[cfg(not(feature = "vendored-tongsuo"))]
    pub(super) async fn do_intercept_tlcp(
        &mut self,
        _client_hello: ParsedClientHello,
        clt_r_buf: BytesMut,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        let StartTlsInterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let mut stream_obj = crate::inspect::stream::StreamInspectObject::new(
            self.ctx.clone(),
            self.upstream.clone(),
        );
        stream_obj.set_io(
            // 已读取的 ClientHello 字节必须回灌，否则裸流转发会丢数据
            Box::new(OnceBufReader::new(clt_r, clt_r_buf)),
            Box::new(clt_w),
            Box::new(ups_r),
            Box::new(ups_w),
        );
        // TLCP is not supported in this build mode, treat it as unknown protocol.
        // Unknown protocol should be forbidden if needed.
        // 中文说明：当前构建不支持 TLCP，按未知协议处理；需要时由未知协议封禁策略拦截。
        Ok(StreamInspection::StreamUnknown(stream_obj))
    }

    /// TLS 握手成功后的收尾：拆分双向半部，按需接入报文导出（dump），
    /// 再交给协议拦截对象继续检测。
    ///
    /// 抓包导出只包装其中一侧（客户端侧或源站侧），避免同一份明文被记录两次。
    fn transfer_connected<CS, US>(&self, clt_s: CS, ups_s: US) -> StreamInspection<SC>
    where
        CS: AsyncStream,
        CS::R: AsyncRead + Send + Sync + Unpin + 'static,
        CS::W: AsyncWrite + Send + Sync + Unpin + 'static,
        US: AsyncStream,
        US::R: AsyncRead + Send + Sync + Unpin + 'static,
        US::W: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let (clt_r, clt_w) = clt_s.into_split();
        let (ups_r, ups_w) = ups_s.into_split();

        let protocol = Protocol::from(self.protocol);
        if let Some(stream_dumper) = self
            .tls_interception
            .get_stream_dumper(self.ctx.task_notes.worker_id)
        {
            // 优先用协议名作为 Wireshark 解析线索，协议无名时退回目标端口
            let dissector_hint = if !protocol.wireshark_dissector().is_empty() {
                ExportedPduDissectorHint::Protocol(protocol)
            } else {
                ExportedPduDissectorHint::TcpPort(self.upstream.port())
            };
            let addresses = StreamDumpProxyAddresses {
                client: self.ctx.task_notes.client_addr,
                local_server: self.ctx.task_notes.server_addr,
                local_client: self.ctx.connect_notes.client_addr,
                remote: self.ctx.connect_notes.server_addr,
            };
            if stream_dumper.client_side() {
                let (clt_r, clt_w) =
                    stream_dumper.wrap_proxy_client_io(addresses, dissector_hint, clt_r, clt_w);
                self.inspect_inner(protocol, clt_r, clt_w, ups_r, ups_w)
            } else {
                let (ups_r, ups_w) =
                    stream_dumper.wrap_proxy_remote_io(addresses, dissector_hint, ups_r, ups_w);
                self.inspect_inner(protocol, clt_r, clt_w, ups_r, ups_w)
            }
        } else {
            self.inspect_inner(protocol, clt_r, clt_w, ups_r, ups_w)
        }
    }

    /// 按承载协议把解密后的明文流交还给对应的拦截对象（检测循环的下一状态）。
    ///
    /// 升级完成即进入新的一层检测，因此先递增检测层数并记录一条
    /// `InspectSource::StartTls` 来源的检测日志。
    /// `OnceBufReader::with_no_buf` 表示此处无残留字节需要回灌，仅借用其类型包装。
    fn inspect_inner<CR, CW, UR, UW>(
        &self,
        protocol: Protocol,
        clt_r: CR,
        clt_w: CW,
        ups_r: UR,
        ups_w: UW,
    ) -> StreamInspection<SC>
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let mut ctx = self.ctx.clone();
        ctx.increase_inspection_depth();
        StreamInspectLog::new(&ctx).log(InspectSource::StartTls, protocol);
        match self.protocol {
            StartTlsProtocol::Smtp => {
                // 标记来源为 STARTTLS，邮件对象据此跳过明文命令阶段的会话状态假设
                let mut smtp_obj =
                    crate::inspect::smtp::SmtpInterceptObject::new(ctx, self.upstream.clone());
                smtp_obj.set_from_starttls();
                smtp_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Smtp(smtp_obj)
            }
            StartTlsProtocol::Imap => {
                let mut imap_obj =
                    crate::inspect::imap::ImapInterceptObject::new(ctx, self.upstream.clone());
                imap_obj.set_from_starttls();
                imap_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Imap(imap_obj)
            }
            StartTlsProtocol::Ftp => {
                // 升级后的 FTP 控制通道继续由 FTP 拦截对象处理（数据通道另行检测）
                let mut ftp_obj =
                    crate::inspect::ftp::FtpInterceptObject::new(ctx, self.upstream.clone());
                ftp_obj.set_from_starttls();
                ftp_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Ftp(ftp_obj)
            }
        }
    }
}
