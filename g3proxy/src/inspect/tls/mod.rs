/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! TLS 中间人（MITM）拦截的核心状态机与共享类型。
//!
//! 职责：从客户端读取并解析 ClientHello（提取 SNI/服务器名指示、ALPN/应用层协议
//! 协商），与上游完成 TLS 握手，按域名签发假证书（经 cert agent），再作为服务端
//! 接受客户端 TLS 握手，最终依据协商出的协议把流转移到 HTTP/SMTP/IMAP/FTP 等内层
//! 检测对象（见 `inspect_inner`）。主要类型：
//! - `TlsInterceptionContext`：可复用的 TLS 拦截配置（客户端/服务端 SSL 配置、
//!   cert agent、流量转储 dumper），由 audit 句柄提供。
//! - `TlsInterceptObject<SC>`：单条 TLS 流的拦截对象，持有双向 IO 与上下文。
//! - `ParsedClientHello`：ClientHello 中检测决策所需的关键字段。
//! 现代 TLS 与国密 TLCP 的握手流程分别实现在 modern.rs / tlcp.rs。

use std::sync::Arc;

use anyhow::anyhow;
use bytes::BytesMut;
use openssl::x509::X509VerifyResult;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::runtime::Handle;

use g3_cert_agent::CertAgentHandle;
use g3_codec::tls::{
    ClientHello, ExtensionType, HandshakeCoalescer, RawVersion, Record, RecordParseError,
};
use g3_dpi::{Protocol, ProtocolInspector};
use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple};
use g3_io_ext::{AsyncStream, FlexBufReader, OnceBufReader};
use g3_slog_types::{LtUpstreamAddr, LtUuid, LtX509VerifyResult};
use g3_types::net::{
    AlpnProtocol, OpensslInterceptionClientConfig, OpensslInterceptionServerConfig, TlsAlpn,
    TlsKeyLogBuffer, TlsServerName, UpstreamAddr,
};
use g3_udpdump::{
    ExportedPduDissectorHint, StreamDumpConfig, StreamDumpProxyAddresses, StreamDumper,
};

use super::{
    BoxAsyncRead, BoxAsyncWrite, InterceptionError, StreamInspectContext, StreamInspection,
};
use crate::config::server::ServerConfig;
use crate::log::inspect::{InspectSource, stream::StreamInspectLog};
use crate::serve::ServerTaskResult;

mod error;
pub(crate) use error::TlsInterceptionError;

mod modern;
#[cfg(feature = "vendored-tongsuo")]
mod tlcp;

/// 解析后的 ClientHello 关键字段：决定上游目标、TLS 版本分支与内层协议
pub(super) struct ParsedClientHello {
    /// legacy 版本字段：用于识别是否为 TLCP（国密）版本，走不同握手分支
    pub(super) version: RawVersion,
    /// 服务器名指示（SNI）扩展中的域名；客户端未带 SNI 时为 `None`
    pub(super) sni: Option<TlsServerName>,
    /// ALPN 扩展：客户端建议的应用层协议列表；未协商时为 `None`
    pub(super) alpn: Option<TlsAlpn>,
}

impl ParsedClientHello {
    /// 遍历扩展，提取 SNI 与 ALPN
    ///
    /// 任一扩展解析失败即整体报错（交由上层视为握手失败）；未出现的扩展保持
    /// `None`，版本直接取 ClientHello 的 legacy_version。
    pub(super) fn parse(ch: ClientHello<'_>) -> anyhow::Result<Self> {
        let mut sni: Option<TlsServerName> = None;
        let mut alpn: Option<TlsAlpn> = None;

        for ext in ch.ext_iter() {
            let ext = ext.map_err(|e| anyhow!("parse extension error: {e}"))?;
            // 扩展无数据体则跳过
            let Some(data) = ext.data() else {
                continue;
            };

            match ext.r#type() {
                ExtensionType::ServerName => {
                    let v = TlsServerName::from_extension_value(data)
                        .map_err(|e| anyhow!("invalid server name extension: {e}"))?;
                    sni = Some(v);
                }
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    let v = TlsAlpn::from_extension_value(data)
                        .map_err(|e| anyhow!("invalid ALPN extension: {e}"))?;
                    alpn = Some(v);
                }
                _ => {}
            }
        }

        Ok(ParsedClientHello {
            version: ch.legacy_version,
            sni,
            alpn,
        })
    }
}

/// TLS 拦截所需的可复用配置上下文（多任务共享）
///
/// 由 `AuditHandle` 在 server 启动时构造并持有，`StreamInspectContext`
/// 通过 `tls_interception()` 取出后传给 `TlsInterceptObject`。
#[derive(Clone)]
pub(crate) struct TlsInterceptionContext {
    /// 假证书签发代理：按域名向上游证书签发对应的伪造证书/私钥对
    pub(super) cert_agent: Arc<CertAgentHandle>,
    /// 作为客户端连上游时使用的 TLS 配置（含握手超时、SSL 上下文）
    pub(super) client_config: Arc<OpensslInterceptionClientConfig>,
    /// 作为服务端面对客户端时使用的 TLS 配置（含 accept 超时、SSL 上下文）
    pub(super) server_config: Arc<OpensslInterceptionServerConfig>,
    /// 每个 worker 一个流量转储器，用于 TLS 解密后的 pcap 风格转储
    stream_dumper: Arc<Vec<StreamDumper>>,
}

impl TlsInterceptionContext {
    /// 构造 TLS 拦截上下文
    ///
    /// 若配置了 `dump_config`，优先在每个 worker 线程上各建一个 `StreamDumper`；
    /// worker 列表为空时回退到在主 runtime 上按预期线程数创建。
    pub(crate) fn new(
        cert_agent: CertAgentHandle,
        client_config: OpensslInterceptionClientConfig,
        server_config: OpensslInterceptionServerConfig,
        dump_config: Option<StreamDumpConfig>,
    ) -> anyhow::Result<Self> {
        let mut stream_dumper = Vec::new();
        if let Some(dump) = dump_config {
            // 每个 worker runtime 线程创建一个 dumper，保证转储在该线程内完成
            g3_daemon::runtime::worker::foreach(|h| {
                let dumper = StreamDumper::new(dump, &h.handle).map_err(|e| {
                    anyhow!("failed to create tls stream dumper in worker {}: {e}", h.id)
                })?;
                stream_dumper.push(dumper);
                Ok::<(), anyhow::Error>(())
            })?;

            // 无 worker 线程（如单 runtime 部署）时，在主 runtime 上按线程数补齐
            if stream_dumper.is_empty() {
                let dump_count =
                    g3_daemon::runtime::config::get_runtime_config().intended_thread_number();
                let handle = Handle::current();
                for i in 0..dump_count {
                    let dumper = StreamDumper::new(dump, &handle).map_err(|e| {
                        anyhow!("failed to create tls stream dumper #{i} in main runtime: {e}")
                    })?;
                    stream_dumper.push(dumper);
                }
            }
        }

        Ok(TlsInterceptionContext {
            cert_agent: Arc::new(cert_agent),
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
            stream_dumper: Arc::new(stream_dumper),
        })
    }

    /// 取出当前 worker 对应的流量转储器
    ///
    /// 未配置转储返回 `None`；有 worker id 且能索引到则精确匹配，否则随机选一个
    /// （避免单一线程过载）。
    pub(super) fn get_stream_dumper(&self, worker_id: Option<usize>) -> Option<&StreamDumper> {
        if self.stream_dumper.is_empty() {
            return None;
        }

        if let Some(id) = worker_id
            && let Some(d) = self.stream_dumper.get(id)
        {
            return Some(d);
        }

        fastrand::choice(self.stream_dumper.iter())
    }

    /// 读取并解析 ClientHello，带客户端握手超时保护
    ///
    /// 超时转为 `ClientHandshakeTimeout`，内部解析错误转为 `ClientHandshakeFailed`。
    /// `clt_r_buf` 为已预读的缓冲，避免重复读取。
    pub(super) async fn read_client_hello<R>(
        &mut self,
        clt_r: &mut R,
        clt_r_buf: &mut BytesMut,
    ) -> Result<ParsedClientHello, TlsInterceptionError>
    where
        R: AsyncRead + Unpin,
    {
        tokio::time::timeout(
            self.server_config.client_hello_recv_timeout,
            self.do_read_client_hello(clt_r, clt_r_buf),
        )
        .await
        .map_err(|_| TlsInterceptionError::ClientHandshakeTimeout)?
        .map_err(TlsInterceptionError::ClientHandshakeFailed)
    }

    /// ClientHello 读取的核心循环
    ///
    /// TLS 记录可能分多个 TCP 段、握手消息甚至跨记录分片，因此用
    /// `HandshakeCoalescer` 持续聚合记录直到能解析出完整的 ClientHello。
    /// `record_offset` 标记已消费的记录边界，每轮只在新数据上继续解析。
    async fn do_read_client_hello<R>(
        &mut self,
        clt_r: &mut R,
        clt_r_buf: &mut BytesMut,
    ) -> anyhow::Result<ParsedClientHello>
    where
        R: AsyncRead + Unpin,
    {
        let mut handshake_coalescer =
            HandshakeCoalescer::new(self.server_config.client_hello_max_size);
        let mut record_offset = 0;

        loop {
            // 在已缓冲字节上尝试解析一条 TLS 记录
            let mut record = match Record::parse(&clt_r_buf[record_offset..]) {
                Ok(r) => r,
                // 数据不足：继续从 socket 读，读空说明客户端关闭连接
                Err(RecordParseError::NeedMoreData(_)) => match clt_r.read_buf(clt_r_buf).await {
                    Ok(0) => {
                        return Err(anyhow!("connection closed by client"));
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        return Err(anyhow!("client read error: {e}"));
                    }
                },
                Err(_) => {
                    return Err(anyhow!("invalid tls client hello request"));
                }
            };
            // 该记录已完整解析，推进偏移到下一条记录
            record_offset += record.encoded_len();

            // The Client Hello Message MUST be the first Handshake message
            // （ClientHello 必须是首个握手消息）
            match record.consume_handshake(&mut handshake_coalescer) {
                // 单条记录即含完整握手消息
                Ok(Some(handshake_msg)) => {
                    let ch = handshake_msg
                        .parse_client_hello()
                        .map_err(|_| anyhow!("invalid tls client hello request"))?;
                    return ParsedClientHello::parse(ch);
                }
                // 握手消息跨记录：尝试从聚合器解析
                Ok(None) => match handshake_coalescer.parse_client_hello() {
                    Ok(Some(ch)) => return ParsedClientHello::parse(ch),
                    Ok(None) => {
                        // 聚合器仍未凑齐，且本记录未吃完——分片不完整，判定无效
                        if !record.consume_done() {
                            return Err(anyhow!("partial fragmented tls client hello request"));
                        }
                    }
                    Err(_) => {
                        return Err(anyhow!("invalid fragmented tls client hello request"));
                    }
                },
                Err(_) => {
                    return Err(anyhow!("invalid tls client hello request"));
                }
            }
        }
    }
}

/// 单条 TLS 流的双向明文 IO（拆分后的读写半部 + 客户端预读缓冲）
struct TlsInterceptIo {
    /// 客户端侧预读缓冲，已读入但尚未消费的字节（如 ClientHello 之后的数据）
    pub(super) clt_r_buf: BytesMut,
    pub(super) clt_r: BoxAsyncRead,
    pub(super) clt_w: BoxAsyncWrite,
    pub(super) ups_r: BoxAsyncRead,
    pub(super) ups_w: BoxAsyncWrite,
}

/// TLS 拦截对象：代表"某条流正处于 TLS 中间人拦截"这一状态
///
/// 持有上下文 `ctx`、上游地址 `upstream`、共享的 `tls_interception` 配置，以及
/// 握手过程中逐步填充的信息（上游证书校验结果 `server_verify_result`、用于
/// 解密流量的 `keylog_buffer`）。握手完成后通过 `transfer_connected` 把流交还给
/// 内层协议检测对象。
pub(crate) struct TlsInterceptObject<SC: ServerConfig> {
    /// 双向 IO；`do_intercept` 通过 `take` 取出，握手后重新装回或交给下游
    io: Option<TlsInterceptIo>,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    tls_interception: TlsInterceptionContext,
    /// 上游真实证书的校验结果；握手前为 `None`，完成后填充用于审计日志
    server_verify_result: Option<X509VerifyResult>,
    /// TLS keylog buffer for the upstream TLS connection
    /// 上游 TLS 连接的密钥日志缓冲：供外部工具（如 Wireshark）解密转储流量
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

/// 输出 TLS 握手拦截审计日志的宏
///
/// 统一带上任务 ID、嵌套深度、上游地址、上游证书校验结果等字段，便于按任务关联。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "TlsHandshake",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
                "tls_server_verify" => $obj.server_verify_result.map(LtX509VerifyResult),
            );
        }
    };
}

impl<SC: ServerConfig> TlsInterceptObject<SC> {
    /// 创建 TLS 拦截对象；此时 IO、上游校验结果与 keylog 均未就绪
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upstream: UpstreamAddr,
        tls: TlsInterceptionContext,
    ) -> Self {
        TlsInterceptObject {
            io: None,
            ctx,
            upstream,
            tls_interception: tls,
            server_verify_result: None,
            keylog_buffer: None,
        }
    }

    /// 注入双向明文 IO 与客户端预读缓冲（进入本状态前由上游建连阶段准备好）
    pub(crate) fn set_io(
        &mut self,
        clt_r_buf: BytesMut,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = TlsInterceptIo {
            clt_r_buf,
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 握手成功后输出审计日志
    fn log_ok(&self) {
        intercept_log!(self, "ok");
    }

    /// 握手失败时输出拦截审计日志
    fn log_err(&self, e: &TlsInterceptionError) {
        intercept_log!(self, "{e}");
    }

    /// 判断 ALPN 协议是否应保留（即其对应的检测策略不要求拦截）
    ///
    /// 返回 `false` 表示该协议（如被 block 的 H2/SMTP/IMAP）不应出现在
    /// 转发给上游的 ALPN 列表中。
    fn retain_alpn_protocol(&self, p: &[u8]) -> bool {
        if p == AlpnProtocol::Http2.identification_sequence() {
            return !self.ctx.h2_inspect_action(self.upstream.host()).is_block();
        } else if p == AlpnProtocol::Smtp.identification_sequence() {
            return !self
                .ctx
                .smtp_inspect_action(self.upstream.host())
                .is_block();
        } else if p == AlpnProtocol::Imap.identification_sequence() {
            return !self
                .ctx
                .imap_inspect_action(self.upstream.host())
                .is_block();
        }
        true
    }
}

impl<SC> TlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 执行 TLS 拦截：根据握手结果返回下一检测状态或终止错误
    ///
    /// 成功/失败都会输出对应的拦截审计日志，并把错误统一映射为
    /// `ServerTaskError`（附带 `Protocol::TlsModern` 标识）。
    pub(crate) async fn intercept(
        mut self,
        inspector: &mut ProtocolInspector,
    ) -> ServerTaskResult<StreamInspection<SC>> {
        match self.do_intercept(inspector).await {
            Ok(obj) => {
                self.log_ok();
                Ok(obj)
            }
            Err(e) => {
                self.log_err(&e);
                Err(InterceptionError::Tls(e).into_server_task_error(Protocol::TlsModern))
            }
        }
    }

    /// 拦截主流程：读 ClientHello -> 按版本分流到现代 TLS 或 TLCP 处理
    async fn do_intercept(
        &mut self,
        inspector: &mut ProtocolInspector,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        // 取出 IO 以便借用客户端读半部解析 ClientHello
        let TlsInterceptIo {
            mut clt_r_buf,
            mut clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let client_hello = self
            .tls_interception
            .read_client_hello(&mut clt_r, &mut clt_r_buf)
            .await?;

        // 解析后重新装回 IO（缓冲可能已追加新数据，需保留）
        self.set_io(clt_r_buf, clt_r, clt_w, ups_r, ups_w);

        if client_hello.version.is_tlcp() {
            self.do_intercept_tlcp(client_hello, inspector).await
        } else {
            self.do_intercept_modern(client_hello, inspector).await
        }
    }

    /// 未编译 TLCP（tongsuo）特性时的回退分支
    ///
    /// TLCP 流量降级为未知流：不拦截 TLS，交由"未知协议应被按需禁止"的策略处理。
    #[cfg(not(feature = "vendored-tongsuo"))]
    async fn do_intercept_tlcp(
        &mut self,
        _client_hello: ParsedClientHello,
        _inspector: &mut ProtocolInspector,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        let TlsInterceptIo {
            clt_r_buf,
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        let mut stream_obj = crate::inspect::stream::StreamInspectObject::new(
            self.ctx.clone(),
            self.upstream.clone(),
        );
        // 把已预读的缓冲重新拼回读流，避免 ClientHello 之后的数据丢失
        stream_obj.set_io(
            Box::new(OnceBufReader::new(clt_r, clt_r_buf)),
            Box::new(clt_w),
            Box::new(ups_r),
            Box::new(ups_w),
        );
        // TLCP is not supported in this build mode, treat it as unknown protocol.
        // Unknown protocol should be forbidden if needed.
        // （当前构建不支持 TLCP，按未知协议处理，由上层策略决定是否禁止）
        Ok(StreamInspection::StreamUnknown(stream_obj))
    }

    /// TLS 握手完成后，把已建立的双向 TLS 流转移到下一检测状态
    ///
    /// `has_alpn` 标记客户端是否通过 ALPN 明确协商出应用层协议：若有则后续按
    /// 未知流继续探测，否则直接进入内容检测。若启用了流量转储，则按配置在
    /// 客户端侧或远端侧包裹 dumper。
    fn transfer_connected<CS, US>(
        &self,
        protocol: Protocol,
        has_alpn: bool,
        clt_s: CS,
        ups_s: US,
    ) -> StreamInspection<SC>
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

        if let Some(stream_dumper) = self
            .tls_interception
            .get_stream_dumper(self.ctx.task_notes.worker_id)
        {
            // 有专用 Wireshark dissector 的协议按其解析，否则用 TLS 端口提示
            let dissector_hint = if !protocol.wireshark_dissector().is_empty() {
                ExportedPduDissectorHint::Protocol(protocol)
            } else {
                ExportedPduDissectorHint::TlsPort(self.upstream.port())
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
                self.inspect_inner(protocol, has_alpn, clt_r, clt_w, ups_r, ups_w)
            } else {
                let (ups_r, ups_w) =
                    stream_dumper.wrap_proxy_remote_io(addresses, dissector_hint, ups_r, ups_w);
                self.inspect_inner(protocol, has_alpn, clt_r, clt_w, ups_r, ups_w)
            }
        } else {
            self.inspect_inner(protocol, has_alpn, clt_r, clt_w, ups_r, ups_w)
        }
    }

    /// 为内层检测准备上下文：克隆并递增嵌套检测深度，同时输出检测日志
    ///
    /// 深度递增保证内层协议（如 TLS 内的 HTTP）有独立的层标识，便于审计与
    /// 防止递归失控。
    fn prepare_ctx(&self, protocol: Protocol) -> StreamInspectContext<SC> {
        let mut ctx = self.ctx.clone();
        ctx.increase_inspection_depth();
        StreamInspectLog::new(&ctx).log(InspectSource::TlsAlpn, protocol);
        ctx
    }

    /// 通用路径：根据协商协议建立"未知流/内容检测"对象
    ///
    /// 当 ALPN 已协商（`has_alpn`）时走 `StreamUnknown`（继续协议探测），
    /// 否则直接进入 `StreamInspect` 内容审查。
    fn build_stream_inspect<CR, CW, UR, UW>(
        &self,
        protocol: Protocol,
        has_alpn: bool,
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
        let ctx = self.prepare_ctx(protocol);
        let mut stream_obj =
            crate::inspect::stream::StreamInspectObject::new(ctx, self.upstream.clone());
        stream_obj.set_io(
            Box::new(clt_r),
            Box::new(clt_w),
            Box::new(ups_r),
            Box::new(ups_w),
        );
        if has_alpn {
            StreamInspection::StreamUnknown(stream_obj)
        } else {
            StreamInspection::StreamInspect(stream_obj)
        }
    }

    /// 依据协商出的协议，把 TLS 内的明文流分发到对应应用层检测对象
    ///
    /// 这是 TLS 拦截后"进入内层协议"的转移表：HTTP/1、HTTP/2、SMTP、IMAP、
    /// FTP 控制各有专门对象；未知协议时还要按端口/FTPS 标记判断是否为 FTP
    /// 控制通道或上传数据通道。
    fn inspect_inner<CR, CW, UR, UW>(
        &self,
        protocol: Protocol,
        has_alpn: bool,
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
        match protocol {
            Protocol::Http1 => {
                let ctx = self.prepare_ctx(protocol);
                let mut h1_obj =
                    crate::inspect::http::H1InterceptObject::new(ctx, self.keylog_buffer.clone());
                h1_obj.set_io(
                    FlexBufReader::new(Box::new(clt_r)),
                    Box::new(clt_w),
                    Box::new(ups_r),
                    Box::new(ups_w),
                );
                StreamInspection::H1(h1_obj)
            }
            Protocol::Http2 => {
                let ctx = self.prepare_ctx(protocol);
                let mut h2_obj = crate::inspect::http::H2InterceptObject::new(
                    ctx,
                    self.upstream.clone(),
                    self.keylog_buffer.clone(),
                );
                h2_obj.set_io(
                    OnceBufReader::with_no_buf(Box::new(clt_r)),
                    Box::new(clt_w),
                    Box::new(ups_r),
                    Box::new(ups_w),
                );
                StreamInspection::H2(h2_obj)
            }
            Protocol::Smtp => {
                let ctx = self.prepare_ctx(protocol);
                let mut smtp_obj =
                    crate::inspect::smtp::SmtpInterceptObject::new(ctx, self.upstream.clone());
                smtp_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Smtp(smtp_obj)
            }
            Protocol::Imap => {
                let ctx = self.prepare_ctx(protocol);
                let mut imap_obj =
                    crate::inspect::imap::ImapInterceptObject::new(ctx, self.upstream.clone());
                imap_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Imap(imap_obj)
            }
            Protocol::FtpControl => {
                let ctx = self.prepare_ctx(protocol);
                let mut ftp_obj =
                    crate::inspect::ftp::FtpInterceptObject::new(ctx, self.upstream.clone());
                ftp_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::with_no_buf(Box::new(ups_r)),
                    Box::new(ups_w),
                );
                StreamInspection::Ftp(ftp_obj)
            }
            Protocol::Unknown => {
                // FTP control ports (21, 990) running over FTPS are still
                // control channels: route them to FtpInterceptObject so the
                // STOR/APPE command can be parsed.
                // 跑在 FTPS 上的 FTP 控制端口(21/990)仍是控制通道，需走 Ftp 对象
                // 以便解析 STOR/APPE 命令。
                let port = self.upstream.port();
                if port == 21 || port == 990 {
                    let ctx = self.prepare_ctx(protocol);
                    let mut ftp_obj =
                        crate::inspect::ftp::FtpInterceptObject::new(ctx, self.upstream.clone());
                    ftp_obj.set_io(
                        Box::new(clt_r),
                        Box::new(clt_w),
                        OnceBufReader::with_no_buf(Box::new(ups_r)),
                        Box::new(ups_w),
                    );
                    return StreamInspection::Ftp(ftp_obj);
                }

                // For FTPS data channels: try the pending upload mark. In
                // passive mode the data channel connects (and completes TLS)
                // *before* STOR is sent on the control channel, so the mark
                // may not exist yet. If the server IP is known FTPS, fall
                // back to deferred checking inside intercept_pending.
                // FTPS 数据通道：先查"待上传"标记。被动模式下数据通道会在控制通道
                // 发出 STOR 之前完成连接与 TLS 握手，因此标记可能尚未写入；若该服务器
                // IP 确为已知 FTPS，则推迟到 intercept_pending 内再判定。
                let upload_info = crate::inspect::ftp::check_ftp_upload_data(
                    self.ctx.task_notes.client_addr,
                    self.ctx.connect_notes.server_addr,
                );
                let upload_info = match upload_info {
                    Some(info) => Some(info),
                    None => {
                        if crate::inspect::ftp::get_ftps_domain(
                            self.ctx.task_notes.client_addr,
                            self.ctx.connect_notes.server_addr,
                        )
                        .is_some()
                        {
                            None
                        } else {
                            return self.build_stream_inspect(
                                protocol, has_alpn, clt_r, clt_w, ups_r, ups_w,
                            );
                        }
                    }
                };

                // 数据通道四元组：用于将上传流量与控制通道会话关联
                let data_channel_tuple = Some(ConnectionTuple {
                    server_addr: self.ctx.connect_notes.client_addr,
                    remote_addr: self.ctx.connect_notes.server_addr,
                    protocol: ConnectionProtocol::Tcp,
                });

                let ctx = self.prepare_ctx(protocol);
                let mut ftp_upload_obj = crate::inspect::ftp::FtpUploadDataInterceptObject::new(
                    ctx,
                    upload_info,
                    data_channel_tuple,
                    self.keylog_buffer.clone(),
                );
                ftp_upload_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    Box::new(ups_r),
                    Box::new(ups_w),
                );
                StreamInspection::FtpUploadData(ftp_upload_obj)
            }
            // 其余协议走通用路径（按 ALPN 是否协商选择未知流/内容检测）
            _ => self.build_stream_inspect(protocol, has_alpn, clt_r, clt_w, ups_r, ups_w),
        }
    }
}
