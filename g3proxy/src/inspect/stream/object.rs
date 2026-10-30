/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 裸 TCP 流检测阶段的拦截对象。
//!
//! [`StreamInspectObject`] 是检测流水线中"协议尚未确定"时所处的一环：
//! 缓存客户端与源站的首段数据，交给 `g3_dpi` 的 `ProtocolInspector` 判定协议，
//! 然后据结果生成 TLS / HTTP / SMTP / IMAP / FTP 等具体拦截对象，
//! 或在无法识别（未知、超时、绕过）时退回透明转发并结束检测。
//!
//! 已消费的首段字节通过 `OnceBufReader` / `FlexBufReader` 重新拼接回读流，
//! 保证下游协议解析器看到的是完整、未丢失的原始数据。

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use g3_dpi::{Protocol, ProtocolInspectError, ProtocolInspector};
use g3_io_ext::{FlexBufReader, OnceBufReader};
use g3_types::net::UpstreamAddr;

use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple};

use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamInspection};
use crate::log::inspect::InspectSource;
use crate::log::inspect::stream::StreamInspectLog;
use crate::serve::{ServerTaskError, ServerTaskResult};

/// 首段数据由哪一侧先发出。
///
/// DPI 既可能由客户端请求触发（大多数协议），也可能由源站先主动推送
/// （例如 SMTP/FTP 这类服务端先发 banner 的协议），识别入口因此不同。
enum InitialDataSource {
    /// 客户端先发送数据
    Client,
    /// 源站先发送数据
    Server,
}

/// 检测阶段暂存的四路原始字节半部。
///
/// 以 `Option` 持有：对象在状态机之间传递时通过 `take()` 一次性移出 IO，
/// 避免同一连接被两个检测对象同时持有。
struct StreamInspectIo {
    clt_r: BoxAsyncRead,
    clt_w: BoxAsyncWrite,
    ups_r: BoxAsyncRead,
    ups_w: BoxAsyncWrite,
}

/// 裸 TCP 流检测阶段的拦截对象。
pub(crate) struct StreamInspectObject<SC: ServerConfig> {
    /// 尚未被移出的 IO 半部；进入转发或转移到下游对象后即被 take 置空
    io: Option<StreamInspectIo>,
    pub(super) ctx: StreamInspectContext<SC>,
    /// 上游目标地址，既用于 DPI 的端口线索，也用于下游拦截对象建连
    upstream: UpstreamAddr,
}

impl<SC> StreamInspectObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建检测对象，此时 IO 尚未装配（需再调用
    /// [`StreamInspectObject::set_io`]）
    pub(crate) fn new(ctx: StreamInspectContext<SC>, upstream: UpstreamAddr) -> Self {
        StreamInspectObject {
            io: None,
            ctx,
            upstream,
        }
    }

    /// 装配四路 IO 半部，使对象具备读取首段数据进行协议识别的能力
    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = StreamInspectIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    /// 本协议检测链的终点：不再识别，直接按未知协议透明转发。
    ///
    /// 与 [`StreamInspectObject::transit_with_inspection`] 不同，这里不产出新状态；
    /// 若此前已缓冲过部分字节，需由装配方在 `set_io` 时用缓冲读取器接回，
    /// 本方法不关心缓冲的存在。
    pub(super) async fn transit_inspect_unknown(mut self) -> ServerTaskResult<()> {
        let StreamInspectIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.ctx
            .transit_inspect_unknown(clt_r, clt_w, ups_r, ups_w)
            .await
    }

    /// 读取并识别首段数据，随后按识别结果转移到对应的下游拦截对象。
    ///
    /// 流程：等待首包（`data0_wait_timeout`）→ 采样识别（`data0_read_timeout`）
    /// → 递增检测层数并打日志 → 分派。返回的 `StreamInspection` 交给
    /// 上层的检测循环继续驱动；`StreamInspection::End` 表示本层已转发完毕、检测结束。
    pub(super) async fn transit_with_inspection(
        mut self,
        inspector: &mut ProtocolInspector,
    ) -> ServerTaskResult<StreamInspection<SC>> {
        let StreamInspectIo {
            mut clt_r,
            clt_w,
            mut ups_r,
            ups_w,
        } = self.io.take().unwrap();

        // 两侧各准备一个采样缓冲，容量由检测配置统一给定
        let inspect_buffer_size = self.ctx.protocol_inspection().data0_buffer_size();
        let mut clt_r_buf = BytesMut::with_capacity(inspect_buffer_size);
        let mut ups_r_buf = BytesMut::with_capacity(inspect_buffer_size);

        // 第一步：等哪一侧先出声。超时说明是一条完全静默的空闲连接，直接关闭
        let data0_wait_timeout = self.ctx.protocol_inspection().data0_wait_timeout();
        let data_source = match tokio::time::timeout(
            data0_wait_timeout,
            self.wait_initial_data(&mut clt_r, &mut clt_r_buf, &mut ups_r, &mut ups_r_buf),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // just close IDLE empty connections
                // （纯空闲且无任何数据的连接没有检测价值，按空闲超时丢弃）
                return Err(ServerTaskError::Idle(data0_wait_timeout, 1));
            }
        };

        // 第二步：持续采样直到 DPI 能给出结论；这一步整体超时则判为 Protocol::Timeout
        let protocol = match tokio::time::timeout(
            self.ctx.protocol_inspection().data0_read_timeout(),
            self.inspect_initial_data(
                data_source,
                inspector,
                &mut clt_r,
                &mut clt_r_buf,
                &mut ups_r,
                &mut ups_r_buf,
            ),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => return Err(e),
            Err(_) => Protocol::Timeout,
        };

        // 进入下一层检测前递增层数，供 skip_next_inspection 判断是否继续嵌套
        self.ctx.increase_inspection_depth();
        StreamInspectLog::new(&self.ctx).log(InspectSource::StreamInspection, protocol);
        match protocol {
            Protocol::Unknown => {
                // For non-TLS FTP data channels (plain FTP over HTTP CONNECT):
                // try the pending upload mark. In passive mode the data channel
                // connects *before* STOR is sent on the control channel, so the
                // mark may not exist yet. If the server IP is a known FTP/FTPS
                // server, fall back to deferred checking inside intercept_pending.
                //
                // 中文说明：非 TLS 的 FTP 数据通道（经 HTTP CONNECT 建起的明文 FTP）
                // 在被动模式下会先于控制通道的 STOR 命令建立，因此此刻"待上传"标记
                // 可能尚未写入。若源站 IP 属于已知的 FTP/FTPS 服务器，则交给
                // intercept_pending 做延迟判定，避免直接按未知协议放行而漏掉上传内容检测。
                let upload_info = crate::inspect::ftp::check_ftp_upload_data(
                    self.ctx.task_notes.client_addr,
                    self.ctx.connect_notes.server_addr,
                );
                let is_ftp_server = upload_info.is_some()
                    || crate::inspect::ftp::get_ftps_domain(
                        self.ctx.task_notes.client_addr,
                        self.ctx.connect_notes.server_addr,
                    )
                    .is_some();

                if is_ftp_server {
                    // 记录本条数据通道的四元组，供控制通道侧后续关联上传内容检查
                    let data_channel_tuple = Some(ConnectionTuple {
                        server_addr: self.ctx.connect_notes.client_addr,
                        remote_addr: self.ctx.connect_notes.server_addr,
                        protocol: ConnectionProtocol::Tcp,
                    });
                    let mut ftp_upload_obj = crate::inspect::ftp::FtpUploadDataInterceptObject::new(
                        self.ctx,
                        upload_info,
                        data_channel_tuple,
                        None,
                    );
                    ftp_upload_obj.set_io(
                        Box::new(OnceBufReader::new(clt_r, clt_r_buf)),
                        Box::new(clt_w),
                        Box::new(OnceBufReader::new(ups_r, ups_r_buf)),
                        Box::new(ups_w),
                    );
                    return Ok(StreamInspection::FtpUploadData(ftp_upload_obj));
                }

                // 无法归类且与 FTP 无关：回灌已采样字节后按未知协议转发，检测到此结束
                self.ctx
                    .transit_inspect_unknown(
                        OnceBufReader::new(clt_r, clt_r_buf),
                        clt_w,
                        OnceBufReader::new(ups_r, ups_r_buf),
                        ups_w,
                    )
                    .await?;
                return Ok(StreamInspection::End);
            }
            Protocol::Timeout => {
                // 检测超时但连接仍在：按超时归因转发，同样结束本层检测
                self.ctx
                    .transit_inspect_timeout(
                        OnceBufReader::new(clt_r, clt_r_buf),
                        clt_w,
                        OnceBufReader::new(ups_r, ups_r_buf),
                        ups_w,
                    )
                    .await?;
                return Ok(StreamInspection::End);
            }
            Protocol::TlsModern => {
                // 仅在服务开启了 TLS 拦截时才接管；否则落到末尾按 bypass 转发
                if let Some(tls_interception) = self.ctx.tls_interception() {
                    let mut tls_obj = crate::inspect::tls::TlsInterceptObject::new(
                        self.ctx,
                        self.upstream,
                        tls_interception,
                    );
                    // ClientHello 原始字节直接交给 TLS 层解析，不做缓冲回灌
                    tls_obj.set_io(clt_r_buf, clt_r, clt_w, ups_r, ups_w);
                    return Ok(StreamInspection::TlsModern(tls_obj));
                }
            }
            #[cfg(feature = "vendored-tongsuo")]
            Protocol::TlsTlcp => {
                // 国密 TLCP 拦截：仅在 tongsuo 构建且开启 TLS 拦截时接管
                if let Some(tls_interception) = self.ctx.tls_interception() {
                    let mut tls_obj = crate::inspect::tls::TlsInterceptObject::new(
                        self.ctx,
                        self.upstream,
                        tls_interception,
                    );
                    tls_obj.set_io(clt_r_buf, clt_r, clt_w, ups_r, ups_w);
                    return Ok(StreamInspection::TlsTlcp(tls_obj));
                }
            }
            Protocol::Http1 => {
                // HTTP/1 需要边解析边读，用 FlexBufReader 把已采样字节续接在原读流前
                let mut h1_obj = crate::inspect::http::H1InterceptObject::new(self.ctx, None);
                h1_obj.set_io(
                    FlexBufReader::with_bytes(clt_r_buf, clt_r),
                    clt_w,
                    ups_r,
                    ups_w,
                );
                return Ok(StreamInspection::H1(h1_obj));
            }
            Protocol::Http2 => {
                // HTTP/2 的帧解析自建缓冲，只需回灌客户端首段字节（含连接前导串）
                let mut h2_obj = crate::inspect::http::H2InterceptObject::new(
                    self.ctx,
                    self.upstream.clone(),
                    None,
                );
                h2_obj.set_io(OnceBufReader::new(clt_r, clt_r_buf), clt_w, ups_r, ups_w);
                return Ok(StreamInspection::H2(h2_obj));
            }
            Protocol::Smtp => {
                // SMTP 属服务端先发 banner 的协议，只需回灌源站侧缓冲
                let mut smtp_obj =
                    crate::inspect::smtp::SmtpInterceptObject::new(self.ctx, self.upstream.clone());
                smtp_obj.set_io(clt_r, clt_w, OnceBufReader::new(ups_r, ups_r_buf), ups_w);
                return Ok(StreamInspection::Smtp(smtp_obj));
            }
            Protocol::Imap => {
                // IMAP 同样由服务端先发欢迎信息，回灌源站侧缓冲
                let mut imap_obj =
                    crate::inspect::imap::ImapInterceptObject::new(self.ctx, self.upstream.clone());
                imap_obj.set_io(clt_r, clt_w, OnceBufReader::new(ups_r, ups_r_buf), ups_w);
                return Ok(StreamInspection::Imap(imap_obj));
            }
            Protocol::FtpControl => {
                // FTP 控制通道：四个半部都交给 FTP 拦截对象管理
                let mut ftp_obj =
                    crate::inspect::ftp::FtpInterceptObject::new(self.ctx, self.upstream.clone());
                ftp_obj.set_io(
                    Box::new(clt_r),
                    Box::new(clt_w),
                    OnceBufReader::new(ups_r, ups_r_buf),
                    Box::new(ups_w),
                );
                return Ok(StreamInspection::Ftp(ftp_obj));
            }
            // 其余已识别但无拦截实现的协议走下方的 bypass 分支
            _ => {}
        }

        // 协议已知但不拦截（或未开启对应拦截）：按 bypass 归因透明转发
        self.ctx
            .transit_inspect_bypass(
                OnceBufReader::new(clt_r, clt_r_buf),
                clt_w,
                OnceBufReader::new(ups_r, ups_r_buf),
                ups_w,
            )
            .await?;
        Ok(StreamInspection::End)
    }

    /// 并发等待客户端与源站的首段数据，返回先到达的一方。
    ///
    /// `biased` 使客户端侧先被轮询：两侧同时可读时以请求侧数据作为识别入口。
    /// 本方法只负责"谁先出声"，采样与不完整读取（incomplete read）的补齐
    /// 由 [`StreamInspectObject::inspect_initial_data`] 完成。
    async fn wait_initial_data(
        &mut self,
        clt_r: &mut BoxAsyncRead,
        clt_r_buf: &mut BytesMut,
        ups_r: &mut BoxAsyncRead,
        ups_r_buf: &mut BytesMut,
    ) -> ServerTaskResult<InitialDataSource> {
        tokio::select! {
            biased;

            r = clt_r.read_buf(clt_r_buf) => {
                match r {
                    Ok(_) => Ok(InitialDataSource::Client),
                    Err(e) => Err(ServerTaskError::ClientTcpReadFailed(e)),
                }
            }
            r = ups_r.read_buf(ups_r_buf) => {
                match r {
                    Ok(_) => Ok(InitialDataSource::Server),
                    Err(e) => Err(ServerTaskError::UpstreamReadFailed(e)),
                }
            }
        }
    }

    /// 按首包来源分派到客户端侧或源站侧的识别流程。
    ///
    /// 两侧不能混用：g3_dpi 的客户端与服务端指纹表不同，用错入口会直接误判协议。
    async fn inspect_initial_data(
        &mut self,
        source: InitialDataSource,
        inspector: &mut ProtocolInspector,
        clt_r: &mut BoxAsyncRead,
        clt_r_buf: &mut BytesMut,
        ups_r: &mut BoxAsyncRead,
        ups_r_buf: &mut BytesMut,
    ) -> ServerTaskResult<Protocol> {
        match source {
            InitialDataSource::Client => {
                self.inspect_client_data(inspector, clt_r_buf, clt_r).await
            }
            InitialDataSource::Server => {
                self.inspect_server_data(inspector, ups_r_buf, ups_r).await
            }
        }
    }

    /// 循环读取客户端首段数据并喂给 DPI，直到能判定协议或缓冲区耗尽。
    ///
    /// DPI 返回 `NeedMoreData` 时继续追加读取；若缓冲区已无有效样本字节
    /// （`remaining() == 0`），说明再也补不出判定依据，按 `Protocol::Unknown` 返回。
    /// 已读取的字节始终留在 `clt_r_buf` 中，供分派时回灌给下游读取器。
    async fn inspect_client_data<CR>(
        &mut self,
        inspector: &mut ProtocolInspector,
        clt_r_buf: &mut BytesMut,
        clt_r: &mut CR,
    ) -> Result<Protocol, ServerTaskError>
    where
        CR: AsyncRead + Unpin,
    {
        loop {
            // 端口作为识别线索之一：同一字节序列在不同端口上的协议含义可能不同
            match inspector.check_client_initial_data(
                self.ctx.protocol_inspection(),
                self.upstream.port(),
                clt_r_buf.chunk(),
            ) {
                Ok(p) => return Ok(p),
                Err(ProtocolInspectError::NeedMoreData(_)) => {
                    if clt_r_buf.remaining() == 0 {
                        return Ok(Protocol::Unknown);
                    }
                    match clt_r.read_buf(clt_r_buf).await {
                        // 对端在半包之前关闭：不是识别失败而是连接异常终止
                        Ok(0) => return Err(ServerTaskError::ClosedByClient),
                        Ok(_) => {}
                        Err(e) => return Err(ServerTaskError::ClientTcpReadFailed(e)),
                    }
                }
            }
        }
    }

    /// 源站侧的协议识别循环，语义与
    /// [`StreamInspectObject::inspect_client_data`] 对称，用于服务端先发数据的协议
    /// （如 SMTP/FTP banner）。
    async fn inspect_server_data<UR>(
        &mut self,
        inspector: &mut ProtocolInspector,
        ups_r_buf: &mut BytesMut,
        ups_r: &mut UR,
    ) -> Result<Protocol, ServerTaskError>
    where
        UR: AsyncRead + Unpin,
    {
        loop {
            match inspector.check_server_initial_data(
                self.ctx.protocol_inspection(),
                self.upstream.port(),
                ups_r_buf.chunk(),
            ) {
                Ok(p) => return Ok(p),
                Err(ProtocolInspectError::NeedMoreData(_)) => {
                    if ups_r_buf.remaining() == 0 {
                        return Ok(Protocol::Unknown);
                    }
                    match ups_r.read_buf(ups_r_buf).await {
                        // 源站在补齐识别数据前关闭连接
                        Ok(0) => return Err(ServerTaskError::ClosedByUpstream),
                        Ok(_) => {}
                        Err(e) => return Err(ServerTaskError::UpstreamReadFailed(e)),
                    }
                }
            }
        }
    }
}
