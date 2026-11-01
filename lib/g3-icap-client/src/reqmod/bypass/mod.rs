/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! 协议无关的 ICAP 旁路（bypass）上传审计管线。
//!
//! 本模块是 FTP 上传审计通路（`reqmod/ftp`）的下沉泛化版：fail-open 中继循环、
//! 带背压的 chunk 通道、聚合批量写、防死锁并发排空、判决后台读取与连接回收
//! 全部在这里实现一次；协议差异收敛为 [`BypassFraming`]（封装区 req-hdr 字节 +
//! `X-Transformed-From` 协议来源标签）。FTP、HTTP/1、HTTP/2 调用方共用同一管线。

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, empty, sink};
use tokio::time::Instant;

use g3_io_ext::{IdleCheck, LimitedWriteExt, OnceBufReader, StreamCopyConfig};
use g3_types::net::TlsKeyLogBuffer;

use log::{debug, warn};

use super::{ConnectionTuple, IcapReqmodClient};
use crate::reqmod::mail::ReqmodAdaptationRunState;
use crate::service::{IcapClientConnection, IcapClientReader, IcapClientWriter};
use crate::{IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::BypassAdaptationError;

/// Classification of adaptation failures, used by callers to decide
/// whether they can still deliver the original payload to upstream.
/// 失败面分类：调用方据此判断"原始数据还能不能继续送给上游"。
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BypassErrorKind {
    /// Failure reading the client data stream. The transfer must be
    /// aborted entirely - there is no data left to forward.
    /// 客户端数据流读失败：源头断了，传输只能整体终止。
    ClientRead,
    /// Failure writing to the upstream server. The transfer must be
    /// aborted entirely.
    /// 上游服务器写失败：目的地断了，传输同样必须终止。
    UpstreamWrite,
    /// Failure writing only to the ICAP service. The original payload
    /// may still be forwarded to upstream; the audit was best-effort.
    /// 仅 ICAP 写失败：审计尽力而为，上传可以照常继续。
    IcapWrite,
    /// Failure reading the ICAP verdict. The audit verdict is unknown
    /// but the original payload has already been forwarded (if any).
    /// ICAP 判决读取失败：结论未知，但数据已转发（或未转发）的事实不变。
    IcapRead,
    /// External request to abort (idle force-quit, user blocked).
    /// 外部强制中止（空闲看门狗触发、用户被封禁等）。
    ForceQuit,
    /// Internal / configuration failures.
    /// 库内部错误或配置错误，与具体网络方向无关。
    Internal,
}

/// 协议差异的唯一载体：封装区里的请求头字节（伪 HTTP 或真实 HTTP 报文头）
/// + ICAP `X-Transformed-From` 协议来源标签。
#[derive(Debug)]
pub struct BypassFraming {
    /// ICAP 封装区 req-hdr：以 `\r\n\r\n` 结尾的请求头字节
    pub req_hdr: Vec<u8>,
    /// 写入 `X-Transformed-From` 的协议来源标签（如 "FTP" / "HTTP/1.0" / "HTTP/2.0"）
    pub transformed_from: &'static str,
}

/// Final audit verdict from the ICAP server for one uploaded stream.
/// 一次上传结束时返回给调用方的最终状态：区分"上传+审计都完成"、
/// "只审计"、"审计失败但已兜底转发"、"审计转入后台继续"四种走向。
#[derive(Debug)]
pub enum BypassEndState {
    /// Audit completed successfully and the original data was already
    /// forwarded to upstream.
    /// 同步路径：ICAP 判决已读到，且原始数据已完整转发给上游。
    OriginalTransferred {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP responded, but we were operating in audit-only mode (no
    /// upstream forwarding configured).
    /// audit_only 模式：调用方自行转发数据，这里只回传审计判决。
    AuditOnly {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP adaptation failed in a way that did NOT prevent us from
    /// forwarding data upstream. This is the "never block upload"
    /// safety net for enterprise ICAP auditing.
    /// 兜底路径：ICAP 审计失败，但原始数据仍然转发成功——
    /// "审计失败绝不阻断上传"的安全网就体现在这个状态上。
    OriginalTransferredAfterFallback { bytes: u64, icap_error: String },
    /// ICAP audit is being processed in the background. The upload
    /// data has already been forwarded to upstream.
    /// 转发已完成，ICAP 判决的读取/善后交给后台任务异步处理
    /// （避免慢 ICAP 拖住上传的收尾）。
    OriginalTransferredInBackground { bytes: u64 },
}

impl IcapReqmodClient {
    /// Build a new streaming bypass auditor. The returned adapter
    /// binds an ICAP connection from the pool (or opens a new one),
    /// so it should only be constructed when a data transfer actually
    /// begins.
    /// 构造一个流式旁路审计器。注意：这里就会从连接池占用（或新建）
    /// 一条 ICAP 连接，所以只应在数据真正开始传输时创建，不要提前构造。
    pub async fn bypass_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> anyhow::Result<BypassAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(BypassAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            idle_checker,
            client_addr: None,
            client_username: None,
            connection_tuple: None,
            keylog_buffer: None,
            upstream_half_close: true,
        })
    }
}

/// 旁路上报数据流的 ICAP 审计适配器（一次上传一个实例，按所有权消费）。
pub struct BypassAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    #[allow(dead_code)]
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    idle_checker: I,
    client_addr: Option<SocketAddr>,
    client_username: Option<arcstr::ArcStr>,
    /* added for connection tuple */
    connection_tuple: Option<ConnectionTuple>,
    /* added for TLS keylog */
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    /// 客户端请求体送达后是否半关闭上游写侧。FTP 数据通道靠 EOF 信令传输
    /// 结束，必须关闭；HTTP 请求体自带结束标记，上游连接要留给后续请求复用。
    upstream_half_close: bool,
}

impl<I: IdleCheck> BypassAdapter<I> {
    /// Assemble an adapter over an already-held ICAP connection.
    /// Only used by tests to deterministically inject broken halves.
    #[cfg(test)]
    pub(crate) fn with_connection(
        icap_client: Arc<IcapServiceClient>,
        icap_connection: IcapClientConnection,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> Self {
        BypassAdapter {
            icap_client,
            icap_connection,
            icap_options: Arc::new(IcapServiceOptions::new_expired(crate::IcapMethod::Reqmod)),
            copy_config,
            idle_checker,
            client_addr: None,
            client_username: None,
            connection_tuple: None,
            keylog_buffer: None,
            upstream_half_close: true,
        }
    }

    /// Record the client address; sent to the ICAP server as
    /// X-Client-IP / X-Client-Port headers so the audit service can
    /// correlate streams with users.
    /// 记录客户端地址，最终以 X-Client-IP / X-Client-Port 头送给 ICAP，
    /// 让审计服务端能把数据流关联到具体用户。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 记录客户端用户名（以 X-Client-Username / X-Authenticated-User 头回传）。
    pub fn set_client_username(&mut self, user: arcstr::ArcStr) {
        self.client_username = Some(user);
    }

    /// 设置请求体送达后是否半关闭上游写侧（默认为真，即 FTP 数据通道行为）。
    /// HTTP 调用方应关闭：请求体成帧自带结束标记，上游连接还要留给
    /// keep-alive / 流水线上的下一个请求使用，半关闭会让它作废。
    pub fn set_upstream_half_close(&mut self, enabled: bool) {
        self.upstream_half_close = enabled;
    }

    /* added for connection tuple - data channel 5-tuple */
    /// 注入数据通道五元组（会以 X-Proxy-IP / X-Remote-IP / X-Proto-P 头回传）。
    pub fn set_connection_tuple(&mut self, tuple: ConnectionTuple) {
        self.connection_tuple = Some(tuple);
    }

    /* added for TLS keylog */
    /// 注入 TLS keylog 缓冲区（会以 X-TLS-* 头回传，供服务端解密对应会话）。
    pub fn set_keylog_buffer(&mut self, buffer: Arc<TlsKeyLogBuffer>) {
        self.keylog_buffer = Some(buffer);
    }

    /// 追加本扩展专用的 ICAP 头：Allow: 204 告诉服务器"只回 204 放行
    /// 就行，不需要修改后的内容"；X-Transformed-From 声明协议来源；
    /// 其余为可选的客户端地址 / 用户名 / 五元组 / keylog 关联信息。
    fn push_extended_headers(&self, data: &mut Vec<u8>, framing: &BypassFraming) {
        data.put_slice(b"Allow: 204\r\n");
        let _ = write!(data, "X-Transformed-From: {}\r\n", framing.transformed_from);
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(ref user) = self.client_username {
            crate::serialize::add_client_username(data, user);
        }
        /* added for connection tuple - data channel 5-tuple */
        if let Some(ref tuple) = self.connection_tuple {
            crate::serialize::add_connection_tuple(data, tuple);
        }
        /* added for TLS keylog */
        if let Some(ref keylog) = self.keylog_buffer {
            crate::serialize::add_keylog_headers(data, keylog);
        }
    }

    /// 组装并发送 ICAP REQMOD 请求头：
    /// 预置的 `ICAP/1.0 REQMOD <uri>` 前缀 + 扩展头 +
    /// `Encapsulated: req-hdr=0, req-body=N` + 封装区 req-hdr（向量写一次发出）。
    async fn send_icap_header(&mut self, framing: &BypassFraming) -> io::Result<()> {
        let mut icap_header =
            Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header, framing);
        // 封装区从 ICAP 头结束处算起：req-hdr 固定在偏移 0，
        // req-body 的偏移 = 封装请求头的字节数，正文内容紧随其后。
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            framing.req_hdr.len()
        );

        debug!(
            "Bypass ICAP request header ({} bytes, req_hdr {} bytes):\n{}",
            icap_header.len(),
            framing.req_hdr.len(),
            String::from_utf8_lossy(&icap_header)
        );

        // 两段头一次 write_all_vectored 发出：省一次系统调用，
        // 也保证 ICAP 头与封装的请求头作为整体送达服务器。
        self.icap_connection
            .writer
            .write_all_vectored([
                io::IoSlice::new(&icap_header),
                io::IoSlice::new(&framing.req_hdr),
            ])
            .await?;
        self.icap_connection.writer.flush().await
    }

    /// 主入口：把客户端数据流同时扇出到上游写端和 ICAP 后台写任务。
    /// 任何 ICAP 侧失败都只降级审计、不中断转发，最终以
    /// [`BypassEndState`] 汇报实际走向。
    ///
    /// 内存模型：读-复制-写循环全程复用一块固定缓冲，堆占用与数据量无关。
    pub async fn audit_and_forward<CR, UW>(
        mut self,
        state: &mut BypassRunState,
        framing: BypassFraming,
        clt_r: &mut CR,
        ups_w: &mut UW,
    ) -> BypassEndState
    where
        CR: AsyncRead + Send + Unpin,
        UW: AsyncWrite + Send + Unpin,
    {
        // 第一步：发送 ICAP 请求头 + 封装区请求头。
        // 若这里就失败（连接已死），ICAP 完全无法参与——直接退化为
        // forward-only 纯转发，保证上传不受影响。
        if let Err(e) = self.send_icap_header(&framing).await {
            warn!(
                "Bypass ICAP header send failed, fallback to forward-only: {}",
                e
            );
            return self.fallback_forward_only(clt_r, ups_w, state, e).await;
        }

        // 第二步：边读客户端边双写（上游 + ICAP 后台写任务）。
        // Err(bytes) 表示"上游写失败"——这是唯一需要终止上传的错误面，
        // 此时 ICAP 侧已写入的数据不再等待判决，直接如实上报。
        let (total_bytes, icap_ok, icap_handle, clt_body_complete) =
            match self.run_relay_loop(clt_r, ups_w).await {
                Ok(outcome) => outcome,
                Err(bytes) => {
                    return BypassEndState::OriginalTransferredAfterFallback {
                        bytes,
                        icap_error: "upstream write failed".to_string(),
                    };
                }
            };

        // 客户端 EOF：把上游已缓冲的数据冲出去；只在调用方要求时才半关闭写侧
        // （FTP 靠 EOF 信令，HTTP 的请求体成帧自带结束标记）。
        let _ = ups_w.flush().await;
        if self.upstream_half_close {
            let _ = ups_w.shutdown().await;
        }
        // 半途而废（客户端读错误、被空闲看门狗掐断）不许汇报成"请求体已搬完"：
        // 调用方靠这两个标志决定是否把仍然可用的上游连接放回 keep-alive 池，
        // 残 body 复用会让源站把下一个请求当成上一段的续文（请求走私）
        if clt_body_complete {
            state.clt_read_finished = true;
            state.mark_ups_send_all();
        }

        // icap_ok=false 表示中继期间 ICAP 写通道已断开/被慢速背压掐掉：
        // 回收后台任务（拿回连接资源）后如实汇报"转发成功、审计失败"。
        if !icap_ok {
            let _ = icap_handle.await;
            return BypassEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: "icap aborted due to slow write".to_string(),
            };
        }

        let icap_client = self.icap_client.clone();

        // 第三步：上传已完成，判决读取放进后台任务，主流程立刻返回
        // OriginalTransferredInBackground——慢 ICAP 不能拖住上传收尾。
        tokio::spawn(async move {
            // Overall timeout for the background ICAP response processing.
            // Prevents resource leaks if the ICAP server hangs.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                let (icap_result, icap_writer, icap_reader, rsp_header_buf) =
                    match icap_handle.await {
                        Ok((result, writer, reader, header_buf)) => {
                            (result, writer, reader, header_buf)
                        }
                        Err(_) => {
                            warn!("Bypass ICAP background task panicked");
                            return;
                        }
                    };

                if let Err(e) = icap_result {
                    warn!("Bypass ICAP write failed ({}), audit incomplete", e);
                    return;
                }

                // 用后台任务归还的读写半端重建一个"半成品"连接对象：
                // writer 已写完，接下来只需从 reader 上取判决
                let mut icap_connection = IcapClientConnection::placeholder();
                icap_connection.writer = icap_writer;
                icap_connection.reader = if rsp_header_buf.is_empty() {
                    icap_reader
                } else {
                    // Prepend the response header captured during drain
                    // so that ReqmodResponse::parse can read the status
                    // line and headers that were otherwise consumed and
                    // discarded by the anti-deadlock drain loop.
                    // 防死锁排空时已把响应头从 socket 上读走并存入
                    // rsp_header_buf，这里用 OnceBufReader 先"重放"
                    // 这段缓存再续读裸连接，parse 才能看到完整头部
                    let prefixed = OnceBufReader::with_bytes(
                        icap_reader.into_inner(),
                        bytes::Bytes::from(rsp_header_buf),
                    );
                    BufReader::new(Box::new(prefixed))
                };
                icap_connection.mark_writer_finished();

                let icap_max_header_size = icap_client.config.icap_max_header_size;
                let respond_shared_names = icap_client.config.respond_shared_names.clone();

                // Parse the ICAP response first. The response headers
                // are available once the write side is done (the server
                // sends them after receiving the complete request).
                let parse_result = crate::reqmod::response::ReqmodResponse::parse(
                    &mut icap_connection.reader,
                    icap_max_header_size,
                    &respond_shared_names,
                )
                .await;

                let rsp = match parse_result {
                    Ok(rsp) => rsp,
                    Err(e) => {
                        warn!("Bypass ICAP response parse failed: {}", e);
                        // Do not save a connection with partial/unparsed response
                        return;
                    }
                };

                debug!(
                    "Bypass ICAP response: code={}, reason={}, keep_alive={}",
                    rsp.code, rsp.reason, rsp.keep_alive
                );

                // Drain any remaining response body data (e.g. from echo
                // services that echo back the request body).
                // Skip draining for responses with no body (e.g. 204 No Content).
                let drain_clean = if !rsp.has_body() {
                    true
                } else {
                    let mut drain_buf = [0u8; 65536];
                    let mut clean = false;
                    loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            icap_connection.reader.read(&mut drain_buf),
                        )
                        .await
                        {
                            Ok(Ok(0)) => {
                                clean = true;
                                break;
                            }
                            Ok(Ok(_)) => continue,
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
                    clean
                };

                icap_connection.mark_reader_finished();

                // Only save the connection for reuse if the response indicates
                // success, keep-alive is enabled, and the body was cleanly
                // drained (no leftover data or read errors).
                if drain_clean && rsp.keep_alive && rsp.code >= 200 && rsp.code < 300 {
                    icap_client.save_connection(icap_connection);
                } else {
                    warn!(
                        "Bypass ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                        rsp.code, rsp.keep_alive, drain_clean
                    );
                }
            })
            .await;
        });

        BypassEndState::OriginalTransferredInBackground { bytes: total_bytes }
    }

    /// 中继主循环：从客户端读一块数据，先写上游、再复制一份投递给
    /// ICAP 后台写任务；返回 (总字节数, ICAP 写侧是否存活, 后台任务句柄,
    /// 客户端请求体是否干净收尾)。
    /// Err(总字节数) 专门表示上游写失败（唯一必须终止上传的错误面）。
    async fn run_relay_loop<CR, UW>(
        &mut self,
        clt_r: &mut CR,
        ups_w: &mut UW,
    ) -> Result<
        (
            u64,
            bool,
            tokio::task::JoinHandle<(
                Result<u64, &'static str>,
                IcapClientWriter,
                IcapClientReader,
                Vec<u8>,
            )>,
            bool,
        ),
        u64,
    >
    where
        CR: AsyncRead + Send + Unpin,
        UW: AsyncWrite + Send + Unpin,
    {
        // Use a 256 KiB buffer to cut the number of syscalls for large
        // files (1 GiB would otherwise need 65536 x 16 KiB copies).
        // 缓冲下限取 256 KiB：大块读写显著减少大文件的系统调用次数；
        // 整轮循环复用这一小块内存，堆占用不随文件增大。
        let buf_size = self.copy_config.buffer_size().max(256 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0usize;

        // ICAP buffering: channel with backpressure
        // When ICAP is slower than the upstream, send() blocks
        // and naturally throttles the client read rate.
        // 带背压的有界通道：ICAP 消费慢时 send() 挂起，天然反压读速率；
        // 若通道被关闭（写任务退出），主循环把 icap_alive 置 false 继续纯转发。
        const CHANNEL_CAPACITY: usize = 64;
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(CHANNEL_CAPACITY);

        // Take both the ICAP writer and reader. The writer is used to
        // send chunked body data; the reader is concurrently drained to
        // prevent deadlock with echo-style ICAP services that start
        // sending back the response while we are still uploading.
        // 用 sink()/empty() 占位换出真正的读写半端：所有权移入后台任务，
        // 本结构体不再触碰 ICAP 连接，直到 join 取回。
        let icap_writer = std::mem::replace(&mut self.icap_connection.writer, Box::new(sink()));
        let icap_reader = std::mem::replace(
            &mut self.icap_connection.reader,
            BufReader::new(Box::new(empty())),
        );
        let max_header_size = self.icap_client.config.icap_max_header_size;

        let icap_handle = tokio::spawn(async move {
            let mut write_buf = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
            let mut icap_writer = icap_writer;
            let mut icap_reader = icap_reader;
            let mut total_written: u64 = 0;
            let mut pending_chunks: usize = 0;
            let mut drain_buf = [0u8; 65536];
            let mut reader_closed = false;
            // Capture the ICAP response header during drain so it can be
            // replayed for parsing.  Echo-style ICAP servers send the full
            // response (header + body) while the upload is still in
            // progress; without this capture the header is consumed and
            // discarded by the drain, causing parse to fail.
            let mut rsp_header_buf: Vec<u8> = Vec::new();
            let mut rsp_header_done = false;

            // Combined write + drain loop.
            // "biased" ensures we prioritise writing chunks over draining
            // so that the request body is delivered as fast as possible.
            // 写数据与排空响应合并到同一循环；biased 保证优先投递请求体。
            loop {
                if reader_closed {
                    // Reader is closed; only process remaining chunks.
                    // 读侧已断开/出错：不再 select 排空，专心把剩余
                    // chunk 写完（继续 select 会在关闭的 reader 上空转）。
                    match chunk_rx.recv().await {
                        Some(chunk) => {
                            total_written += chunk.len() as u64;
                            append_chunk_header(&mut write_buf, chunk.len());
                            write_buf.extend_from_slice(&chunk);
                            write_buf.extend_from_slice(b"\r\n");
                            pending_chunks += 1;

                            // 攒到 16 个 chunk 或 4 MiB 才真正落盘一次：
                            // 摊薄系统调用开销，同时给读侧让出排空机会。
                            if pending_chunks >= 16 || write_buf.len() >= 4 * 1024 * 1024 {
                                if icap_writer.write_all(&write_buf).await.is_err() {
                                    return (
                                        Err("icap write failed"),
                                        icap_writer,
                                        icap_reader,
                                        Vec::new(),
                                    );
                                }
                                if icap_writer.flush().await.is_err() {
                                    return (
                                        Err("icap flush failed"),
                                        icap_writer,
                                        icap_reader,
                                        Vec::new(),
                                    );
                                }
                                write_buf.clear();
                                pending_chunks = 0;
                            }
                        }
                        None => break,
                    }
                    continue;
                }

                tokio::select! {
                    biased;
                    chunk = chunk_rx.recv() => {
                        match chunk {
                            Some(chunk) => {
                                total_written += chunk.len() as u64;
                                // Write hex length + CRLF + data + CRLF
                                // into write_buf in one pass to avoid
                                // per-chunk String allocation.
                                append_chunk_header(&mut write_buf, chunk.len());
                                write_buf.extend_from_slice(&chunk);
                                write_buf.extend_from_slice(b"\r\n");
                                pending_chunks += 1;

                                if pending_chunks >= 16 || write_buf.len() >= 4 * 1024 * 1024 {
                                    if icap_writer.write_all(&write_buf).await.is_err() {
                                        return (Err("icap write failed"), icap_writer, icap_reader, Vec::new());
                                    }
                                    if icap_writer.flush().await.is_err() {
                                        return (Err("icap flush failed"), icap_writer, icap_reader, Vec::new());
                                    }
                                    write_buf.clear();
                                    pending_chunks = 0;
                                }
                            }
                            None => {
                                // Channel closed — all request data has been sent.
                                break;
                            }
                        }
                    }
                    // Drain the ICAP reader concurrently.  This is critical
                    // for echo services that start streaming the response
                    // body back before the request body is complete.  Without
                    // this drain, the TCP receive buffer fills up, the ICAP
                    // server blocks on writing, then stops reading our data,
                    // and the whole pipeline deadlocks.
                    n = icap_reader.read(&mut drain_buf) => {
                        match n {
                            Ok(0) | Err(_) => {
                                // Connection closed / error — stop draining
                                // to avoid busy-looping on a closed reader.
                                reader_closed = true;
                            }
                            Ok(read_len) => {
                                // Capture the ICAP response header so it
                                // can be replayed for parsing after the
                                // upload finishes.  Echo-style ICAP servers
                                // send the full response while we are still
                                // uploading; without this capture the header
                                // is lost and parsing fails with
                                // "not long enough".
                                if !rsp_header_done {
                                    rsp_header_buf.extend_from_slice(&drain_buf[..read_len]);
                                    if let Some(pos) = find_icap_header_end(&rsp_header_buf) {
                                        rsp_header_buf.truncate(pos + 4);
                                        rsp_header_done = true;
                                    } else if rsp_header_buf.len() >= max_header_size {
                                        rsp_header_done = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Flush remaining write buffer
            // 通道关闭：先冲掉聚合缓冲里攒着的 chunk……
            if !write_buf.is_empty() {
                let _ = icap_writer.write_all(&write_buf).await;
                let _ = icap_writer.flush().await;
            }

            // ……再写分块编码终止标记 "0\r\n\r\n"，告知 ICAP 请求体完整，
            // 服务器随后即可给出判决（响应由后台任务继续解析）。
            let _ = icap_writer.write_all(b"0\r\n\r\n").await;
            let _ = icap_writer.flush().await;

            (Ok(total_written), icap_writer, icap_reader, rsp_header_buf)
        });

        let mut icap_alive = true;
        // 只有客户端自己把请求体送完（读到 EOF）才算"搬完了"；读错误与空闲
        // 看门狗掐断都是半途而废，调用方要靠这个区分决定上游连接能否复用
        let mut clt_body_complete = false;

        // 主中继循环：客户端数据是最高优先级（biased），空闲计时仅用于
        // 看门狗（长时间无数据时按 IdleCheck 策略强制退出）。
        loop {
            tokio::select! {
                biased;
                res = clt_r.read(&mut buf) => {
                    match res {
                        // 客户端 EOF：上传数据全部送达，正常结束
                        Ok(0) => {
                            clt_body_complete = true;
                            break;
                        }
                        Ok(n) => {
                            idle_count = 0;
                            total_bytes += n as u64;

                            // 上游写失败属于 UpstreamWrite 错误面：上传本身
                            // 已不可能成功，掐断通道并带上已转发字节数返回。
                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                drop(chunk_tx);
                                return Err(total_bytes);
                            }

                            if icap_alive {
                                // 复制一份投递给 ICAP 写任务；通道满时
                                // send().await 挂起形成背压（见上方说明）。
                                let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                                match chunk_tx.send(chunk).await {
                                    Ok(()) => {}
                                    Err(_) => {
                                        // ICAP 写任务已退出（写失败提前返回）：
                                        // 此后纯转发，不再尝试审计投递。
                                        warn!("Bypass ICAP channel closed");
                                        icap_alive = false;
                                    }
                                }
                            }
                        }
                        // 客户端读错误属于 ClientRead 错误面：源头断了，
                        // 只能停止转发（已发出的部分由上层决定如何收尾）。
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if self.idle_checker.check_quit(idle_count) {
                        // 空闲超限且看门狗要求退出：ForceQuit 错误面
                        break;
                    }
                }
            }
        }

        // 结束投递：drop 发送端使后台写任务看到 None 从而收尾
        drop(chunk_tx);
        Ok((total_bytes, icap_alive, icap_handle, clt_body_complete))
    }

    /// audit-only 模式：数据只送 ICAP 不上送上游——调用方（如 HTTP CONNECT
    /// 隧道处理器）自己已经在搬运原始数据，这里只额外做一份审计。
    /// 与 audit_and_forward 不同，此路径同步等待并解析 ICAP 判决
    /// （没有"不能阻断上传"的转发路径可兜底，失败时同样只汇报不抛错）。
    pub async fn audit_only<CR>(
        mut self,
        state: &mut BypassRunState,
        framing: BypassFraming,
        clt_r: &mut CR,
    ) -> BypassEndState
    where
        CR: AsyncRead + Send + Unpin,
    {
        let total_bytes;
        if let Err(e) = self.send_icap_header(&framing).await {
            // Best-effort drain so the caller doesn't stall because we
            // refused to read.
            // 尽力排空：调用方仍在往数据通道里写，我们不读它就会把
            // 对方的复制流程卡住；这里丢弃内容只计数，审计宣告失败。
            let mut buf = [0u8; 16 * 1024];
            let mut drained = 0u64;
            loop {
                match clt_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained += n as u64,
                }
            }
            return BypassEndState::OriginalTransferredAfterFallback {
                bytes: drained,
                icap_error: format!("icap header write failed: {e}"),
            };
        }

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut scanned_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();
        // 复用聚合缓冲拼装分块帧头，避免每块一次堆分配
        let mut write_buf = bytes::BytesMut::with_capacity(4096);

        let mut idle_count = 0usize;

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            idle_count = 0;
                            scanned_bytes += n as u64;
                            if write_icap_chunk(&mut self.icap_connection.writer, &buf[..n], &mut write_buf)
                                .await
                                .is_err()
                            {
                                // Drain rest so reader isn't blocked;
                                // caller already got the bytes on its
                                // own path.
                                // ICAP 体写失败：继续排空剩余数据防止
                                // 调用方被反压卡死，汇报"审计降级、上传不受影响"
                                let mut tail = [0u8; 16 * 1024];
                                loop {
                                    match clt_r.read(&mut tail).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(m) => scanned_bytes += m as u64,
                                    }
                                }
                                return BypassEndState::OriginalTransferredAfterFallback {
                                    bytes: scanned_bytes,
                                    icap_error: "icap body write failed".to_string(),
                                };
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if self.idle_checker.check_quit(idle_count) {
                        // 空闲看门狗要求强制退出（ForceQuit 错误面）
                        break;
                    }
                }
            }
        }

        total_bytes = scanned_bytes;
        state.clt_read_finished = true;

        // 分块编码终止标记，随后宣告写侧完成、可以读取判决
        let _ = self.icap_connection.writer.write_all(b"0\r\n\r\n").await;
        let _ = self.icap_connection.writer.flush().await;
        self.icap_connection.mark_writer_finished();

        // 同步解析 ICAP 判决；解析失败即审计失败（不向上抛错）
        let rsp = match crate::reqmod::response::ReqmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await
        {
            Ok(rsp) => rsp,
            Err(_) => {
                warn!("Bypass ICAP response parse failed");
                self.icap_connection.mark_reader_finished();
                return BypassEndState::OriginalTransferredAfterFallback {
                    bytes: total_bytes,
                    icap_error: "icap response parse failed".to_string(),
                };
            }
        };

        // Drain any remaining response body data so the connection can be
        // safely reused.  Without this, leftover bytes would corrupt the
        // next ICAP request on the same connection.
        // Skip draining for responses with no body (e.g. 204 No Content),
        // where there is nothing to read and a 5s timeout would be wasted.
        let drain_clean = if !rsp.has_body() {
            true
        } else {
            let mut drain_buf = [0u8; 65536];
            let mut clean = false;
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    self.icap_connection.reader.read(&mut drain_buf),
                )
                .await
                {
                    Ok(Ok(0)) => {
                        clean = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            clean
        };

        self.icap_connection.mark_reader_finished();

        // 只有"判决正常(2xx) + 支持复用 + 连接上无残留数据"三者齐备
        // 才归还连接池，否则直接丢弃（drop 即关闭 TCP）
        if drain_clean && rsp.keep_alive && rsp.code >= 200 && rsp.code < 300 {
            self.icap_client.save_connection(self.icap_connection);
        } else {
            warn!(
                "Bypass ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                rsp.code, rsp.keep_alive, drain_clean
            );
        }

        // 成功：带回 ICAP 的状态码与原因短语，供调用方判断文件是否被拦截
        BypassEndState::AuditOnly {
            icap_status_code: rsp.code,
            icap_reason: rsp.reason,
            bytes: total_bytes,
        }
    }

    /// ICAP 请求头首发即失败时的兜底转发：彻底放弃审计，把数据流
    /// 原样搬到上游，保证上传本身必然成功。
    async fn fallback_forward_only<CR, UW>(
        self,
        clt_r: &mut CR,
        ups_w: &mut UW,
        state: &mut BypassRunState,
        first_err: io::Error,
    ) -> BypassEndState
    where
        CR: AsyncRead + Send + Unpin,
        UW: AsyncWrite + Send + Unpin,
    {
        // The ICAP connection is effectively dead - just drop it.
        // ICAP 连接已不可信：drop 即关闭 TCP，不回收进连接池
        drop(self.icap_connection);

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();

        // 纯转发循环：没有任何 ICAP 分支，任一方向出错/空闲即停
        let mut clt_body_complete = false;
        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => {
                            clt_body_complete = true;
                            break;
                        }
                        Ok(n) => {
                            total_bytes += n as u64;
                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => break,
            }
        }

        let _ = ups_w.flush().await;
        // 与中继循环同一套判断：只有请求体确实搬完了才允许调用方复用上游连接
        if clt_body_complete {
            state.clt_read_finished = true;
            state.mark_ups_send_all();
        }

        // 无论转发是否完整，都如实带上字节数与首个 ICAP 错误，
        // 由调用方决定如何向客户端汇报结果
        BypassEndState::OriginalTransferredAfterFallback {
            bytes: total_bytes,
            icap_error: format!("icap header write failed: {first_err}"),
        }
    }
}

/// Find the position of `\r\n\r\n` (end of ICAP/HTTP headers) in `buf`.
/// Returns the index of the first byte of the match.
/// 在缓冲中定位头部结束空行（CRLFCRLF），返回匹配起始下标；
/// 用于从排空数据里切出完整的 ICAP 响应头。
fn find_icap_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Append `<hex-size>\r\n` to the buffer without heap allocation.
/// 纯位运算把块长度写成十六进制分块帧头，全部在栈上完成、零堆分配。
fn append_chunk_header(buf: &mut bytes::BytesMut, len: usize) {
    // Maximum hex digits for usize on 64-bit: 16
    const HEX: &[u8; 16] = b"0123456789abcdef";

    // Calculate number of hex digits needed
    let mut num_digits = 0usize;
    let mut n = len;
    if n == 0 {
        num_digits = 1;
    } else {
        while n > 0 {
            num_digits += 1;
            n >>= 4;
        }
    }

    // Use stack-based buffer: hex digits + "\r\n"
    let total_len = num_digits + 2;
    let mut tmp = [0u8; 18]; // 16 hex digits max + "\r\n"

    // Write hex digits from right to left within the digit region
    let mut pos = num_digits;
    n = len;
    while n > 0 {
        pos -= 1;
        tmp[pos] = HEX[n & 0xf];
        n >>= 4;
    }
    if len == 0 {
        tmp[0] = b'0';
    }

    // Add "\r\n" after hex digits
    tmp[num_digits] = b'\r';
    tmp[num_digits + 1] = b'\n';

    buf.extend_from_slice(&tmp[..total_len]);
}

/// Send a single chunk to ICAP in `<hex-size>\r\n<data>\r\n` form.
/// Reuses the caller-provided `BytesMut` buffer to avoid per-chunk allocations.
/// 把一段数据按 HTTP 分块编码格式（十六进制长度行 + 数据 + CRLF）发给 ICAP；
/// 复用调用方给的 BytesMut，避免每块一次堆分配。
async fn write_icap_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    buf: &mut bytes::BytesMut,
) -> io::Result<()> {
    buf.clear();
    append_chunk_header(buf, data.len());
    buf.extend_from_slice(data);
    buf.extend_from_slice(b"\r\n");
    writer.write_all(buf).await
}

/// 旁路管线一轮上报的运行状态类型。
///
/// 直接复用 REQMOD 邮件侧那份通用运行状态（只记录收发是否结束与各阶段耗时，
/// 不含任何邮件语义），协议调用方在管线结束后读取这些字段回填自己的任务日志。
pub type BypassRunState = ReqmodAdaptationRunState;

/// A cheap builder/helper for creating a [`ReqmodAdaptationRunState`]
/// in bypass callers that don't have a mail module state tracker.
/// 便捷构造：调用方没有邮件模块那套状态跟踪器时，用这个直接建一个
/// 空的运行状态（内部只记录起始时间戳等）。
pub fn new_run_state() -> ReqmodAdaptationRunState {
    ReqmodAdaptationRunState::new(Instant::now())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    use g3_io_ext::{IdleCheck, IdleForceQuitReason, IdleInterval, IdleWheel, StreamCopyConfig};

    use crate::reqmod::bypass::{BypassAdapter, BypassEndState, BypassFraming, new_run_state};
    use crate::reqmod::{ConnectionProtocol, ConnectionTuple, IcapReqmodClient};
    use crate::{IcapMethod, IcapServiceClient, IcapServiceConfig};

    // ---------- test helpers ----------

    struct NoIdleCheck {
        wheel: Arc<IdleWheel>,
    }

    impl IdleCheck for NoIdleCheck {
        fn interval_timer(&self) -> IdleInterval {
            self.wheel.register()
        }
        fn check_quit(&self, _idle_count: usize) -> bool {
            false
        }
        fn check_force_quit(&self) -> Option<IdleForceQuitReason> {
            None
        }
    }

    /// 收集写入字节的 AsyncWrite，用于断言上游收到的内容。
    /// `shutdowns` 记录写侧被关闭（半关闭）的次数。
    struct CollectingWriter {
        sink: Arc<std::sync::Mutex<Vec<u8>>>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl AsyncWrite for CollectingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let _ = cx;
            self.sink.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl CollectingWriter {
        fn new_counting_pair() -> (Self, Arc<AtomicUsize>) {
            let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
            let shutdowns = Arc::new(AtomicUsize::new(0));
            (
                CollectingWriter {
                    sink: Arc::clone(&sink),
                    shutdowns: Arc::clone(&shutdowns),
                },
                shutdowns,
            )
        }

        fn new_pair() -> (Self, Arc<std::sync::Mutex<Vec<u8>>>) {
            let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                CollectingWriter {
                    sink: Arc::clone(&sink),
                    shutdowns: Arc::new(AtomicUsize::new(0)),
                },
                sink,
            )
        }
    }

    /// 客户端读端：先交出 `data` 里的全部字节，之后每次读取都返回 UnexpectedEof，
    /// 模拟 Content-Length 没收满、或 chunked 迟迟等不到终止块的截断请求体。
    struct TruncatingReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl TruncatingReader {
        fn new(data: Vec<u8>) -> Self {
            TruncatingReader { data, pos: 0 }
        }
    }

    impl AsyncRead for TruncatingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            let n = std::cmp::min(this.data.len() - this.pos, buf.remaining());
            buf.initialize_unfilled_to(n)
                .copy_from_slice(&this.data[this.pos..this.pos + n]);
            buf.advance(n);
            this.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// 空闲看门狗到点就要求退出的检查器：用于模拟客户端半途停住不再发送。
    struct StallQuitCheck {
        wheel: Arc<IdleWheel>,
    }

    impl IdleCheck for StallQuitCheck {
        fn interval_timer(&self) -> IdleInterval {
            self.wheel.register()
        }
        fn check_quit(&self, idle_count: usize) -> bool {
            idle_count >= 1
        }
        fn check_force_quit(&self) -> Option<IdleForceQuitReason> {
            None
        }
    }

    /// 造一个"ICAP 请求头首发即写失败"的适配器，确定性走兜底纯转发分支。
    fn broken_icap_adapter(client: &IcapReqmodClient) -> BypassAdapter<NoIdleCheck> {
        struct BrokenWriter;
        impl AsyncWrite for BrokenWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let mut conn = crate::service::IcapClientConnection::placeholder();
        conn.writer = Box::new(BrokenWriter);
        conn.reader = BufReader::new(Box::new(tokio::io::empty()));
        BypassAdapter::with_connection(
            client.service_client().clone(),
            conn,
            StreamCopyConfig::default(),
            idle_check(),
        )
    }

    const OPTIONS_OK: &[u8] =
        b"ICAP/1.0 200 OK\r\nISTag: \"mock\"\r\nAllow: request\r\nConnection: keep-alive\r\n\r\n";
    const RSP_204: &[u8] =
        b"ICAP/1.0 204 No Content\r\nISTag: \"mock\"\r\nConnection: keep-alive\r\n\r\n";

    #[derive(Clone, Copy)]
    enum Scenario {
        /// 收完整个 ICAP 请求后回 204
        Normal204,
        /// 读完 ICAP 请求头就抢先回 204（不等请求体发完）
        EarlyResponse,
        /// 收完后延迟回 204（判决慢场景）
        SlowVerdict,
    }

    fn find_seq(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// 测试侧的分块解码：把封装区里 req-body 的 chunked 线格式还原成裸内容，
    /// 用于断言"上报的是解码后的原始字节流、只是重新分了块"。
    fn decode_chunked(data: &[u8]) -> Vec<u8> {
        let mut rest = data;
        let mut out = Vec::new();
        loop {
            let pos = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("chunk-size line must end with CRLF");
            let line = String::from_utf8_lossy(&rest[..pos]);
            let size = usize::from_str_radix(line.trim(), 16).expect("hex chunk size");
            rest = &rest[pos + 2..];
            if size == 0 {
                return out;
            }
            assert!(rest.len() >= size, "chunk body shorter than its size");
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size..];
            assert_eq!(&rest[..2], b"\r\n", "chunk body must be followed by CRLF");
            rest = &rest[2..];
        }
    }

    /// 读一个完整的 ICAP 请求头（到 \r\n\r\n）。
    async fn read_icap_head<R: AsyncRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match r.read(&mut byte).await {
                Ok(0) => return None,
                Ok(_) => head.push(byte[0]),
                Err(_) => return None,
            }
            if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
                return Some(head);
            }
            if head.len() > 65536 {
                return None;
            }
        }
    }

    async fn serve_conn(
        mut stream: TcpStream,
        scenario: Scenario,
        saw_terminator: Arc<AtomicBool>,
    ) {
        loop {
            let head = match read_icap_head(&mut stream).await {
                Some(h) => h,
                None => return,
            };
            if head.windows(7).any(|w| w == b"OPTIONS") {
                if stream.write_all(OPTIONS_OK).await.is_err() {
                    return;
                }
                continue;
            }
            // REQMOD：从此刻起是封装区（req-hdr + chunked body）
            if matches!(scenario, Scenario::EarlyResponse) {
                // 抢先回 204：不等请求体发完。测试 body 控制在本地 socket 缓冲
                // 可容纳的大小，管线仍需靠后台写任务与排空逻辑正常推进。
                let _ = stream.write_all(RSP_204).await;
            }
            let mut buf = vec![0u8; 4096];
            let mut acc = Vec::new();
            let mut done = false;
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if find_seq(&acc, b"0\r\n\r\n") {
                    // 注意：测试 framing 的 req-hdr 特意不含 "0\r\n\r\n" 序列，
                    // 这里命中的一定是分块终止标记（见 Ruling：HTTP/1.0 结尾的
                    // "1.0\r\n\r\n" 会与之冲突，因此测试 req-hdr 用 HTTP/1.1）。
                    saw_terminator.store(true, Ordering::SeqCst);
                    done = true;
                    break;
                }
                acc.drain(..acc.len().saturating_sub(16));
            }
            if !done && matches!(scenario, Scenario::Normal204) {
                // 未等到终止标记也照常回，避免测试卡死
                saw_terminator.store(false, Ordering::SeqCst);
            }
            match scenario {
                Scenario::SlowVerdict => {
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                    let _ = stream.write_all(RSP_204).await;
                }
                Scenario::Normal204 | Scenario::EarlyResponse => {
                    if matches!(scenario, Scenario::Normal204) {
                        let _ = stream.write_all(RSP_204).await;
                    }
                }
            }
            return;
        }
    }

    async fn start_mock(
        scenario: Scenario,
    ) -> (SocketAddr, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let saw_terminator = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_terminator);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let flag = Arc::clone(&flag);
                        tokio::spawn(serve_conn(stream, scenario, flag));
                    }
                    Err(_) => return,
                }
            }
        });
        (addr, saw_terminator, task)
    }

    /// 捕获版 mock：把 REQMOD 的 ICAP 头区与其后的封装区原样留存，
    /// 供"审计字段是否真的上了线"这类线格式断言使用。语义同 Normal204：
    /// 收完分块终止标记后回 204。
    async fn start_mock_capture() -> (
        SocketAddr,
        Arc<std::sync::Mutex<Vec<u8>>>,
        Arc<std::sync::Mutex<Vec<u8>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let new_cap = || Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let head = new_cap();
        let encapsulated = new_cap();
        let (head_task, enc_task) = (Arc::clone(&head), Arc::clone(&encapsulated));
        let task = tokio::spawn(async move {
            while let Ok((stream, _addr)) = listener.accept().await {
                tokio::spawn(serve_capture(
                    stream,
                    Arc::clone(&head_task),
                    Arc::clone(&enc_task),
                ));
            }
        });
        (addr, head, encapsulated, task)
    }

    async fn serve_capture(
        mut stream: TcpStream,
        head: Arc<std::sync::Mutex<Vec<u8>>>,
        encapsulated: Arc<std::sync::Mutex<Vec<u8>>>,
    ) {
        loop {
            let req_head = match read_icap_head(&mut stream).await {
                Some(h) => h,
                None => return,
            };
            if req_head.windows(7).any(|w| w == b"OPTIONS") {
                if stream.write_all(OPTIONS_OK).await.is_err() {
                    return;
                }
                continue;
            }
            // 只留 REQMOD 那一次的头区：管线可能先做过 OPTIONS 探测
            head.lock().unwrap().extend_from_slice(&req_head);
            let mut buf = vec![0u8; 4096];
            let mut acc = Vec::new();
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                encapsulated.lock().unwrap().extend_from_slice(&buf[..n]);
                if find_seq(&acc, b"0\r\n\r\n") {
                    break;
                }
                acc.drain(..acc.len().saturating_sub(16));
            }
            let _ = stream.write_all(RSP_204).await;
            return;
        }
    }

    async fn reqmod_client_to(addr: SocketAddr) -> IcapReqmodClient {
        let url = url::Url::parse(&format!("icap://{addr}/mock")).unwrap();
        let config = Arc::new(IcapServiceConfig::new(IcapMethod::Reqmod, url).unwrap());
        let client = Arc::new(IcapServiceClient::new(config).unwrap());
        IcapReqmodClient::new(client)
    }

    /// 测试用 framing：注意结尾不能含 "0\r\n\r\n" 子串。
    fn test_framing() -> BypassFraming {
        BypassFraming {
            req_hdr: b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
            transformed_from: "HTTP/1.1",
        }
    }

    fn test_body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn idle_check() -> NoIdleCheck {
        NoIdleCheck {
            wheel: IdleWheel::spawn(Duration::from_millis(200)),
        }
    }

    async fn poll_flag(flag: &Arc<AtomicBool>, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        flag.load(Ordering::SeqCst)
    }

    // ---------- Review Focus 五测试 ----------

    #[tokio::test]
    async fn test_normal_204_audit_and_forward_counts_bytes() {
        let (addr, terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(100 * 1024);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = tokio::time::timeout(
            Duration::from_secs(5),
            adapter.audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w),
        )
        .await
        .expect("no deadlock");

        match end {
            BypassEndState::OriginalTransferredInBackground { bytes } => {
                assert_eq!(bytes, body.len() as u64);
            }
            other => panic!("unexpected end state: {other:?}"),
        }
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
        assert!(state.clt_read_finished);
        assert!(
            poll_flag(&terminator, Duration::from_secs(3)).await,
            "server must observe chunk terminator"
        );
    }

    #[tokio::test]
    async fn test_run_state_marks_upstream_send_complete() {
        let (addr, _terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(16 * 1024);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, _ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            adapter.audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w),
        )
        .await
        .expect("no deadlock");

        // 调用方靠这两个字段回填"请求体整体发送耗时"等任务日志指标
        assert!(state.ups_write_finished);
        assert!(state.dur_ups_send_all.is_some());
    }

    #[tokio::test]
    async fn test_upstream_half_close_is_optional() {
        let (addr, _terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let body = test_body(16 * 1024);

        // 默认（FTP 数据通道语义）：请求体送达后半关闭上游写侧
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, shutdowns) = CollectingWriter::new_counting_pair();
        let mut state = new_run_state();
        let _ = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        assert_eq!(
            shutdowns.load(Ordering::SeqCst),
            1,
            "half-close is on by default"
        );

        // 关闭后：HTTP 请求体自带结束标记，不需要 EOF 信令，
        // 上游写侧必须留给 keep-alive / 流水线复用
        let mut adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();
        adapter.set_upstream_half_close(false);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, shutdowns) = CollectingWriter::new_counting_pair();
        let mut state = new_run_state();
        let _ = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        assert_eq!(
            shutdowns.load(Ordering::SeqCst),
            0,
            "explicitly disabled half-close must not shut the upstream write side down"
        );
    }

    #[tokio::test]
    async fn test_client_eof_midway_still_terminates_icap_request() {
        let (addr, terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(64 * 1024);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        assert!(matches!(
            end,
            BypassEndState::OriginalTransferredInBackground { .. }
        ));
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
        // Cursor 读完即 EOF：管线仍须把 0\r\n\r\n 终止标记写给 ICAP
        assert!(poll_flag(&terminator, Duration::from_secs(3)).await);
    }

    #[tokio::test]
    async fn test_client_read_error_does_not_mark_request_complete() {
        // 截断的请求体绝不能被汇报成"已收满"：调用方据此决定是否把仍然开着的
        // 上游连接放回 keep-alive 池，误判会让下一个请求被源站当成残体的续文。
        let (addr, _terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(16 * 1024);
        let mut clt_r = TruncatingReader::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        // fail-open：源头断了不改变转发结果，已收到的部分照常交给上游
        assert!(matches!(
            end,
            BypassEndState::OriginalTransferredInBackground { .. }
        ));
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
        assert!(
            !state.clt_read_finished,
            "a client read error is not a complete request body"
        );
        assert!(
            !state.ups_write_finished,
            "a half-written body must not make the upstream connection reusable"
        );
    }

    #[tokio::test]
    async fn test_idle_timeout_does_not_mark_request_complete() {
        // 客户端半途停住（连接还活着）被看门狗掐掉：同样是未搬完的请求体
        let (addr, _terminator, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(
                StreamCopyConfig::default(),
                StallQuitCheck {
                    wheel: IdleWheel::spawn(Duration::from_millis(50)),
                },
            )
            .await
            .unwrap();

        let (mut keeper, mut clt_r) = tokio::io::duplex(4096);
        keeper.write_all(b"partial-body").await.unwrap();
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        drop(keeper);

        assert!(matches!(
            end,
            BypassEndState::OriginalTransferredInBackground { .. }
        ));
        assert_eq!(ups_sink.lock().unwrap().as_slice(), b"partial-body");
        assert!(
            !state.clt_read_finished,
            "a stalled client never finished the body"
        );
        assert!(!state.ups_write_finished);
    }

    #[tokio::test]
    async fn test_fallback_forward_on_client_error_does_not_mark_complete() {
        // ICAP 不可达时走兜底纯转发：这条路径同样是"审计降级"，
        // 但请求体完整性判断不能因此失真（源头截断时依旧不许复用上游连接）
        let client = reqmod_client_to("127.0.0.1:1".parse().unwrap()).await;
        let adapter = broken_icap_adapter(&client);

        let body = test_body(4096);
        let mut clt_r = TruncatingReader::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        assert!(matches!(
            end,
            BypassEndState::OriginalTransferredAfterFallback { .. }
        ));
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
        assert!(!state.clt_read_finished);
        assert!(!state.ups_write_finished);
    }

    #[tokio::test]
    async fn test_echo_service_concurrent_drain() {
        // 模拟"不等请求收完就抢先回响应"的 ICAP 服务（echo 型服务的最坏时机）：
        // 后台写任务必须边写边排空读侧并捕获响应头，主流程不死锁、字节计数正确。
        let (addr, _term, _mock) = start_mock(Scenario::EarlyResponse).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(256 * 1024);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = tokio::time::timeout(
            Duration::from_secs(5),
            adapter.audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w),
        )
        .await
        .expect("early response must not deadlock the relay");
        match end {
            BypassEndState::OriginalTransferredInBackground { bytes } => {
                assert_eq!(bytes, body.len() as u64);
            }
            other => panic!("unexpected end state: {other:?}"),
        }
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
    }

    #[tokio::test]
    async fn test_slow_verdict_returns_background_and_reclaims() {
        let (addr, _term, _mock) = start_mock(Scenario::SlowVerdict).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();

        let body = test_body(64 * 1024);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let t0 = tokio::time::Instant::now();
        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        let elapsed = t0.elapsed();
        assert!(matches!(
            end,
            BypassEndState::OriginalTransferredInBackground { .. }
        ));
        assert!(
            elapsed < Duration::from_millis(800),
            "2s verdict must not block the transfer, got {elapsed:?}"
        );
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());

        // 判决在后台完成并回收连接后，同一客户端应能立即取到复用连接。
        // （见 Ruling：池后台也可能补建连接，is_reused 是"回收机制整体工作"的
        // 弱断言，而非精确到本次连接。）
        let mut reused = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !reused {
            let svc = client.service_client().clone();
            if let Ok(Ok((conn, _opts))) =
                tokio::time::timeout(Duration::from_millis(500), svc.fetch_connection()).await
            {
                reused = conn.is_reused();
                drop(conn); // 未 mark_io_inuse 前不可回池，直接 drop 即可
            }
            if !reused {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        assert!(
            reused,
            "background verdict should reclaim the ICAP connection into the pool"
        );
    }

    #[tokio::test]
    async fn test_header_send_failure_falls_back_to_forward_only() {
        // 用确定性写失败的 writer 制造 ICAP 头首发即断连。
        let client = reqmod_client_to("127.0.0.1:1".parse().unwrap()).await;
        let adapter = broken_icap_adapter(&client);

        let body = test_body(4096);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();

        let end = adapter
            .audit_and_forward(&mut state, test_framing(), &mut clt_r, &mut ups_w)
            .await;
        match end {
            BypassEndState::OriginalTransferredAfterFallback { bytes, .. } => {
                assert_eq!(bytes, body.len() as u64);
            }
            other => panic!("unexpected end state: {other:?}"),
        }
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());
        assert!(state.clt_read_finished);
    }

    #[tokio::test]
    async fn test_tuple_keylog_username_extended_headers_present() {
        // 审计字段是否真的上了线：用捕获版 mock 把 ICAP 头区与封装区原样存下来，
        // 再逐行断言扩展头、Encapsulated 偏移与封装的请求头字节。
        let (addr, head_cap, enc_cap, _mock) = start_mock_capture().await;
        let client = reqmod_client_to(addr).await;
        let mut adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();
        adapter.set_client_addr("203.0.113.7:5555".parse().unwrap());
        adapter.set_client_username(arcstr::ArcStr::from("alice"));
        adapter.set_connection_tuple(ConnectionTuple {
            server_addr: "192.0.2.1:8080".parse().unwrap(),
            remote_addr: "198.51.100.9:21".parse().unwrap(),
            protocol: ConnectionProtocol::Tcp,
        });
        let keylog = Arc::new(g3_types::net::TlsKeyLogBuffer::new_empty());
        let server_random = "aa".repeat(32);
        let client_random = "bb".repeat(32);
        let secret = "cc".repeat(32);
        keylog.set_server_random(server_random.clone());
        assert!(keylog.add(
            "CLIENT_RANDOM".to_string(),
            client_random.clone(),
            secret.clone(),
        ));
        adapter.set_keylog_buffer(Arc::clone(&keylog));

        let req_hdr = b"POST /upload HTTP/1.1\r\nHost: example.org\r\nContent-Length: 4\r\n\r\n";
        let framing = BypassFraming {
            req_hdr: req_hdr.to_vec(),
            transformed_from: "HTTP/2.0",
        };
        let body = test_body(2048);
        let mut clt_r = Cursor::new(body.clone());
        let (mut ups_w, ups_sink) = CollectingWriter::new_pair();
        let mut state = new_run_state();
        let end = adapter
            .audit_and_forward(&mut state, framing, &mut clt_r, &mut ups_w)
            .await;
        assert!(
            matches!(end, BypassEndState::OriginalTransferredInBackground { .. }),
            "{end:?}"
        );
        assert_eq!(ups_sink.lock().unwrap().len(), body.len());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if find_seq(&enc_cap.lock().unwrap(), b"0\r\n\r\n") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let head = String::from_utf8_lossy(&head_cap.lock().unwrap()).into_owned();
        assert!(
            head.starts_with("REQMOD icap://"),
            "ICAP 请求行是 `REQMOD <uri> ICAP/1.0`：{head}"
        );
        for expect in [
            "REQMOD icap://",
            "Allow: 204\r\n",
            "X-Transformed-From: HTTP/2.0\r\n",
            "X-Client-IP: 203.0.113.7\r\n",
            "X-Client-Port: 5555\r\n",
            "X-Client-Username: alice\r\n",
            "X-Authenticated-User: TG9jYWw6Ly9hbGljZQ==\r\n",
            "X-Proxy-IP: 192.0.2.1\r\n",
            "X-Proxy-PORT: 8080\r\n",
            "X-Remote-IP: 198.51.100.9\r\n",
            "X-Remote-PORT: 21\r\n",
            "X-Proto-P: 6\r\n",
            &format!("X-TLS-SERVER_RANDOM: {server_random}\r\n"),
            &format!("X-TLS-CLIENT_RANDOM: {client_random} {secret}\r\n"),
            &format!("Encapsulated: req-hdr=0, req-body={}\r\n", req_hdr.len()),
        ] {
            assert!(
                head.contains(expect),
                "missing {expect:?} in ICAP head:\n{head}"
            );
        }

        let enc = enc_cap.lock().unwrap().clone();
        assert!(
            enc.starts_with(req_hdr),
            "the encapsulated region must begin with the framing req-hdr: {:?}",
            String::from_utf8_lossy(&enc[..enc.len().min(64)])
        );
        assert!(
            find_seq(&enc, b"0\r\n\r\n"),
            "the ICAP request must be terminated by the chunk terminator"
        );
        assert_eq!(
            decode_chunked(&enc[req_hdr.len()..]),
            body,
            "the audited body must arrive as the raw stream re-framed in chunks"
        );
    }

    #[tokio::test]
    async fn test_audit_only_mode_counts_bytes() {
        // audit_only 路径：无上游写，只送 ICAP，同步解析判决返回 AuditOnly。
        let (addr, term, _mock) = start_mock(Scenario::Normal204).await;
        let client = reqmod_client_to(addr).await;
        let adapter = client
            .bypass_adapter(StreamCopyConfig::default(), idle_check())
            .await
            .unwrap();
        let body = test_body(4096);
        let mut clt_r = Cursor::new(body.clone());
        let mut state = new_run_state();
        let end = adapter
            .audit_only(&mut state, test_framing(), &mut clt_r)
            .await;
        match end {
            BypassEndState::AuditOnly {
                icap_status_code,
                bytes,
                ..
            } => {
                assert_eq!(icap_status_code, 204);
                assert_eq!(bytes, body.len() as u64);
            }
            other => panic!("unexpected end state: {other:?}"),
        }
        assert!(poll_flag(&term, Duration::from_secs(2)).await);
    }

    // ---------- append_chunk_header 既有单测平移 ----------

    use super::append_chunk_header;

    #[test]
    fn test_append_chunk_header_zero() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 0);
        assert_eq!(buf.as_ref(), b"0\r\n");
    }

    #[test]
    fn test_append_chunk_header_single_digit() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 5);
        assert_eq!(buf.as_ref(), b"5\r\n");
    }

    #[test]
    fn test_append_chunk_header_two_digits() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 255);
        assert_eq!(buf.as_ref(), b"ff\r\n");
    }

    #[test]
    fn test_append_chunk_header_three_digits() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 4096);
        assert_eq!(buf.as_ref(), b"1000\r\n");
    }

    #[test]
    fn test_append_chunk_header_large() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 0x10000);
        assert_eq!(buf.as_ref(), b"10000\r\n");
    }

    #[test]
    fn test_append_chunk_header_usize_max() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, usize::MAX);
        // usize::MAX on 64-bit = 0xffffffffffffffff = 16 f's
        if cfg!(target_pointer_width = "64") {
            assert_eq!(buf.as_ref(), b"ffffffffffffffff\r\n");
        } else {
            assert_eq!(buf.as_ref(), b"ffffffff\r\n");
        }
    }
}
