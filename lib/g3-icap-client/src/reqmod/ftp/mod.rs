/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP 上传审计适配器（本机扩展，服务 repid 审计场景）。
//!
//! FTP 数据通道里传输的是裸字节流，没有 HTTP 语义，无法直接送进 ICAP。
//! [`FtpUploadAdapter`] 的做法是把一次 STOR 上传"伪装"成一次 HTTP 请求
//! 再走标准 REQMOD：
//!
//! ```text
//! PUT <ftp_path> HTTP/1.1
//! Host: localhost
//! Content-Type: application/octet-stream
//! X-FTP-Command: STOR
//! ```
//!
//! 并在这段伪 HTTP 头之外附加 ICAP 扩展头：`Allow: 204`（声明只需放行
//! 判决即可）、`X-Transformed-From: FTP`、X-Client-IP/Port、五元组
//! （X-Proxy-IP / X-Remote-IP / X-Proto-P）以及 X-TLS-* keylog（供服务端
//! 解密审计 HTTPS 侧内容）。
//!
//! 最核心的设计约束：**审计失败绝不阻断上传**。任何 ICAP 侧的写失败、
//! 读失败或响应过慢，都会退化为 fallback 路径（forward-only 纯转发，或
//! 把剩余判决读取放到后台任务），最终通过 [`FtpAdaptationEndState`]
//! 告知调用方"数据到底送达了没有、审计进行到了哪一步"；失败面本身则由
//! [`FtpAdaptationErrorKind`] 六分类（客户端读/上游写/ICAP 写/ICAP 读/
//! 强制退出/内部）。
//!
//! 内存特性：整条流水线只用一块固定大小的缓冲循环读写，堆占用不随
//! 被审计文件的大小增长。

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, empty, sink};
use tokio::time::Instant;

use g3_io_ext::{IdleCheck, LimitedWriteExt, OnceBufReader, StreamCopyConfig};

use log::{debug, warn};

use super::{ConnectionTuple, IcapReqmodClient, TlsKeyLogBuffer};
use crate::reqmod::mail::ReqmodAdaptationRunState;
use crate::service::{IcapClientConnection, IcapClientReader, IcapClientWriter};
use crate::{IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::FtpAdaptationError;

/// Classification of adaptation failures, used by callers to decide
/// whether they can still deliver the original payload to upstream.
/// 失败面分类：调用方据此判断"原始数据还能不能继续送给上游"。
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FtpAdaptationErrorKind {
    /// Failure reading the FTP client data channel.  The transfer must
    /// be aborted entirely - there is no data left to forward.
    /// 客户端数据通道读失败：源头断了，上传只能整体终止。
    ClientRead,
    /// Failure writing to the upstream FTP server.  The transfer must
    /// be aborted entirely.
    /// 上游 FTP 服务器写失败：目的地断了，上传同样必须终止。
    UpstreamWrite,
    /// Failure writing only to the ICAP service.  The original payload
    /// may still be forwarded to upstream; the audit was best-effort.
    /// 仅 ICAP 写失败：审计尽力而为，上传可以照常继续。
    IcapWrite,
    /// Failure reading the ICAP verdict.  The audit verdict is unknown
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

/// Final audit verdict from the ICAP server for an uploaded file.
/// 一次上传结束时返回给调用方的最终状态：区分"上传+审计都完成"、
/// "只审计"、"审计失败但已兜底转发"、"审计转入后台继续"四种走向。
#[derive(Debug)]
pub enum FtpAdaptationEndState {
    /// Audit completed successfully and the original data was already
    /// forwarded to the upstream FTP server.
    /// 同步路径：ICAP 判决已读到，且原始数据已完整转发给上游。
    OriginalTransferred {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP responded, but we were operating in audit-only mode (no
    /// upstream forwarding configured).  The audit verdict is provided
    /// but no bytes were forwarded.
    /// audit_only 模式：调用方自行转发数据，这里只回传审计判决。
    AuditOnly {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP adaptation failed in a way that did NOT prevent us from
    /// forwarding data upstream.  This is the "never block upload"
    /// safety net for enterprise ICAP auditing.
    /// 兜底路径：ICAP 审计失败，但原始数据仍然转发成功——
    /// "审计失败绝不阻断上传"的安全网就体现在这个状态上。
    OriginalTransferredAfterFallback { bytes: u64, icap_error: String },
    /// ICAP audit is being processed in the background.  The upload
    /// data has already been forwarded to the upstream FTP server.
    /// The audit verdict will be available asynchronously.
    /// 转发已完成，ICAP 判决的读取/善后交给后台任务异步处理
    /// （避免慢 ICAP 拖住上传的收尾）。
    OriginalTransferredInBackground { bytes: u64 },
}

impl IcapReqmodClient {
    /// Build a new streaming FTP upload auditor.  The returned adapter
    /// binds an ICAP connection from the pool (or opens a new one),
    /// so it should only be constructed when a data transfer actually
    /// begins.
    /// 构造一个流式 FTP 上传审计器。注意：这里就会从连接池占用（或新建）
    /// 一条 ICAP 连接，所以只应在数据真正开始传输时创建，不要提前构造。
    ///
    /// This adapter is designed to be reused by both native FTP proxy
    /// data channels and HTTP CONNECT-tunnelled FTP traffic detected
    /// in-band by g3proxy.
    pub async fn ftp_upload_audit_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> anyhow::Result<FtpUploadAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(FtpUploadAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            idle_checker,
            client_addr: None,
            connection_tuple: None,
            keylog_buffer: None,
        })
    }

    /// Convenience accessor: callers may need the raw service client
    /// for metrics/monitoring or to fall back to manual pool save.
    /// 透传出底层服务客户端句柄，供调用方打点监控或在特殊路径下手动归还连接。
    pub fn ftp_service_client(&self) -> &Arc<IcapServiceClient> {
        &self.inner
    }
}

/// FTP 上传数据通道的 ICAP 审计适配器（一次上传一个实例，按所有权消费）。
pub struct FtpUploadAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    #[allow(dead_code)]
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    idle_checker: I,
    client_addr: Option<SocketAddr>,
    /* added for connection tuple */
    connection_tuple: Option<ConnectionTuple>,
    /* added for TLS keylog */
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<I: IdleCheck> FtpUploadAdapter<I> {
    /// Record the client address; sent to the ICAP server as
    /// X-Client-IP / X-Client-Port headers so the audit service can
    /// correlate streams with users.
    /// 记录客户端地址，最终以 X-Client-IP / X-Client-Port 头送给 ICAP，
    /// 让审计服务端能把数据流关联到具体用户。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
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

    /// 把 FTP 上传伪装成伪 HTTP 请求行 + 最小头部（PUT + Host +
    /// Content-Type + X-FTP-Command），作为 ICAP 封装区里的 req-hdr。
    fn build_http_header(&self, ftp_cmd: &str, ftp_path: &str) -> Vec<u8> {
        let mut header = Vec::with_capacity(256);
        let _ = write!(
            header,
            "PUT {} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/octet-stream\r\n\
             X-FTP-Command: {}\r\n\
             \r\n",
            ftp_path, ftp_cmd
        );
        header
    }

    /// 追加本扩展专用的 ICAP 头：Allow: 204 告诉服务器"只回 204 放行
    /// 就行，不需要修改后的内容"；X-Transformed-From: FTP 声明协议来源；
    /// 其余为可选的客户端地址 / 五元组 / keylog 关联信息。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"Allow: 204\r\n");
        data.put_slice(b"X-Transformed-From: FTP\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
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

    /// Stream the data channel from `clt_r` to both `ups_w` (the
    /// upstream FTP server) and the ICAP server.  ICAP failures never
    /// abort the upstream forward; callers receive an
    /// `FtpAdaptationEndState` describing what happened.
    /// 主入口：把 FTP 客户端数据通道同时扇出到上游 FTP 服务器和 ICAP 服务。
    /// 任何 ICAP 侧失败都只降级审计、不中断上传，最终以
    /// [`FtpAdaptationEndState`] 汇报实际走向。
    ///
    /// Memory behaviour: a single fixed-size buffer is used for every
    /// read/duplicate/write cycle, so the heap footprint does not grow
    /// with file size.
    /// 内存模型：读-复制-写循环全程复用一块固定缓冲，堆占用与文件大小无关。
    pub async fn audit_and_forward<CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: &mut UW,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
    {
        // 第一步：发送 ICAP 请求头 + 伪 HTTP 封装头。
        // 若这里就失败（连接已死），ICAP 完全无法参与——直接退化为
        // forward-only 纯转发，保证上传不受影响。
        if let Err(e) = self.send_icap_header(ftp_cmd, ftp_path).await {
            warn!(
                "FTP ICAP header send failed, fallback to forward-only: {}",
                e
            );
            return self.fallback_forward_only(clt_r, ups_w, state, e).await;
        }

        // 第二步：边读客户端边双写（上游 + ICAP 后台写任务）。
        // Err(bytes) 表示"上游写失败"——这是唯一需要终止上传的错误面，
        // 此时 ICAP 侧已写入的数据不再等待判决，直接如实上报。
        let (total_bytes, icap_ok, icap_handle) = match self.run_relay_loop(clt_r, ups_w).await {
            Ok((bytes, ok, handle)) => (bytes, ok, handle),
            Err(bytes) => {
                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                    bytes,
                    icap_error: "upstream write failed".to_string(),
                };
            }
        };

        state.clt_read_finished = true;

        // 客户端 EOF：把上游已缓冲的数据冲出去并关闭写侧，上传至此完成。
        let _ = ups_w.flush().await;
        let _ = ups_w.shutdown().await;

        // icap_ok=false 表示中继期间 ICAP 写通道已断开/被慢速背压掐掉：
        // 回收后台任务（拿回连接资源）后如实汇报"转发成功、审计失败"。
        if !icap_ok {
            let _ = icap_handle.await;
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
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
                            warn!("FTP ICAP background task panicked");
                            return;
                        }
                    };

                if let Err(e) = icap_result {
                    warn!("FTP ICAP write failed ({}), audit incomplete", e);
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
                        warn!("FTP ICAP response parse failed: {}", e);
                        // Do not save a connection with partial/unparsed response
                        return;
                    }
                };

                debug!(
                    "FTP ICAP response: code={}, reason={}, keep_alive={}",
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
                        "FTP ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                        rsp.code, rsp.keep_alive, drain_clean
                    );
                }
            })
            .await;
        });

        FtpAdaptationEndState::OriginalTransferredInBackground { bytes: total_bytes }
    }

    /// 组装并发送 ICAP REQMOD 请求头：
    /// 预置的 `ICAP/1.0 REQMOD <uri>` 前缀 + 扩展头 +
    /// `Encapsulated: req-hdr=0, req-body=N` + 伪 HTTP 头（向量写一次发出）。
    async fn send_icap_header(&mut self, ftp_cmd: &str, ftp_path: &str) -> io::Result<()> {
        let http_header = self.build_http_header(ftp_cmd, ftp_path);
        let mut icap_header =
            Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header);
        // 封装区从 ICAP 头结束处算起：req-hdr 固定在偏移 0，
        // req-body 的偏移 = 伪 HTTP 头的字节数，文件内容紧随其后。
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            http_header.len()
        );

        debug!(
            "FTP ICAP request header ({} bytes, http_header {} bytes):\n{}",
            icap_header.len(),
            http_header.len(),
            String::from_utf8_lossy(&icap_header)
        );

        // 两段头一次 write_all_vectored 发出：省一次系统调用，
        // 也保证 ICAP 头与封装的伪 HTTP 头作为整体送达服务器。
        self.icap_connection
            .writer
            .write_all_vectored([
                io::IoSlice::new(&icap_header),
                io::IoSlice::new(&http_header),
            ])
            .await?;
        self.icap_connection.writer.flush().await
    }

    /// 中继主循环：从客户端读一块数据，先写上游、再复制一份投递给
    /// ICAP 后台写任务；返回 (总字节数, ICAP 写侧是否存活, 后台任务句柄)。
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
        ),
        u64,
    >
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
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

        // 主中继循环：客户端数据是最高优先级（biased），空闲计时仅用于
        // 看门狗（长时间无数据时按 IdleCheck 策略强制退出）。
        loop {
            tokio::select! {
                biased;
                res = clt_r.read(&mut buf) => {
                    match res {
                        // 客户端 EOF：上传数据全部送达，正常结束
                        Ok(0) => break,
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
                                        warn!("FTP ICAP channel closed");
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
        Ok((total_bytes, icap_alive, icap_handle))
    }

    /// Audit-only mode: stream the data channel only to ICAP, no
    /// upstream forwarding.  Used by callers who already forward the
    /// data themselves (e.g. HTTP CONNECT tunnel handlers where the
    /// entire data copy is already happening) but want an audit copy.
    /// audit-only 模式：数据只送 ICAP 不上送上游——调用方（如 HTTP CONNECT
    /// 隧道处理器）自己已经在搬运原始数据，这里只额外做一份审计。
    /// 与 audit_and_forward 不同，此路径同步等待并解析 ICAP 判决
    /// （没有"不能阻断上传"的转发路径可兜底，失败时同样只汇报不抛错）。
    pub async fn audit_only<CR>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
    {
        // 与 send_icap_header 相同的组包逻辑，但此处需要区分
        // "头部写失败"以便走纯排空兜底，故未复用该方法
        let http_header = self.build_http_header(ftp_cmd, ftp_path);
        let mut icap_header =
            Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header);
        // req-body 偏移 = 伪 HTTP 头长度（相对封装区起点）
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            http_header.len()
        );

        let header_sent = self
            .icap_connection
            .writer
            .write_all_vectored([
                io::IoSlice::new(&icap_header),
                io::IoSlice::new(&http_header),
            ])
            .await;

        if header_sent.is_err() {
            // Best-effort drain so the caller doesn't stall because we
            // refused to read.
            // 尽力排空：调用方仍在往数据通道里写，我们不读它就会把
            // 对方的复制流程卡住；这里丢弃内容只计数，审计宣告失败。
            let mut buf = [0u8; 16 * 1024];
            let mut total_bytes = 0u64;
            loop {
                match clt_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total_bytes += n as u64,
                }
            }
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: "icap header write failed".to_string(),
            };
        }

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
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
                            total_bytes += n as u64;
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
                                        Ok(m) => total_bytes += m as u64,
                                    }
                                }
                                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                                    bytes: total_bytes,
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
                warn!("FTP ICAP response parse failed");
                self.icap_connection.mark_reader_finished();
                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
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
                "FTP ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                rsp.code, rsp.keep_alive, drain_clean
            );
        }

        // 成功：带回 ICAP 的状态码与原因短语，供调用方判断文件是否被拦截
        FtpAdaptationEndState::AuditOnly {
            icap_status_code: rsp.code,
            icap_reason: rsp.reason,
            bytes: total_bytes,
        }
    }

    /// Forward path used when ICAP header send fails immediately.
    /// Guarantees the client data is still delivered to upstream so
    /// the FTP upload succeeds.
    /// ICAP 请求头首发即失败时的兜底转发：彻底放弃审计，把数据通道
    /// 原样搬到上游，保证上传本身必然成功。
    async fn fallback_forward_only<CR, UW>(
        self,
        clt_r: &mut CR,
        ups_w: &mut UW,
        state: &mut ReqmodAdaptationRunState,
        first_err: io::Error,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
    {
        // The ICAP connection is effectively dead - just drop it.
        // ICAP 连接已不可信：drop 即关闭 TCP，不回收进连接池
        drop(self.icap_connection);

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();

        // 纯转发循环：没有任何 ICAP 分支，任一方向出错/空闲即停
        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
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
        state.clt_read_finished = true;

        // 无论转发是否完整，都如实带上字节数与首个 ICAP 错误，
        // 由调用方（如 g3proxy 的 FTP 处理器）决定如何向 FTP 客户端汇报结果
        FtpAdaptationEndState::OriginalTransferredAfterFallback {
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

/// A cheap builder/helper for creating a [`ReqmodAdaptationRunState`]
/// in FTP callers that don't have a mail module state tracker.
/// 便捷构造：FTP 调用方没有邮件模块那套状态跟踪器时，用这个直接建一个
/// 空的运行状态（内部只记录起始时间戳等）。
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState {
    ReqmodAdaptationRunState::new(Instant::now())
}

#[cfg(test)]
mod tests {
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
