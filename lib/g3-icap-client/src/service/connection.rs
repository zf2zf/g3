/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 单条连接抽象 + 连接器（TCP/TLS/UDS）实现。
//!
//! 关键类型：
//! - [`IcapClientConnection`]：把底层流 split 为 `reader`/`writer` 后包装；
//!   `reader_clean` / `writer_clean` 标记当前一次 ICAP 事务是否已把两端都"用完"，
//!   决定是否可安全回池。
//! - [`IcapConnector`]：按配置建立新的 TCP（可选 TLS）/ Unix Socket 连接。
//! - [`IcapConnectionEofPoller`]：连接回池后的空闲探测协程，等待 EOF、
//!   idle 超时、或下一次 fetch 把连接"唤醒"。
//!
//! 连接生命周期（新建 → OPTIONS → 复用 → 过期/关闭回池）详见 `service/mod.rs`。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

use g3_io_ext::{AsyncStream, LimitedBufReadExt};
use g3_types::net::{Host, RustlsClientConfig};

use super::IcapServiceConfig;
use crate::IcapServiceOptions;

/// ICAP 连接写端：使用 trait object 屏蔽 TCP/UDS/TLS 的差异，统一 `AsyncWrite`。
pub type IcapClientWriter = Box<dyn AsyncWrite + Send + Sync + Unpin>;
/// ICAP 连接读端：`BufReader` 包装以便按行/按块读 ICAP 头。
pub type IcapClientReader = BufReader<Box<dyn AsyncRead + Send + Sync + Unpin>>;

/// 单条 ICAP 连接：持有 reader/writer 两端 + 状态机。
///
/// 状态机含义：
/// - `reader_clean`：读端在上一事务中已读完所有数据；
/// - `writer_clean`：写端在上一事务中已发完所有数据；
/// - 二者都为 true 时连接才算 `reusable()`，才能回池；
/// - 任何一次发起 ICAP 请求前都会调用 `mark_io_inuse` 把两者清零。
pub struct IcapClientConnection {
    pub reader: IcapClientReader,
    pub writer: IcapClientWriter,
    reader_clean: bool,
    writer_clean: bool,
    reused_connection: bool,
}

impl IcapClientConnection {
    fn new<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Send + Sync + Unpin + 'static,
        W: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        IcapClientConnection {
            reader: BufReader::new(Box::new(reader)),
            writer: Box::new(writer),
            reader_clean: true,
            writer_clean: true,
            reused_connection: false,
        }
    }

    /// 是否是从池里复用的连接（用于上层打点/日志区分新建 vs 复用）。
    pub fn is_reused(&self) -> bool {
        self.reused_connection
    }

    /// 标记读端本轮事务已读完（例如读到完整 ICAP 响应头）。
    pub fn mark_reader_finished(&mut self) {
        self.reader_clean = true;
    }

    /// 标记写端本轮事务已发完（例如 ICAP 请求体写完）。
    pub fn mark_writer_finished(&mut self) {
        self.writer_clean = true;
    }

    /// 开始一次新事务前调用：读写两端都"未结束"，避免误判为 reusable。
    pub(super) fn mark_io_inuse(&mut self) {
        self.reader_clean = false;
        self.writer_clean = false;
    }

    /// 是否可被池回收（两端都 clean）。
    pub(super) fn reusable(&self) -> bool {
        self.reader_clean && self.writer_clean
    }

    /// Create a placeholder connection with no-op reader/writer.
    /// Used when the real connection halves have been moved into a
    /// background task and we need a temporary container to put them back.
    pub fn placeholder() -> Self {
        use tokio::io::{empty, sink};
        IcapClientConnection {
            reader: BufReader::new(Box::new(empty())),
            writer: Box::new(sink()),
            reader_clean: true,
            writer_clean: true,
            reused_connection: false,
        }
    }
}

/// ICAP 连接器：根据 [`IcapServiceConfig`] 建立底层传输。
///
/// 支持三种传输（按优先级）：
/// 1. `use_unix_socket`（仅 unix）：直接连 UDS；
/// 2. `tls_client` 不为 None：先 TCP 连接，再做 TLS 握手（SNI 取 URL host）；
/// 3. 纯 TCP（icap:// 明文）。
pub(super) struct IcapConnector {
    config: Arc<IcapServiceConfig>,
    tls_client: Option<RustlsClientConfig>,
}

impl IcapConnector {
    /// 预先把 `tls_client` builder 编译为可用的 rustls 客户端配置，
    /// 后续每建一条连接都复用同一份 TLS 配置（含会话缓存等）。
    pub(super) fn new(config: Arc<IcapServiceConfig>) -> anyhow::Result<Self> {
        let tls_client = match &config.tls_client {
            Some(builder) => {
                let client = builder
                    .build()
                    .context("failed to build TLS client config")?;
                Some(client)
            }
            None => None,
        };
        Ok(IcapConnector { config, tls_client })
    }

    /// 将 URL 中的 host 解析为 `SocketAddr`：域名走 DNS，IP 直接拼装。
    /// 只取解析结果中的第一个地址（与 g3 其它 client 行为一致）。
    async fn select_peer_addr(&self) -> io::Result<SocketAddr> {
        let upstream = &self.config.upstream;
        match upstream.host() {
            Host::Domain(domain) => {
                let mut addrs = tokio::net::lookup_host((domain.as_ref(), upstream.port())).await?;
                addrs
                    .next()
                    .ok_or_else(|| io::Error::other("no resolved socket address"))
            }
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, upstream.port())),
        }
    }

    /// 建立一条新的 ICAP 连接。
    ///
    /// 注意：TLS ServerName 直接来自 URL host（配置 `tls_name` 仅在显式覆盖时生效），
    /// 这样 SNI/证书校验与 URL 主机名保持一致，避免误配。
    pub(super) async fn create(&self) -> io::Result<IcapClientConnection> {
        #[cfg(unix)]
        if let Some(path) = &self.config.use_unix_socket
            && let Ok(socket) = tokio::net::UnixStream::connect(path).await
        {
            let (r, w) = socket.into_split();
            return Ok(IcapClientConnection::new(r, w));
        }

        let peer = self.select_peer_addr().await?;
        let socket = g3_socket::tcp::new_socket_to(
            peer.ip(),
            &Default::default(),
            &self.config.tcp_keepalive,
            &Default::default(),
            true,
        )?;
        let stream = socket.connect(peer).await?;

        if let Some(client) = &self.tls_client {
            let tls_connector = TlsConnector::from(client.driver.clone());
            // 对握手单独加超时：避免 TCP 已连上但 TLS 永远卡死拖垮整个服务。
            match tokio::time::timeout(
                client.handshake_timeout,
                tls_connector.connect(self.config.tls_name.clone(), stream),
            )
            .await
            {
                Ok(Ok(tls_stream)) => {
                    let (r, w) = tls_stream.into_split();
                    Ok(IcapClientConnection::new(r, w))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tls handshake with ICAP server timed out",
                )),
            }
        } else {
            let (r, w) = stream.into_split();
            Ok(IcapClientConnection::new(r, w))
        }
    }
}

/// 池 → poller 的"取连接"请求载荷：把 client 侧的 `oneshot` sender +
/// 当前缓存的 options 一起交给空闲 poller。
pub(super) struct IcapConnectionPollRequest {
    client_sender: oneshot::Sender<(IcapClientConnection, Arc<IcapServiceOptions>)>,
    options: Arc<IcapServiceOptions>,
}

impl IcapConnectionPollRequest {
    pub(super) fn new(
        client_sender: oneshot::Sender<(IcapClientConnection, Arc<IcapServiceOptions>)>,
        options: Arc<IcapServiceOptions>,
    ) -> Self {
        IcapConnectionPollRequest {
            client_sender,
            options,
        }
    }
}

/// 空闲连接的探测协程：在 `into_running` 中三选一，任一触发即退出
/// （退出意味着连接归还池、被 EOF/超时丢弃）。
///
/// - `fill_wait_data`：读端等待，直到有数据可读或对端关闭（EOF）；
///   空闲期间若服务端关闭连接，本协程被唤醒后 drop 连接即可。
/// - `idle_sleep`：超过 `idle_timeout` 未使用，主动丢弃。
/// - `req_receiver.recv()`：池里有 fetch 命令命中本连接，把连接 + options
///   发回 client 侧，本协程结束。
pub(super) struct IcapConnectionEofPoller {
    conn: IcapClientConnection,
    req_receiver: kanal::AsyncReceiver<IcapConnectionPollRequest>,
}

impl IcapConnectionEofPoller {
    /// 仅在连接 reusable 时启动 poller，否则直接丢弃。
    pub(super) fn new(
        conn: IcapClientConnection,
        req_receiver: &kanal::AsyncReceiver<IcapConnectionPollRequest>,
    ) -> Option<Self> {
        if conn.reusable() {
            Some(IcapConnectionEofPoller {
                conn,
                req_receiver: req_receiver.clone(),
            })
        } else {
            None
        }
    }

    pub(super) async fn into_running(mut self, idle_timeout: Duration) {
        let idle_sleep = tokio::time::sleep(idle_timeout);

        // biased select：按声明顺序优先处理 EOF 与 idle，保证服务端关闭/超时
        // 时不会先收到 client 端的 fetch 请求。
        tokio::select! {
            _ = self.conn.reader.fill_wait_data() => {}
            _ = idle_sleep => {}
            r = self.req_receiver.recv() => {
                if let Ok(req) = r {
                    let IcapConnectionPollRequest {
                        client_sender,
                        options,
                    } = req;
                    self.conn.reused_connection = true;
                    let _ = client_sender.send((self.conn, options));
                }
            }
        }
    }
}
