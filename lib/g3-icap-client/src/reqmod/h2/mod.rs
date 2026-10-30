/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! REQMOD over HTTP/2：把前端（clt）的 h2 请求上报给 ICAP 服务器，
//! 并把 ICAP 返回的（可能被改写的）请求转回 h2 发送给上游（ups）。
//!
//! 与 `reqmod::h1` 版对称，主要差异有两点：
//! - 封装进 ICAP 报文的"HTTP 请求报文"不是原始 TCP 字节流，而是由 h2 的
//!   pseudo-header + 普通头**降级序列化**出来的 HTTP/1.1 形式头部文本
//!   （`g3_h2::RequestExt::serialize_for_adapter()`）：`:method` 与
//!   `:path`（缺 path 时 `OPTIONS` 用 `*`、其它方法用 `/`）拼成请求行
//!   `METHOD path HTTP/1.1`，`:authority` 补成 `Host:` 头，`TE` 等
//!   hop-by-hop 头被跳过。因此本模块的扩展头写
//!   `X-Transformed-From: HTTP/2.0`（h1 版为 `HTTP/1.0`）。
//! - body 来自 h2 `RecvStream` 数据帧（流式、无 Content-Length 语义），
//!   上报 ICAP 时按 chunked 传输编码**重新分块**
//!   （`g3_h2::H2StreamToChunkedTransfer`，末尾补 `0\r\n` 终止块 +
//!   h2 trailer）；ICAP 改写的请求同样以 chunked 返回，再解码回 h2
//!   数据帧发给上游（`g3_h2::H2StreamFromChunkedTransfer`）。
//!
//! 其余能力与 h1 版一致：preview（先送一段预览体，等 ICAP 回
//! 100-continue 再送剩余体）、双向流（上行 body 转发与下行 ICAP 响应
//! 接收并发）、idle 超时检查。
//!
//! 本模块还附带本机审计扩展（非 RFC 3507 要求）：
//! `H2RequestAdapter::push_extended_headers` 会追加 `X-Proxy-IP` / `X-Proxy-PORT` /
//! `X-Remote-IP` / `X-Remote-PORT` / `X-Proto-P` 五元组（来自 [`ConnectionTuple`]）与
//! `X-TLS-VERSION` / `X-TLS-CIPHER` / `X-TLS-SERVER_RANDOM` / `X-TLS-KeyLog`
//! 等 keylog 头（来自 `TlsKeyLogBuffer`），供 ICAP 侧做 repid 审计与解密取证。
//!
//! 文件分工：
//! - `forward_header.rs`：无 body 的请求（`null-body` 偏移）与 CONNECT
//!   这类"只报头"的场景（`xfer_without_body` / `xfer_connect`）；
//! - `forward_body.rs`：全量（无 preview）上报，以及"小于 preview 上限、
//!   一次性把 body 发完"的小体上报（`xfer_small_body`）；
//! - `preview.rs`：先只发一段预览体，等 ICAP 回 100-continue 再继续；
//! - `bidirectional.rs`：上行 h2 body → chunked 与下行 ICAP 响应/改写请求
//!   并发进行的双向流处理；
//! - `recv_request.rs`：收到 ICAP 最终响应后，把原始/改写后的请求发给 h2
//!   上游的各收尾分支；
//! - `recv_response.rs`：ICAP 直接返回 HTTP 响应（拦截页）时的收尾分支；
//! - `error.rs`：本模块统一错误类型 [`H2ReqmodAdaptationError`]。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arcstr::ArcStr;
use bytes::{BufMut, Bytes};
use h2::client::SendRequest;
use h2::ext::Protocol;
use h2::{RecvStream, SendStream};
use http::{Extensions, Request, Response};
use tokio::time::Instant;

use g3_h2::H2StreamFromChunkedTransfer;
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::{IdleCheck, StreamCopyConfig};
use g3_types::net::{HttpHeaderMap, TlsKeyLogBuffer};

use super::{ConnectionTuple, IcapReqmodClient};
use crate::{IcapClientConnection, IcapClientReader, IcapServiceClient, IcapServiceOptions};

// ICAP 响应中封装的"HTTP 错误响应报文"的解析结果类型与 h1 版完全通用，
// 直接从 h1 模块复用（本模块只重导出，不重复定义）。
pub use crate::reqmod::h1::HttpAdapterErrorResponse;

mod error;
pub use error::H2ReqmodAdaptationError;

mod recv_request;
mod recv_response;

// 双向流（边上报 body 边接收 ICAP 响应）的两个协程结构体，仅模块内部使用
mod bidirectional;
use bidirectional::{BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse};

// 三种上报路径：只有头 / 带 body / 带 preview
mod preview;

mod forward_body;
mod forward_header;

impl IcapReqmodClient {
    /// 构造一个 h2 请求的 REQMOD 适配器。
    ///
    /// 会从 ICAP 连接池取（或新建）一条 ICAP 连接（`fetch_connection`），
    /// 并把该服务 `OPTIONS` 结果一并带进适配器，供后续判断是否支持
    /// 204 / preview 等能力。
    ///
    /// 参数说明（与 h1 版一致，大多针对"ICAP 返回的 HTTP 报文"的解析限制）：
    /// - `copy_config`：body 拷贝的分块/yield 大小等流控配置；
    /// - `http_body_line_max_size`：ICAP 返回报文中单行的长度上限；
    /// - `http_trailer_max_size`：ICAP 返回报文 trailer 头的总大小上限；
    /// - `http_rsp_head_recv_timeout`：请求 body 发完后，等待上游响应头的超时；
    /// - `http_req_add_no_via_header`：解析 ICAP 返回的请求头时是否忽略 `Via`
    ///   头（透传上游 `Via`，不追加本机标识）；
    /// - `idle_checker`：idle 检查器，各读写方向都靠它判定超时/强制退出。
    pub async fn h2_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        http_body_line_max_size: usize,
        http_trailer_max_size: usize,
        http_rsp_head_recv_timeout: Duration,
        http_req_add_no_via_header: bool,
        idle_checker: I,
    ) -> anyhow::Result<H2RequestAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(H2RequestAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            http_body_line_max_size,
            http_trailer_max_size,
            http_rsp_head_recv_timeout,
            http_req_add_no_via_header,
            idle_checker,
            client_addr: None,
            client_username: None,
            /* added by wming for repid audit */
            connection_tuple: None,
            keylog_buffer: None,
        })
    }
}

/// h2 REQMOD 适配器：一条 ICAP 连接 + 一次上报所需的全部配置。
///
/// 采用"消耗自身"（`self` by value）的写法：一次 `xfer*` 调用就把适配器
/// 连同 ICAP 连接一起移走，避免同一连接被重复上报。
/// 后置的 `Option` 字段都是可选的审计/身份信息，由调用方按需 `set_*` 填充。
pub struct H2RequestAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    // 该 ICAP 服务 OPTIONS 结果：决定是否支持 204、preview 大小等
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    http_body_line_max_size: usize,
    http_trailer_max_size: usize,
    http_rsp_head_recv_timeout: Duration,
    http_req_add_no_via_header: bool,
    idle_checker: I,
    // 客户端地址，序列化成 X-Client-IP / X-Client-Port 上报
    client_addr: Option<SocketAddr>,
    // 用户名（可为空），序列化成 X-Client-Username / X-Authenticated-User 上报
    client_username: Option<ArcStr>,
    /* added by wming for repid audit */
    // 五元组，序列化成 X-Proxy-IP/PORT、X-Remote-IP/PORT、X-Proto-P 上报
    connection_tuple: Option<ConnectionTuple>,
    // TLS keylog 缓冲区，序列化成 X-TLS-* 头上报（供 ICAP 侧解密审计）
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

/// 一次上报任务的运行时状态/耗时打点，由调用方（代理任务）创建并持有。
///
/// 各 `dur_ups_*` 都是"相对任务创建时刻"的累计耗时，不是相邻两次的间隔，
/// 因此必须在同一个 `task_create_instant` 基准上打点（见 `mark_*` 方法）。
pub struct ReqmodAdaptationRunState {
    task_create_instant: Instant,
    /// 向上游发送（改写后）请求头的完成时刻耗时；无 body 时也代表头已发出。
    pub dur_ups_send_header: Option<Duration>,
    /// 向上游发送完全部 body 的耗时。
    pub dur_ups_send_all: Option<Duration>,
    /// 收到上游响应头的耗时。
    pub dur_ups_recv_header: Option<Duration>,
    // ICAP 通过 X-... 共享头（respond_shared_names 配置）回传的内容，
    // 由适配器写入，调用方用 take_respond_shared_headers 取走
    pub(crate) respond_shared_headers: Option<HttpHeaderMap>,
}

impl ReqmodAdaptationRunState {
    /// 以任务创建时刻 `task_create_instant` 为基准创建运行状态，所有耗时从 0 起算。
    pub fn new(task_create_instant: Instant) -> Self {
        ReqmodAdaptationRunState {
            task_create_instant,
            dur_ups_send_header: None,
            dur_ups_send_all: None,
            dur_ups_recv_header: None,
            respond_shared_headers: None,
        }
    }

    /// 取走（并清空）ICAP 回传的共享头，供调用方附加到对客户端的响应上。
    pub fn take_respond_shared_headers(&mut self) -> Option<HttpHeaderMap> {
        self.respond_shared_headers.take()
    }

    /// 打点：上游请求头已发出。
    pub(crate) fn mark_ups_send_header(&mut self) {
        self.dur_ups_send_header = Some(self.task_create_instant.elapsed());
    }

    /// 打点：无 body 的请求，"头发完"即"全部发完"，直接复用 send_header 的时刻。
    pub(crate) fn mark_ups_send_no_body(&mut self) {
        self.dur_ups_send_all = self.dur_ups_send_header;
    }

    /// 打点：上游请求 body 已全部发出。
    pub(crate) fn mark_ups_send_all(&mut self) {
        self.dur_ups_send_all = Some(self.task_create_instant.elapsed());
    }

    /// 打点：已收到上游响应头。
    pub(crate) fn mark_ups_recv_header(&mut self) {
        self.dur_ups_recv_header = Some(self.task_create_instant.elapsed());
    }
}

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// 设置客户端地址，将以上报 `X-Client-IP` / `X-Client-Port`。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 设置客户端用户名，将以上报 `X-Client-Username` / `X-Authenticated-User`。
    pub fn set_client_username(&mut self, user: ArcStr) {
        self.client_username = Some(user);
    }

    /* added by wming for repid audit */
    /// 设置连接五元组，将以上报 `X-Proxy-IP` / `X-Proxy-PORT` /
    /// `X-Remote-IP` / `X-Remote-PORT` / `X-Proto-P`。
    pub fn set_connection_tuple(&mut self, tuple: ConnectionTuple) {
        self.connection_tuple = Some(tuple);
    }

    /// 设置 TLS keylog 缓冲区，将以上报 `X-TLS-*` 系列头（含逐条 keylog）。
    pub fn set_keylog_buffer(&mut self, buffer: Arc<TlsKeyLogBuffer>) {
        self.keylog_buffer = Some(buffer);
    }

    /// 追加 ICAP 扩展头（写进 ICAP 请求头区，位于 `Encapsulated` 之前）。
    ///
    /// 与 h1 版的差异：这里声明的是 `X-Transformed-From: HTTP/2.0`，
    /// 且当 h2 流带 `:protocol` pseudo-header（RFC 8441 extended CONNECT，
    /// h2 crate 以 `Protocol` 扩展形式挂在 `Extensions` 上）时，
    /// 额外用 `X-HTTP-Upgrade` 告知 ICAP 被升级的协议名（如 `websocket`）。
    ///
    /// `extensions` 仅在"只报头"路径（`xfer_without_body` / `xfer_connect`）
    /// 传入；带 body 的上报路径传 `None`，因为此时请求已被 body 流走开过。
    fn push_extended_headers(&self, data: &mut Vec<u8>, extensions: Option<&Extensions>) {
        data.put_slice(b"X-Transformed-From: HTTP/2.0\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(user) = &self.client_username {
            crate::serialize::add_client_username(data, user);
        }
        // :protocol pseudo-header —— h2 扩展 CONNECT（websocket over h2）才会带
        if let Some(ext) = extensions
            && let Some(p) = ext.get::<Protocol>()
        {
            data.put_slice(b"X-HTTP-Upgrade: ");
            data.put_slice(p.as_str().as_bytes());
            data.put_slice(b"\r\n");
        }
        /* added by wming for repid audit */
        // 五元组：X-Proxy-IP/PORT、X-Remote-IP/PORT、X-Proto-P
        if let Some(ref tuple) = self.connection_tuple {
            crate::serialize::add_connection_tuple(data, tuple);
        }
        // TLS keylog：X-TLS-VERSION / X-TLS-CIPHER / X-TLS-SERVER_RANDOM / X-TLS-KeyLog
        if let Some(ref keylog) = self.keylog_buffer {
            crate::serialize::add_keylog_headers(data, keylog);
        }
    }

    /// 本服务生效的 preview 字节数；返回 `None` 表示不做 preview
    /// （配置禁用，或服务 OPTIONS 未声明 `Preview` 值）。
    fn preview_size(&self) -> Option<usize> {
        if self.icap_client.config.disable_preview {
            return None;
        }
        self.icap_options.preview_size
    }

    /// 上报入口：根据 body 是否存在、是否启用 preview，派发到三条路径之一。
    ///
    /// - body 已结束（`clt_body.is_end_stream()`，h2 端无需读数据帧）→ 只报头；
    /// - 有 preview 上限 → 先发预览头 + 一段体，等 ICAP 决策（可能回 100-continue）；
    /// - 否则 → 全量（无 preview）边转发边等 ICAP 响应。
    ///
    /// `clt_body` 为客户端 h2 流的接收端，`ups_send_request` 为向上游 h2
    /// 连接发起新流的发送句柄。
    pub async fn xfer(
        self,
        state: &mut ReqmodAdaptationRunState,
        http_request: Request<()>,
        clt_body: RecvStream,
        ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        if clt_body.is_end_stream() {
            // 请求无 body：走 header-only 上报（Encapsulated 用 null-body 偏移）
            self.xfer_without_body(state, http_request, ups_send_request)
                .await
        } else if let Some(preview_size) = self.preview_size() {
            self.xfer_with_preview(
                state,
                http_request,
                clt_body,
                ups_send_request,
                preview_size,
            )
            .await
        } else {
            self.xfer_without_preview(state, http_request, clt_body, ups_send_request)
                .await
        }
    }
}

/// 一次 REQMOD 上报的最终结果。
pub enum ReqmodAdaptationEndState {
    /// ICAP 未改写（如 204）：请求原样发给上游，返回上游的 h2 响应。
    OriginalTransferred(Response<RecvStream>),
    /// ICAP 改写了请求：按 `HttpAdaptedRequest`（h1 形式的改写头）发给上游，
    /// 返回上游的 h2 响应。
    AdaptedTransferred(HttpAdaptedRequest, Response<RecvStream>),
    /// ICAP 直接返回 HTTP 响应（拦截/拒绝页），无需访问上游；
    /// 第二项为"响应带 body"时的续读句柄（chunked，需调用方取完）。
    HttpErrResponse(HttpAdapterErrorResponse, Option<ReqmodRecvHttpResponseBody>),
}

/// "只报头"（含 CONNECT）路径的中间结果：尚未发送上游请求，由调用方继续处理。
pub enum ReqmodAdaptationMidState {
    /// ICAP 未改写，原请求可继续（CONNECT 隧道场景）。
    OriginalRequest(Request<()>),
    /// ICAP 改写了请求：第一项为改写后的 h1 形式头，第二项为转回 h2 的请求。
    AdaptedRequest(HttpAdaptedRequest, Request<()>),
    /// ICAP 返回 HTTP 错误响应，调用方直接回复客户端。
    HttpErrResponse(HttpAdapterErrorResponse, Option<ReqmodRecvHttpResponseBody>),
}

/// ICAP 返回的 HTTP 响应"剩余 body"的续读句柄。
///
/// 响应头已由 `HttpAdapterErrorResponse::parse` 读完，body 仍是 ICAP
/// 连接上的 chunked 流，故必须配合 h2 发送端（`SendStream`）才能取完；
/// 读完后按 keep-alive 决定归还或丢弃 ICAP 连接。
pub struct ReqmodRecvHttpResponseBody {
    icap_client: Arc<IcapServiceClient>,
    icap_keepalive: bool,
    icap_connection: IcapClientConnection,
    copy_config: StreamCopyConfig,
    http_body_line_max_size: usize,
    http_trailer_max_size: usize,
}

impl ReqmodRecvHttpResponseBody {
    /// 把 ICAP 连接上剩余的 chunked body 解码为 h2 数据帧写入 `send_stream`。
    ///
    /// 即"chunked 重编码的逆过程"：按 `ICAP 的 chunked 分块`读取，
    /// 受 `http_body_line_max_size` / `http_trailer_max_size` 限制，
    /// 结束时的 h2 trailer 一并转给 `send_stream`。
    pub fn body_transfer<'a>(
        &'a mut self,
        send_stream: &'a mut SendStream<Bytes>,
    ) -> H2StreamFromChunkedTransfer<'a, IcapClientReader> {
        H2StreamFromChunkedTransfer::new(
            &mut self.icap_connection.reader,
            send_stream,
            &self.copy_config,
            self.http_body_line_max_size,
            self.http_trailer_max_size,
        )
    }

    /// 读完（或放弃）body 后收尾：标记 ICAP 读端已用尽，
    /// 仅当 ICAP 声明 keep-alive 时才把连接放回连接池，否则丢弃。
    pub async fn save_connection(mut self) {
        self.icap_connection.mark_reader_finished();
        if self.icap_keepalive {
            self.icap_client.save_connection(self.icap_connection);
        }
    }
}
