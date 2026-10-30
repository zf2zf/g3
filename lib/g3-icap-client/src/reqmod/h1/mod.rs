/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 请求的 REQMOD 上报适配器（状态机入口与公共类型）。
//!
//! 本文件是整个 `reqmod::h1` 的"总装车间"：定义对外入口 [`HttpRequestAdapter`]、
//! 各子文件共用的类型（运行状态、结束/中间状态、错误响应体句柄），以及两个适配
//! trait（[`HttpRequestForAdaptation`] / [`HttpRequestUpstreamWriter`]）。
//! 真正的收发流程分散在同目录的其他文件里，通过多个 `impl` 块拼回同一个类型：
//!
//! | 文件 | 承担的状态机分支 |
//! | --- | --- |
//! | preview.rs | 带 `Preview: N` 的预检流程（100 / 204 / 200 分支） |
//! | forward_header.rs | 无 body（或 CONNECT）时只上报请求头，`null-body` |
//! | forward_body.rs | 无 preview 时全量上报；body 已读完的小 body 一次性上报 |
//! | bidirectional.rs | 与 ICAP 双向流水线：一边续传剩余 body，一边读 ICAP 响应 |
//! | recv_request.rs | 处理 ICAP 返回的"改写后 HTTP 请求" |
//! | recv_response.rs | 处理 ICAP 返回的"替代 HTTP 响应"（直接回客户端） |
//! | impl_trait.rs | 为 g3-http 的 h1 请求类型实现 [`HttpRequestForAdaptation`] |
//!
//! 一次 `xfer()` 调用的主干（详见 `reqmod/mod.rs` 的决策表）：
//! 序列化请求头 → 按"有无 body / 有无 preview"分派 → 发送 REQMOD →
//! 解析响应码与 `Encapsulated` → 三种结局之一
//! （原样转发 / 转发改写后的请求 / 用 ICAP 的响应直接回复客户端）。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arcstr::ArcStr;
use bytes::BufMut;
use http::Method;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::time::Instant;

use g3_http::server::HttpAdaptedRequest;
use g3_http::{HttpBodyReader, HttpBodyType};
use g3_io_ext::{IdleCheck, StreamCopyConfig};
use g3_types::net::HttpHeaderMap;
use g3_types::net::TlsKeyLogBuffer;

use super::{ConnectionTuple, IcapReqmodClient};
use crate::{IcapClientConnection, IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::H1ReqmodAdaptationError;

mod bidirectional;
use bidirectional::{BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse};

mod recv_request;
mod recv_response;

mod http_response;
pub use http_response::HttpAdapterErrorResponse;

mod forward_body;
mod forward_header;
mod preview;

mod impl_trait;

/// 被适配的 HTTP/1.1 请求需要提供的能力（由 impl_trait.rs 为 g3-http 类型实现）。
///
/// ICAP 侧只关心"字节"，因此各协议类型只要能把请求头序列化出来、并且能用
/// ICAP 返回的报文重建自身，就可以接入本适配器。
pub trait HttpRequestForAdaptation {
    /// 请求方法。适配器据此判断是否为 CONNECT 等特殊情况。
    fn method(&self) -> &Method;

    /// 请求 body 的类型：`None` 表示没有 body，否则为 chunked / 定长 / 读到结束。
    ///
    /// 这是 xfer() 分派的第一层依据（无 body 走 forward_header.rs 的 null-body 分支）。
    fn body_type(&self) -> Option<HttpBodyType>;

    /// 序列化成要封装进 ICAP 报文的 HTTP 头字节（请求行 + 头部 + 空行）。
    ///
    /// 返回长度即 `Encapsulated: req-hdr=0, req-body=<len>` 中的偏移量：
    /// req-hdr 从封装内容起点算作 0，body 紧随其后，所以偏移恰为头部字节数。
    /// 注意此处序列化的是"原始请求头"，扩展头（X-Transformed-From 等）写在
    /// ICAP 自己的头部里，不参与这个偏移计算。
    fn serialize_for_adapter(&self) -> Vec<u8>;

    /// 把 hop-by-hop 的 `Upgrade:` 头改写成 `X-HTTP-Upgrade:` 追加到 ICAP 头部。
    ///
    /// hop-by-hop 头不能直接进入封装报文（会被 ICAP 当作自身连接的控制头丢掉），
    /// 因此只在 null-body 上报时以 X- 前缀的扩展头形式透传给 ICAP 服务。
    fn append_upgrade_header(&self, buf: &mut Vec<u8>);

    /// 用 ICAP 返回的（含 body 的）改写请求重建一个自身类型的请求。
    fn adapt_with_body(&self, other: HttpAdaptedRequest) -> Self;
    /// 用 ICAP 返回的（不含 body 的）改写请求重建一个自身类型的请求。
    fn adapt_without_body(&self, other: HttpAdaptedRequest) -> Self;
}

/// 上游（真实 HTTP 服务器）写入端需要实现的能力：把请求头字节写出去。
///
/// 之所以要求 `AsyncWrite`，是因为 body 的续传／拷贝直接用 tokio 的流式写；
/// 而请求头需要按各协议自己的方式（含必要的前后处理）单独发送一次。
#[allow(async_fn_in_trait)]
pub trait HttpRequestUpstreamWriter<H: HttpRequestForAdaptation>: AsyncWrite {
    /// 向真实上游发送（可能是改写后的）HTTP/1.1 请求头。
    async fn send_request_header(&mut self, req: &H) -> io::Result<()>;
}

impl IcapReqmodClient {
    /// 为一次 HTTP/1.1 请求建立 REQMOD 适配器：从连接池取一条 ICAP 连接。
    ///
    /// `copy_config` 控制 body 拷贝的窗口/限速；`http_body_line_max_size` 限制
    /// chunked 分块头行的最大长度（防放大攻击）；`http_req_add_no_via_header`
    /// 决定是否在转发改写请求时补 `Via`/`No-Via` 相关头；
    /// `idle_checker` 为所有读／拷贝循环提供空闲超时与强制退出（force_quit）能力。
    pub async fn h1_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        http_body_line_max_size: usize,
        http_req_add_no_via_header: bool,
        idle_checker: I,
    ) -> anyhow::Result<HttpRequestAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(HttpRequestAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            http_body_line_max_size,
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

/// REQMOD HTTP/1.1 适配器：持有独占的 ICAP 连接与本次上报所需的全部配置。
///
/// 生命周期为"一次请求"：所有 xfer* 方法都 `self` 消耗自身，流程结束时按
/// ICAP 的 `Keep-Alive` 情况决定连接是归还连接池还是丢弃（各分支里成对的
/// `mark_writer_finished()` / `mark_reader_finished()` 就是在为归还做准备——
/// 只有收发两侧都确认读干净了，连接才能安全复用）。
pub struct HttpRequestAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    http_body_line_max_size: usize,
    http_req_add_no_via_header: bool,
    idle_checker: I,
    client_addr: Option<SocketAddr>,
    client_username: Option<ArcStr>,
    /* added by wming for repid audit */
    connection_tuple: Option<ConnectionTuple>,
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

/// 一次上报任务的运行状态（由调用方持有，用于打点与观察进度）。
///
/// 调用方可在超时/失败时依据 `clt_read_finished` / `ups_write_finished`
/// 判断"能不能安全重试"：客户端 body 还没读完就不能把请求原样重发。
pub struct ReqmodAdaptationRunState {
    task_create_instant: Instant,
    /// 头写完（发给上游）耗时。
    pub dur_ups_send_header: Option<Duration>,
    /// 全部（头 + body）写完耗时。
    pub dur_ups_send_all: Option<Duration>,
    /// 是否已把客户端 body 读完。
    pub clt_read_finished: bool,
    /// 是否已把内容全部写给上游。
    pub ups_write_finished: bool,
    /// ICAP 通过共享头回传的数据（内部填充，由调用方取走）。
    pub(crate) respond_shared_headers: Option<HttpHeaderMap>,
}

impl ReqmodAdaptationRunState {
    /// 新建运行状态，`task_create_instant` 作为所有耗时的起点。
    pub fn new(task_create_instant: Instant) -> Self {
        ReqmodAdaptationRunState {
            task_create_instant,
            dur_ups_send_header: None,
            dur_ups_send_all: None,
            clt_read_finished: false,
            ups_write_finished: false,
            respond_shared_headers: None,
        }
    }

    /// 取走（并清空）ICAP 回传的共享头，供代理写入会话/审计信息。
    pub fn take_respond_shared_headers(&mut self) -> Option<HttpHeaderMap> {
        self.respond_shared_headers.take()
    }

    pub(crate) fn mark_ups_send_header(&mut self) {
        self.dur_ups_send_header = Some(self.task_create_instant.elapsed());
    }

    /// 无 body 的情形：写完头即视为全部发送完成，两个耗时打点取同一值。
    pub(crate) fn mark_ups_send_no_body(&mut self) {
        self.dur_ups_send_all = self.dur_ups_send_header;
        self.ups_write_finished = true;
    }

    pub(crate) fn mark_ups_send_all(&mut self) {
        self.dur_ups_send_all = Some(self.task_create_instant.elapsed());
        self.ups_write_finished = true;
    }
}

impl<I: IdleCheck> HttpRequestAdapter<I> {
    /// 设置客户端地址，会以 `X-Client-IP` / `X-Client-Port` 扩展头上报。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 设置认证用户名，会以 `X-Client-Username` / `X-Authenticated-User`(base64) 上报。
    pub fn set_client_username(&mut self, user: ArcStr) {
        self.client_username = Some(user);
    }

    /* added by wming for repid audit */
    /// 设置连接五元组，会以 `X-Proxy-IP` / `X-Remote-IP` / `X-Proto-P` 上报（本机审计扩展）。
    pub fn set_connection_tuple(&mut self, tuple: ConnectionTuple) {
        self.connection_tuple = Some(tuple);
    }

    /// 设置 TLS keylog 缓冲区，会以 `X-TLS-*` 系列扩展头上报，供 ICAP 侧解密审计。
    pub fn set_keylog_buffer(&mut self, buffer: Arc<TlsKeyLogBuffer>) {
        self.keylog_buffer = Some(buffer);
    }

    /// 追加本适配器统一的扩展头。
    ///
    /// `X-Transformed-From: HTTP/1.0` 是 RFC 3507 对封装请求来源协议的声明；
    /// 其余均为 g3 自有扩展（客户端地址、用户名、五元组、TLS keylog），
    /// 未设置的项直接跳过，因此同一个适配器也能服务于不便提供这些信息的路径。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"X-Transformed-From: HTTP/1.0\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(user) = &self.client_username {
            crate::serialize::add_client_username(data, user);
        }
        /* added by wming for repid audit */
        if let Some(ref tuple) = self.connection_tuple {
            crate::serialize::add_connection_tuple(data, tuple);
        }
        if let Some(ref keylog) = self.keylog_buffer {
            crate::serialize::add_keylog_headers(data, keylog);
        }
    }

    /// 本次上报是否使用 Preview 预检，以及预检的字节数。
    ///
    /// 优先级：客户端配置 `disable_preview` 一律关闭（有些 ICAP 服务对
    /// Preview 支持不佳）；否则使用 OPTIONS 协商回来的 `Preview:` 值。
    /// 返回 `None` 表示不走 preview，即全量上报。
    fn preview_size(&self) -> Option<usize> {
        if self.icap_client.config.disable_preview {
            return None;
        }
        self.icap_options.preview_size
    }

    /// 对外唯一入口：把一次 HTTP/1.1 请求上报给 ICAP 并完成转发。
    ///
    /// 三层分派：
    /// 1. `body_type()` 为 `None` → 无 body，只上报头（xfer_without_body）；
    /// 2. 有 body 且协商到 preview → 预检流程（xfer_with_preview）；
    /// 3. 有 body 但无 preview → 全量流式上报（xfer_without_preview）。
    ///
    /// `clt_body_io` 是客户端连接的剩余字节流；若 `body_type()` 非 `None` 却没
    /// 传 io，属于调用方用法错误，直接返回内部错误而不是 panic。
    pub async fn xfer<H, CR, UW>(
        self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        clt_body_io: Option<&mut CR>,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        CR: AsyncBufRead + Unpin,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        if let Some(body_type) = http_request.body_type() {
            let Some(clt_body_io) = clt_body_io else {
                return Err(H1ReqmodAdaptationError::InternalServerError(
                    "no client http body io supplied while body type is not none",
                ));
            };
            if let Some(preview_size) = self.preview_size() {
                self.xfer_with_preview(
                    state,
                    http_request,
                    body_type,
                    clt_body_io,
                    ups_writer,
                    preview_size,
                )
                .await
            } else {
                self.xfer_without_preview(state, http_request, body_type, clt_body_io, ups_writer)
                    .await
            }
        } else {
            // 无 body：客户端侧天然"已读完"，调用方可安全整体重试
            state.clt_read_finished = true;
            self.xfer_without_body(state, http_request, ups_writer)
                .await
        }
    }
}

/// 上报流程的终态：三种结局之一，调用方据此决定后续动作。
pub enum ReqmodAdaptationEndState<H: HttpRequestForAdaptation> {
    /// ICAP 放行（204 等）：原始请求已按原样完整发给上游。
    OriginalTransferred,
    /// ICAP 改写了请求：改写后的请求已发给上游。
    AdaptedTransferred(H),
    /// ICAP 返回替代响应：应直接回给客户端、不再访问上游。
    /// 第二个字段是尚未读完的响应体句柄（body 为 chunked，需流式取用）。
    HttpErrResponse(HttpAdapterErrorResponse, Option<ReqmodRecvHttpResponseBody>),
}

/// 上报流程的中间态：只完成"决定/重建"，转发由调用方继续（CONNECT 场景）。
pub enum ReqmodAdaptationMidState<H: HttpRequestForAdaptation> {
    /// 原请求放行，调用方按自己的方式继续连接上游（CONNECT 隧道）。
    OriginalRequest,
    /// 请求被改写，调用方用新请求继续。
    AdaptedRequest(H),
    /// ICAP 直接给出替代响应。
    HttpErrResponse(HttpAdapterErrorResponse, Option<ReqmodRecvHttpResponseBody>),
}

/// ICAP 替代响应中"尚未读完的 body"句柄，把 ICAP 连接的读半端交给调用方继续消费。
///
/// 因为响应可能是 200 + chunked body，此时 ICAP 连接上还有未读数据，
/// 既不能立即归还连接池，也不能丢弃；调用方读完后再调 save_connection。
pub struct ReqmodRecvHttpResponseBody {
    icap_client: Arc<IcapServiceClient>,
    icap_keepalive: bool,
    icap_connection: IcapClientConnection,
}

impl ReqmodRecvHttpResponseBody {
    /// 以 chunked 方式读取 ICAP 连接上剩余的响应体。
    ///
    /// ICAP 侧封装的 HTTP 响应体固定按 chunked 传输编码组织，因此这里不需要
    /// 再判断 Content-Length；1024 是读缓冲区大小。
    pub fn body_reader(&mut self) -> HttpBodyReader<'_, impl AsyncBufRead + use<>> {
        HttpBodyReader::new_chunked(&mut self.icap_connection.reader, 1024)
    }

    /// body 读完后归还连接：仅当 ICAP 声明 Keep-Alive 且读侧确实干净时才复用，
    /// 否则连接被丢弃，避免残留数据污染下一个请求。
    pub async fn save_connection(mut self) {
        if self.icap_keepalive {
            self.icap_connection.mark_reader_finished();
            self.icap_client.save_connection(self.icap_connection);
        }
    }
}
