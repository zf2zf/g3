/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD over HTTP/2：把后端（ups）的 h2 响应上报给 ICAP 服务器，
//! 并将 ICAP 返回的改写响应转回 h2 发送给前端客户端。
//!
//! 与 `respmod::h1` 版对称，主要差异：
//! - 封装进 ICAP 报文的"HTTP 响应报文"不是原始 TCP 字节流，而是由 h2
//!   响应头（`http::Response`）通过 `serialize_for_adapter()` 降级
//!   序列化成 HTTP/1.1 形式的头部文本；
//! - body 来自 h2 `RecvStream` 数据帧，转发给 ICAP 时按 chunked
//!   传输编码重新分块（`H2StreamToChunkedTransfer`）；ICAP 改写的响应
//!   同样以 chunked 返回，再解码回 h2 数据帧发给客户端
//!   （`H2StreamFromChunkedTransfer`）。
//!
//! 同样支持 preview + 100-continue、双向流（边发 body 边收 ICAP 响应）、
//! 以及 idle 超时检查。扩展头除 `X-Transformed-From: HTTP/2.0` 外，
//! 还携带 X-Client-IP / X-Client-Port / X-Client-Username /
//! X-Authenticated-User 以及与请求侧共享的请求头。
//!
//! 文件分工：
//! - `forward_header.rs`：无 body 的响应（只上报头，`res-body`/`null-body` 偏移）；
//! - `forward_body.rs`：全量（无 preview）上报或小于 preview 上限的一次性上报；
//! - `preview.rs`：先只发一段预览体，等 ICAP 回 100-continue 再继续；
//! - `bidirectional.rs`：上行 body 转发与下行 ICAP 响应接收并发进行的
//!   双向流处理；
//! - `recv_response.rs`：收到 ICAP 最终响应后，把原始/改写后的响应
//!   发给 h2 客户端的各收尾分支；
//! - `impl_trait.rs`：为 h2 server 侧的 `SendResponse` /
//!   `SendPushedResponse` 实现统一的发送抽象 [`H2SendResponseToClient`]；
//! - `error.rs`：本模块统一错误类型 [`H2RespmodAdaptationError`]。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes};
use h2::{RecvStream, SendStream};
use http::{Request, Response};
use tokio::time::Instant;

use g3_http::client::HttpAdaptedResponse;
use g3_io_ext::{IdleCheck, StreamCopyConfig};
use g3_types::net::HttpHeaderMap;

use super::IcapRespmodClient;
use crate::{IcapClientConnection, IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::H2RespmodAdaptationError;

mod bidirectional;
use bidirectional::{BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse};

mod recv_response;

mod forward_body;
mod forward_header;
mod preview;

mod impl_trait;

/// 向 h2 客户端发送最终响应的统一抽象。
///
/// 抽象出来是为了让适配流程既能对接普通响应（`h2::server::SendResponse`），
/// 也能对接服务器推送响应（`SendPushedResponse`），二者都通过降级/升级后
/// 的响应头返回一个可写 body 的 `SendStream<Bytes>`。
pub trait H2SendResponseToClient {
    /// 发送响应头；`end_of_stream` 为 true 表示这是不带 body 的空响应。
    fn send_response(
        &mut self,
        response: Response<()>,
        end_of_stream: bool,
    ) -> Result<SendStream<Bytes>, h2::Error>;
}

impl IcapRespmodClient {
    /// 为一次 h2 响应适配创建一个 [`H2ResponseAdapter`]。
    ///
    /// 从连接池取出一条 ICAP 连接（并附带该服务的 OPTIONS 结果，
    /// 如 preview 上限、是否允许 204），后续由调用方填充客户端地址、
    /// 用户名等扩展信息后调用 `xfer()` 完成上报与改写。
    pub async fn h2_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        http_body_line_max_size: usize,
        http_trailer_max_size: usize,
        idle_checker: I,
    ) -> anyhow::Result<H2ResponseAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(H2ResponseAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            http_body_line_max_size,
            http_trailer_max_size,
            idle_checker,
            client_addr: None,
            client_username: None,
            respond_shared_headers: None,
        })
    }
}

/// 一次 RESPMOD h2 适配所需的全部配置与 ICAP 连接的持有者。
///
/// 生命周期：由 [`IcapRespmodClient::h2_adapter`] 创建，可选地通过
/// `set_*` 方法补充扩展头信息，最后调用 [`H2ResponseAdapter::xfer`]
/// 消费自身，完成"上报响应 -> 接收 ICAP 结果 -> 发给客户端"全流程。
pub struct H2ResponseAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    http_body_line_max_size: usize,
    http_trailer_max_size: usize,
    idle_checker: I,
    client_addr: Option<SocketAddr>,
    client_username: Option<String>,
    respond_shared_headers: Option<HttpHeaderMap>,
}

/// 适配任务的运行时刻统计/状态，由上层（如 proxy task）创建并传入，
/// 用于记录"上游收头/收全、下游发头/发全"等关键时间点（相对任务创建时刻）。
pub struct RespmodAdaptationRunState {
    task_create_instant: Instant,
    dur_ups_recv_header: Duration,
    /// 上游（h2 后端）body 全部接收完毕的耗时；无 body 时等于收头耗时
    pub dur_ups_recv_all: Option<Duration>,
    /// 已向 h2 客户端发送完响应头的耗时
    pub dur_clt_send_header: Option<Duration>,
    /// 已向 h2 客户端发送完全部数据的耗时
    pub dur_clt_send_all: Option<Duration>,
    /// 是否已开始向客户端写出
    pub clt_write_started: bool,
}

impl RespmodAdaptationRunState {
    /// 以任务创建时刻与"上游收头耗时"初始化；其余时间点稍后由各
    /// `mark_*` 方法填写。
    pub fn new(task_create_instant: Instant, dur_ups_recv_header: Duration) -> Self {
        RespmodAdaptationRunState {
            task_create_instant,
            dur_ups_recv_header,
            dur_ups_recv_all: None,
            dur_clt_send_header: None,
            dur_clt_send_all: None,
            clt_write_started: false,
        }
    }

    /// 上游响应没有 body：收全时间直接等于收头时间。
    pub(crate) fn mark_ups_recv_no_body(&mut self) {
        self.dur_ups_recv_all = Some(self.dur_ups_recv_header);
    }

    /// 记录上游 body（含 trailer）全部接收的时刻。
    pub(crate) fn mark_ups_recv_all(&mut self) {
        self.dur_ups_recv_all = Some(self.task_create_instant.elapsed());
    }

    /// 标记开始向客户端写出（用于上层判断是否已产生副作用、能否回退）。
    pub(crate) fn mark_clt_send_start(&mut self) {
        self.clt_write_started = true;
    }

    /// 记录响应头发送完成的时刻。
    pub(crate) fn mark_clt_send_header(&mut self) {
        self.dur_clt_send_header = Some(self.task_create_instant.elapsed());
    }

    /// 客户端侧无 body：发全时间等于发头时间。
    pub(crate) fn mark_clt_send_no_body(&mut self) {
        self.dur_clt_send_all = self.dur_clt_send_header;
    }

    /// 记录向客户端发送完全部数据的时刻。
    pub(crate) fn mark_clt_send_all(&mut self) {
        self.dur_clt_send_all = Some(self.task_create_instant.elapsed());
    }
}

impl<I: IdleCheck> H2ResponseAdapter<I> {
    /// 设置客户端地址，将以 X-Client-IP / X-Client-Port 扩展头发给 ICAP。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 设置已认证用户名，将以 X-Client-Username / X-Authenticated-User
    /// 扩展头发给 ICAP。
    pub fn set_client_username(&mut self, user: &str) {
        self.client_username = Some(user.to_string());
    }

    /// 设置需与请求侧共享给 ICAP 的请求头（如请求阶段的改写结果）。
    pub fn set_respond_shared_headers(&mut self, shared_headers: Option<HttpHeaderMap>) {
        self.respond_shared_headers = shared_headers;
    }

    /// 在 ICAP 头中追加本适配的扩展头：固定的 X-Transformed-From，
    /// 以及可选的客户端地址、用户名和共享请求头。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        // h2 上报时降级为 HTTP/1.1 语法，故用该头告知 ICAP 原始协议版本
        data.put_slice(b"X-Transformed-From: HTTP/2.0\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(user) = &self.client_username {
            crate::serialize::add_client_username(data, user);
        }
        if let Some(map) = &self.respond_shared_headers {
            crate::serialize::add_shared(data, map);
        }
    }

    /// 返回本次适配应使用的 preview 字节上限；
    /// 客户端配置禁用 preview 或服务器未声明时返回 `None`（走全量上报）。
    fn preview_size(&self) -> Option<usize> {
        if self.icap_client.config.disable_preview {
            return None;
        }
        self.icap_options.preview_size
    }

    /// RESPMOD 适配总入口：把 h2 后端响应（头 + `ups_body` 数据流）上报给
    /// ICAP，并把结果通过 `clt_send_response` 发给 h2 客户端。
    ///
    /// 按 body 情况三分支选择具体流程：
    /// - 上游已无 body（`is_end_stream()`）：只报头（forward_header）；
    /// - 允许 preview：先报预览体等 100-continue（preview）；
    /// - 否则：全量双向流上报（forward_body）。
    pub async fn xfer<CW>(
        self,
        state: &mut RespmodAdaptationRunState,
        http_request: &Request<()>,
        http_response: Response<()>,
        ups_body: RecvStream,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        if ups_body.is_end_stream() {
            state.mark_ups_recv_no_body();
            self.xfer_without_body(state, http_request, http_response, clt_send_response)
                .await
        } else if let Some(preview_size) = self.preview_size() {
            self.xfer_with_preview(
                state,
                http_request,
                http_response,
                ups_body,
                clt_send_response,
                preview_size,
            )
            .await
        } else {
            self.xfer_without_preview(
                state,
                http_request,
                http_response,
                ups_body,
                clt_send_response,
            )
            .await
        }
    }
}

/// 适配结束状态：ICAP 是否改写了响应。
pub enum RespmodAdaptationEndState {
    /// ICAP 返回 204（或未改写），原样透传了上游响应。
    OriginalTransferred,
    /// ICAP 返回了改写的 HTTP 响应并已发给客户端；
    /// 携带解析出的适配后响应头，供上层记录/进一步处理。
    AdaptedTransferred(HttpAdaptedResponse),
}
