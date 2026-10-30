/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 响应的 RESPMOD 上报适配器（状态机入口与公共类型）。
//!
//! 本文件是整个 `respmod::h1` 的"总装车间"：定义对外入口 [`HttpResponseAdapter`]、
//! 各子文件共用的类型（运行状态 [`RespmodAdaptationRunState`]、结局
//! [`RespmodAdaptationEndState`]、错误类型 [`H1RespmodAdaptationError`]），以及两个
//! 适配 trait（[`HttpResponseForAdaptation`] / [`HttpResponseClientWriter`]）。
//! 真正的收发流程分散在同目录的其他文件里，通过多个 `impl` 块拼回同一个类型。
//!
//! 与 `reqmod::h1` 完全对称，但方向相反：REQMOD 封装的是"客户端发来的 HTTP 请求"，
//! 改写结果要交给上游；RESPMOD 封装的是"上游返回给客户端的 HTTP 响应"，改写结果要
//! 交给客户端。因此本模块同时持有三个 I/O 端点：
//! - `ups_body_io`：上游响应 body 的读取端（已读过响应头，只剩 body）；
//! - `icap_connection`：ICAP 服务器连接（读 ICAP 响应 / 写上报请求）；
//! - `clt_writer`：面向客户端的写出端。
//! 另外还额外接收原始的 HTTP 请求 [`HttpRequestForAdaptation`]，因为 RFC 3507 允许
//! RESPMOD 请求把"请求头 + 响应头/响应体"一起封装（本实现始终带上 req-hdr=0）。
//!
//! 上报线格式（见 `build_*_request` 系列函数）：
//! ```text
//! RESPMOD <icap-uri> ICAP/1.0          ← 由 IcapServiceClient 预生成的前缀
//! Host / User-Agent / Authorization     ← 同上
//! X-Transformed-From: HTTP/1.0          ← 固定声明被封装报文的版本
//! X-Client-IP / X-Client-Port           ← 可选，客户端地址
//! X-Client-Username / X-Authenticated-User ← 可选，用户名
//! <命中 respond_shared_names 的共享请求头> ← 可选，与 REQMOD 侧联动
//! Allow: 204                            ← 仅"只报头"分支且服务端支持时
//! Encapsulated: req-hdr=0, res-hdr=<请求头长度>, res-body|null-body=<请求头长度+响应头长度>
//! Preview: <n>                          ← 仅 preview 分支
//! <空行>
//! <HTTP 请求头字节><HTTP 响应头字节><chunked 重编码的响应 body>
//! ```
//!
//! ICAP 响应处理策略：
//! - 204（无 Encapsulated 载荷）→ 原样把上游响应转给客户端；
//! - 200 + `Encapsulated: res-hdr=.., res-body|null-body=..` → 按 ICAP 改写后的
//!   响应转发（响应头来自 ICAP，body 从 ICAP 的 chunked 流解码后写给客户端）；
//! - preview 模式下先只报一段预览体，等 ICAP 回 100 (Continue) 再续传剩余 body，
//!   收发两侧用 `tokio::select!` 做双向流水线；
//! - 206（ICAP 只改写部分）本库不支持，直接返回
//!   [`H1RespmodAdaptationError::NotImplemented`]。
//! 所有读写循环都受 [`g3_io_ext::IdleCheck`] 空闲保护，超时即按"卡在哪个方向"
//! 返回对应的 Idle 错误。
//!
//! 文件分工：
//! | 文件 | 承担的状态机分支 |
//! | --- | --- |
//! | [`preview`] | 带 `Preview: N` 的预检流程（100 / 204 / 200 分支，含分块预览读取） |
//! | [`forward_header`] | 响应无 body 时只上报头，`Encapsulated` 用 `null-body` |
//! | [`forward_body`] | 无 preview 的全量上报；body 已读完的小 body 一次性上报 |
//! | [`bidirectional`] | 与 ICAP 双向流水线：一边续传剩余 body，一边读 ICAP 响应 |
//! | [`recv_response`] | 收到 ICAP 最终响应后，把原始/改写响应发给客户端的各收尾分支 |
//! | [`impl_trait`] | 为 g3-http 的 h1 响应类型实现 [`HttpResponseForAdaptation`]，并给出 [`HttpResponseClientWriter`] 的通用实现 |
//! | [`error`] | 本模块统一错误类型 [`H1RespmodAdaptationError`] |

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arcstr::ArcStr;
use bytes::BufMut;
use http::Method;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::time::Instant;

use g3_http::HttpBodyType;
use g3_http::client::HttpAdaptedResponse;
use g3_io_ext::{IdleCheck, StreamCopyConfig};
use g3_types::net::HttpHeaderMap;

use super::IcapRespmodClient;
use crate::reqmod::h1::HttpRequestForAdaptation;
use crate::{IcapClientConnection, IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::H1RespmodAdaptationError;

mod bidirectional;
use bidirectional::{BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse};

mod recv_response;

mod forward_body;
mod forward_header;
mod preview;

mod impl_trait;

/// 待适配（上报/转发）的 HTTP/1.1 响应：由调用方（代理层）实现的抽象。
///
/// 之所以要把"响应"抽象成 trait，是因为 ICAP 客户端并不知道上层用的是哪种
/// h1 响应表示（透明转发 `HttpTransparentResponse` 还是自研远程响应
/// `HttpForwardRemoteResponse`，见 `impl_trait.rs`）。RESPMOD 流程只依赖四种能力：
/// 判断有没有 body、序列化成"给客户端的字节"、序列化成"给 ICAP 的字节"、
/// 以及用 ICAP 返回的改写头替换原头。
pub trait HttpResponseForAdaptation {
    /// 按请求方法判定响应 body 的传输方式；返回 `None` 表示该响应不允许带 body
    /// （如 HEAD 响应、1xx/204/304），此时走"只报头"分支
    /// [`HttpResponseAdapter::xfer_without_body`]。
    fn body_type(&self, method: &Method) -> Option<HttpBodyType>;

    /// 序列化成最终发给客户端的响应头字节（状态行 + 头 + 空行）。
    fn serialize_for_client(&self) -> Vec<u8>;

    /// 序列化成封装进 ICAP 报文的响应头字节。
    ///
    /// 与 `serialize_for_client` 的区别：只输出端到端（end-to-end）头，逐跳头
    /// （`Connection`、`Transfer-Encoding` 等）会被剔除；封装体被视为 HTTP/1.0
    /// 报文（对应固定发送的 `X-Transformed-From: HTTP/1.0`），其后的 body 由本模块
    /// 在 ICAP 层重新按 chunked 分块，所以这里保留的 Content-Length 仅供参考。
    fn serialize_for_adapter(&self) -> Vec<u8>;

    /// 用 ICAP 改写后的响应（头 + 有 body）替换原响应，返回新的可发送响应。
    fn adapt_with_body(&self, other: HttpAdaptedResponse) -> Self;

    /// 用 ICAP 改写后的响应（仅头，无 body）替换原响应，返回新的可发送响应。
    fn adapt_without_body(&self, other: HttpAdaptedResponse) -> Self;
}

/// 面向客户端写出响应头的通道：由调用方（代理层）实现。
///
/// 任何 `AsyncWrite` 都可以通过 `impl_trait.rs` 里的泛型实现获得该能力，
/// 单独定义 trait 是为了让"发送响应头"这一步可以被上层重载（例如需要先补
/// chunked 分帧或需要更新统计信息）。
#[allow(async_fn_in_trait)]
pub trait HttpResponseClientWriter<H: HttpResponseForAdaptation>: AsyncWrite {
    /// 把（可能被 ICAP 改写过的）响应头写给客户端。注意 body 由后续拷贝循环发送。
    async fn send_response_header(&mut self, req: &H) -> io::Result<()>;
}

impl IcapRespmodClient {
    /// 为一次 RESPMOD 适配创建 [`HttpResponseAdapter`]。
    ///
    /// 会先从连接池取一条 ICAP 连接（若池空则现场新建），并连带取回该服务的
    /// OPTIONS 能力信息（`preview_size`、`support_204` 等），用于决定走 preview
    /// 还是全量分支。
    ///
    /// - `copy_config`：body 拷贝的分块大小/限速配置；
    /// - `http_body_line_max_size`：解析 chunked 分块大小时单行的长度上限；
    /// - `idle_checker`：空闲保护，长时间无任何进展即中止并返回 Idle 类错误。
    pub async fn h1_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        http_body_line_max_size: usize,
        idle_checker: I,
    ) -> anyhow::Result<HttpResponseAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(HttpResponseAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            http_body_line_max_size,
            idle_checker,
            client_addr: None,
            client_username: None,
            respond_shared_headers: None,
        })
    }
}

/// 一次 RESPMOD 适配的全部状态：ICAP 连接 + 上报所需的可选信息。
///
/// 采用"消耗式"使用：`xfer()` 以 `self`（而非 `&mut self`）接收，一次适配走完后
/// 对象即失效，ICAP 连接要么归还连接池（keep-alive），要么随对象一起丢弃。
pub struct HttpResponseAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    /// OPTIONS 请求得到的服务能力：`preview_size`（是否支持预览及预览上限）、
    /// `support_204`（是否允许 ICAP 用 204 表示"不改写"）。
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    /// 解析 chunked 分块行（以及 trailer 行）时的单行长度上限。
    http_body_line_max_size: usize,
    idle_checker: I,
    /// 可选扩展头 X-Client-IP / X-Client-Port 的来源。
    client_addr: Option<SocketAddr>,
    /// 可选扩展头 X-Client-Username / X-Authenticated-User 的来源。
    client_username: Option<ArcStr>,
    /// 与 REQMOD 侧联动的共享头（命中 respond_shared_names 的请求头），原样附加。
    respond_shared_headers: Option<HttpHeaderMap>,
}

/// RESPMOD 适配过程的耗时/进度打点，由调用方创建并传入 [`HttpResponseAdapter::xfer`]。
///
/// 语义上四个阶段依次为：上游响应头已收到（构造时给出）→ 上游 body 读完
/// (`dur_ups_recv_all`) → 客户端收到响应头 (`dur_clt_send_header`) → 客户端收到
/// 完整 body (`dur_clt_send_all`)。日志与统计据此计算各方向时延。
pub struct RespmodAdaptationRunState {
    task_create_instant: Instant,
    dur_ups_recv_header: Duration,
    pub dur_ups_recv_all: Option<Duration>,
    pub dur_clt_send_header: Option<Duration>,
    pub dur_clt_send_all: Option<Duration>,
    pub ups_read_finished: bool,
    pub clt_write_started: bool,
    pub clt_write_finished: bool,
}

impl RespmodAdaptationRunState {
    /// 以"上游响应头刚收完"的时刻创建打点状态。
    ///
    /// - `task_create_instant`：本次适配任务的起点，后续所有耗时都相对它计算；
    /// - `dur_ups_recv_header`：从任务起点到响应头收完已消耗的时长。
    pub fn new(task_create_instant: Instant, dur_ups_recv_header: Duration) -> Self {
        RespmodAdaptationRunState {
            task_create_instant,
            dur_ups_recv_header,
            dur_ups_recv_all: None,
            dur_clt_send_header: None,
            dur_clt_send_all: None,
            ups_read_finished: false,
            clt_write_started: false,
            clt_write_finished: false,
        }
    }

    /// 无 body 场景：上游读取在"收到头"时即已完成，故直接复用心跳值。
    pub(crate) fn mark_ups_recv_no_body(&mut self) {
        self.dur_ups_recv_all = Some(self.dur_ups_recv_header);
        self.ups_read_finished = true;
    }

    /// 上游响应 body 全部读完（含 trailer）。
    pub(crate) fn mark_ups_recv_all(&mut self) {
        self.dur_ups_recv_all = Some(self.task_create_instant.elapsed());
        self.ups_read_finished = true;
    }

    /// 即将向客户端写出响应头。
    pub(crate) fn mark_clt_send_start(&mut self) {
        self.clt_write_started = true;
    }

    /// 响应头已写入客户端（body 尚未写完）。
    pub(crate) fn mark_clt_send_header(&mut self) {
        self.dur_clt_send_header = Some(self.task_create_instant.elapsed());
    }

    /// 无 body 场景：写完头即等于写完全部内容。
    pub(crate) fn mark_clt_send_no_body(&mut self) {
        self.dur_clt_send_all = self.dur_clt_send_header;
        self.clt_write_finished = true;
    }

    /// 响应体也已全部写入客户端。
    pub(crate) fn mark_clt_send_all(&mut self) {
        self.dur_clt_send_all = Some(self.task_create_instant.elapsed());
        self.clt_write_finished = true;
    }
}

impl<I: IdleCheck> HttpResponseAdapter<I> {
    /// 设置客户端地址，用于生成 X-Client-IP / X-Client-Port 扩展头。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 设置已认证用户名，用于生成 X-Client-Username / X-Authenticated-User 扩展头。
    pub fn set_client_username(&mut self, user: ArcStr) {
        self.client_username = Some(user);
    }

    /// 设置与 REQMOD 侧共享的请求头（命中 respond_shared_names 的部分），随响应一起上报。
    pub fn set_respond_shared_headers(&mut self, shared_headers: Option<HttpHeaderMap>) {
        self.respond_shared_headers = shared_headers;
    }

    /// 追加各分支共用的扩展头。
    ///
    /// 顺序固定：先 `X-Transformed-From: HTTP/1.0`（声明被封装报文版本），再按需
    /// 追加客户端地址、用户名与共享请求头；`Allow` / `Encapsulated` / `Preview`
    /// 因各分支不同，交由调用方自行补齐。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"X-Transformed-From: HTTP/1.0\r\n");
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

    /// 计算本次可用的 preview 大小：配置禁用或服务端未通告时为 `None`，
    /// 此时改走"全量上报"分支。
    fn preview_size(&self) -> Option<usize> {
        if self.icap_client.config.disable_preview {
            return None;
        }
        self.icap_options.preview_size
    }

    /// RESPMOD 适配总入口：按"有无 body / 有无 preview"分派到三条分支之一。
    ///
    /// - 响应有 body 且可用 preview → `xfer_with_preview`（先报预览体，等 100-continue）；
    /// - 响应有 body 但不可用 preview → `xfer_without_preview`（全量上报，双向流水线）；
    /// - 响应无 body（HEAD / 1xx / 204 / 304）→ `xfer_without_body`（只报头，
    ///   `Encapsulated` 使用 `null-body` 偏移）。
    ///
    /// 无论走哪条分支，返回的都是 [`RespmodAdaptationEndState`]，调用方据此决定
    /// 是否需要保留原响应对象（例如连接复用统计）。
    pub async fn xfer<R, H, UR, CW>(
        self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        ups_body_io: &mut UR,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        UR: AsyncBufRead + Unpin,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        // body_type 为 None 表示该响应按 RFC 7231 不允许携带 body
        if let Some(body_type) = http_response.body_type(http_request.method()) {
            if let Some(preview_size) = self.preview_size() {
                self.xfer_with_preview(
                    state,
                    http_request,
                    http_response,
                    body_type,
                    ups_body_io,
                    clt_writer,
                    preview_size,
                )
                .await
            } else {
                self.xfer_without_preview(
                    state,
                    http_request,
                    http_response,
                    body_type,
                    ups_body_io,
                    clt_writer,
                )
                .await
            }
        } else {
            state.mark_ups_recv_no_body();
            self.xfer_without_body(state, http_request, http_response, clt_writer)
                .await
        }
    }
}

/// 一次 RESPMOD 适配的最终结局。
///
/// - `OriginalTransferred`：ICAP 返回 204（或只报头分支被认可不改写），
///   上游原响应已完整转发给客户端；
/// - `AdaptedTransferred(H)`：ICAP 返回 200 并附带改写后的响应头，
///   新响应对象被回传，便于调用方继续做日志/缓存记录。
pub enum RespmodAdaptationEndState<H: HttpResponseForAdaptation> {
    OriginalTransferred,
    AdaptedTransferred(H),
}
