/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 Upgrade 协议切换请求的拦截检测。
//!
//! [`H1UpgradeTask`] 处理带 Upgrade 头的请求：先按检测策略过滤/阻断不允许的
//! 切换协议（如 WebSocket 可按域名阻断、Connect-IP 一律拒绝），再把请求（可选
//! 经 ICAP reqmod 改写）发给上游；收到 101 Switching Protocols 后解析实际切换
//! 目标，返回 (协议, 权威目标) 供主循环创建下一层检测状态机（H2/WebSocket/未知流）。
//! 非 101 响应则按普通应答透传后继续在 HTTP/1 状态机内处理。

use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{StatusCode, Version};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_dpi::Protocol;
use g3_http::client::HttpTransparentResponse;
use g3_http::server::{HttpTransparentRequest, UriExt};
use g3_http::{HttpBodyReader, HttpBodyType};
use g3_icap_client::reqmod::IcapReqmodClient;
use g3_icap_client::reqmod::h1::{
    H1ReqmodAdaptationError, HttpAdapterErrorResponse, HttpRequestAdapter,
    ReqmodAdaptationMidState, ReqmodAdaptationRunState, ReqmodRecvHttpResponseBody,
};
use g3_io_ext::{LimitedWriteExt, OnceBufReader, StreamCopy, StreamCopyError};
use g3_slog_types::{LtDateTime, LtDuration, LtHttpUri, LtUpstreamAddr, LtUuid};
use std::sync::Arc;

use g3_types::net::{HttpUpgradeToken, TlsKeyLogBuffer, UpstreamAddr, WebSocketNotes};

use super::{H1InterceptionError, HttpRequest, HttpRequestIo, HttpResponseIo};
use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamInspection};
use crate::log::inspect::InspectSource;
use crate::log::inspect::stream::StreamInspectLog;
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::{ServerIdleChecker, ServerTaskError, ServerTaskResult};

// Upgrade 任务审计日志宏：附带切换后的下一协议、下一跳上游与各阶段耗时。
macro_rules! intercept_log {
    ($obj:tt, $r:expr, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "HttpUpgrade",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "request_id" => $obj.req_id,
                "next_protocol" => $r.as_ref().map(|v| v.0.to_string()),
                "next_upstream" => $r.as_ref().map(|v| LtUpstreamAddr(&v.1)),
                "received_at" => LtDateTime(&$obj.http_notes.receive_datetime),
                "uri" => LtHttpUri::new(&$obj.req.uri, $obj.ctx.log_uri_max_chars()),
                "rsp_status" => $obj.http_notes.rsp_status,
                "origin_status" => $obj.http_notes.origin_status,
                "dur_req_send_hdr" => LtDuration($obj.http_notes.dur_req_send_hdr),
                "dur_req_pipeline" => LtDuration($obj.http_notes.dur_req_pipeline),
                "dur_rsp_recv_hdr" => LtDuration($obj.http_notes.dur_rsp_recv_hdr),
            );
        }
    };
}

/// Upgrade 请求各阶段的状态码与耗时快照，用于拦截审计日志。
/// 未发生的阶段保持 0/Duration::default()。
struct HttpForwardTaskNotes {
    rsp_status: u16,
    origin_status: u16,
    receive_ins: Instant,
    receive_datetime: DateTime<Utc>,
    dur_req_send_hdr: Duration,
    dur_req_pipeline: Duration,
    dur_rsp_recv_hdr: Duration,
}

impl HttpForwardTaskNotes {
    /// 以请求到达时刻为基准创建快照；`dur_req_pipeline` 即请求在流水线
    /// channel 中排队等待被主循环取出的时间。
    fn new(datetime_received: DateTime<Utc>, time_received: Instant) -> Self {
        let dur_req_pipeline = time_received.elapsed();
        HttpForwardTaskNotes {
            rsp_status: 0,
            origin_status: 0,
            receive_ins: time_received,
            receive_datetime: datetime_received,
            dur_req_send_hdr: Duration::default(),
            dur_req_pipeline,
            dur_rsp_recv_hdr: Duration::default(),
        }
    }

    /// 记录"请求头已发出"距到达时刻的耗时
    fn mark_ups_send_header(&mut self) {
        self.dur_req_send_hdr = self.receive_ins.elapsed();
    }

    /// 记录"上游响应头已收到"距到达时刻的耗时
    pub(crate) fn mark_rsp_recv_hdr(&mut self) {
        self.dur_rsp_recv_hdr = self.receive_ins.elapsed();
    }
}

/// Upgrade 协议切换任务：处理单个带 Upgrade 头的请求直到 101 完成切换或失败。
pub(super) struct H1UpgradeTask<SC: ServerConfig> {
    ctx: StreamInspectContext<SC>,
    req: HttpTransparentRequest,
    req_id: usize,
    // 是否还可以向客户端发送错误响应；响应头一旦写出即置 false
    send_error_response: bool,
    // 本次交互后连接是否必须关闭
    should_close: bool,
    http_notes: HttpForwardTaskNotes,
    // 切换到 WebSocket 时收集请求/响应两侧头部，供 WebSocket 检测层记录审计
    ws_notes: Option<WebSocketNotes>,
    // TLS keylog 缓冲，供 ICAP 送检时导出会话密钥
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC> H1UpgradeTask<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建协议切换任务；keylog_buffer 用于 ICAP 送检时导出 TLS 会话密钥。
    pub(super) fn new(
        ctx: StreamInspectContext<SC>,
        req: HttpRequest,
        req_id: usize,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        let http_notes = HttpForwardTaskNotes::new(req.datetime_received, req.time_received);
        H1UpgradeTask {
            ctx,
            req: req.inner,
            req_id,
            send_error_response: true,
            should_close: false,
            http_notes,
            ws_notes: None,
            keylog_buffer,
        }
    }

    /// 上层据此决定是否关闭整条客户端连接
    #[inline]
    pub(super) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 把任务错误尽量映射为 HTTP 错误响应回给客户端；
    /// 响应要求关闭或写失败时更新 [`Self::should_close`]。
    async fn reply_task_err<CW>(&mut self, e: &ServerTaskError, clt_w: &mut CW)
    where
        CW: AsyncWrite + Unpin,
    {
        let rsp = HttpProxyClientResponse::from_task_err(e, self.req.version, self.should_close);

        if let Some(rsp) = rsp {
            if rsp.should_close() {
                self.should_close = true;
            }

            if rsp.reply_err_to_request(clt_w).await.is_err() {
                self.should_close = true;
            } else {
                self.http_notes.rsp_status = rsp.status();
            }
        }
    }

    /// 直接以指定的致命响应（403/400）终结本请求：必定关闭连接。
    /// 用于检测策略阻断或请求本身不合法（缺 Upgrade 头）的场景。
    async fn reply_fatal<CW>(&mut self, rsp: HttpProxyClientResponse, clt_w: &mut CW)
    where
        CW: AsyncWrite + Unpin,
    {
        self.should_close = true;
        if rsp.reply_err_to_request(clt_w).await.is_ok() {
            self.http_notes.rsp_status = rsp.status();
        }
    }

    /// 按检测策略过滤 Upgrade 头中的协议令牌：
    /// - WebSocket：查询该 Host 的 websocket 检测动作，被阻断则剔除；
    /// - Connect-Ip（extended connect 携带客户端 IP 的变体）：一律剔除；
    /// - 其它令牌：保留透传。
    /// 返回值：None 表示请求根本没有 Upgrade 头（400 终结）；Some(0) 表示所有
    /// 令牌都被剔除（403 终结）；Some(n>0) 表示仍有可切换协议，放行。
    async fn check_blocked<CW>(&mut self, clt_w: &mut CW) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
    {
        match self.req.retain_upgrade_token(|req, p| {
            if matches!(p, HttpUpgradeToken::Websocket) {
                let Some(http_host) = &req.host else {
                    return false;
                };
                return !self
                    .ctx
                    .websocket_inspect_action(http_host.host())
                    .is_block();
            } else if matches!(p, HttpUpgradeToken::ConnectIp) {
                return false;
            }
            true
        }) {
            Some(0) => {
                self.reply_fatal(HttpProxyClientResponse::forbidden(self.req.version), clt_w)
                    .await;
                Err(ServerTaskError::InternalAdapterError(anyhow!(
                    "upgrade protocol blocked by inspection policy"
                )))
            }
            Some(_) => Ok(()),
            None => {
                self.reply_fatal(
                    HttpProxyClientResponse::bad_request(self.req.version),
                    clt_w,
                )
                .await;
                Err(ServerTaskError::InternalAdapterError(anyhow!(
                    "no Upgrade header found in HTTP upgrade request"
                )))
            }
        }
    }

    /// 不经 ICAP、原样转发 Upgrade 请求。
    /// 返回 `Some((协议, 权威目标))` 表示收到 101 且切换成功；`None` 表示失败
    /// 或收到非 101 应答（此时已尽量透传响应），失败时视情况回复错误。
    pub(super) async fn forward_original<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> Option<(HttpUpgradeToken, UpstreamAddr)>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match self.do_forward_original(rsp_io).await {
            Ok(v) => {
                intercept_log!(self, &v, "ok");
                v
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, &None::<(HttpUpgradeToken, UpstreamAddr)>, "{e}");
                None
            }
        }
    }

    /// 原样路径的内部实现：先做协议阻断检查，再发送请求并处理响应。
    pub(super) async fn do_forward_original<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.check_blocked(&mut rsp_io.clt_w).await?;
        self.send_request(None, rsp_io).await
    }

    /// 经 ICAP reqmod 送检后转发 Upgrade 请求。返回值语义同 [`Self::forward_original`]。
    pub(super) async fn forward_icap<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        reqmod_client: &IcapReqmodClient,
    ) -> Option<(HttpUpgradeToken, UpstreamAddr)>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match self.do_forward_icap(rsp_io, reqmod_client).await {
            Ok(v) => {
                intercept_log!(self, &v, "ok");
                v
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, &None::<(HttpUpgradeToken, UpstreamAddr)>, "{e}");
                None
            }
        }
    }

    /// ICAP 路径的内部实现：阻断检查通过后创建 reqmod adapter 并送检转发；
    /// adapter 创建失败时，配置了 bypass 则降级为原样转发，否则直接报错。
    async fn do_forward_icap<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        reqmod_client: &IcapReqmodClient,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.check_blocked(&mut rsp_io.clt_w).await?;
        match reqmod_client
            .h1_adapter(
                self.ctx.server_config.limited_copy_config(),
                self.ctx.h1_interception().body_line_max_len,
                true,
                self.ctx.idle_checker(),
            )
            .await
        {
            Ok(mut adapter) => {
                adapter.set_client_addr(self.ctx.task_notes.client_addr);
                if let Some(username) = self.ctx.raw_user_name() {
                    adapter.set_client_username(username.clone());
                }
                let mut adaptation_state =
                    ReqmodAdaptationRunState::new(self.http_notes.receive_ins);
                self.forward_with_adaptation(rsp_io, adapter, &mut adaptation_state)
                    .await
            }
            Err(e) => {
                if reqmod_client.bypass() {
                    self.send_request(None, rsp_io).await
                } else {
                    Err(ServerTaskError::InternalAdapterError(e))
                }
            }
        }
    }

    /// 执行 Upgrade 请求的 ICAP 送检并按中间状态分派：
    /// 原样转发 / 转发改写后的请求 / 直接返回适配器的错误响应（阻断）。
    /// 复用 xfer_connect 通道：Upgrade 与 CONNECT 一样是无请求体的控制类请求。
    async fn forward_with_adaptation<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        icap_adapter: HttpRequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match icap_adapter.xfer_connect(adaptation_state, &self.req).await {
            Ok(ReqmodAdaptationMidState::OriginalRequest) => self.send_request(None, rsp_io).await,
            Ok(ReqmodAdaptationMidState::AdaptedRequest(final_req)) => {
                self.send_request(Some(final_req), rsp_io).await
            }
            Ok(ReqmodAdaptationMidState::HttpErrResponse(rsp, rsp_body)) => {
                self.send_adaptation_error_response(&mut rsp_io.clt_w, rsp, rsp_body)
                    .await?;
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 把 ICAP 适配器返回的错误响应（阻断页）透传给客户端。
    /// 响应头写出后即禁止再发代理层错误响应；错误响应体若存在则经 ICAP
    /// 连接流式拷贝后归还连接池。整个连接此后必须关闭。
    async fn send_adaptation_error_response<W>(
        &mut self,
        clt_w: &mut W,
        rsp: HttpAdapterErrorResponse,
        rsp_recv_body: Option<ReqmodRecvHttpResponseBody>,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.should_close = true;

        let buf = rsp.serialize(self.should_close);
        self.send_error_response = false;
        clt_w
            .write_all(buf.as_ref())
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        self.http_notes.rsp_status = rsp.status.as_u16();

        if let Some(mut recv_body) = rsp_recv_body {
            let mut body_reader = recv_body.body_reader();
            let copy_to_clt = StreamCopy::new(
                &mut body_reader,
                clt_w,
                &self.ctx.server_config.limited_copy_config(),
            );
            copy_to_clt.await.map_err(|e| match e {
                StreamCopyError::ReadFailed(e) => ServerTaskError::InternalAdapterError(anyhow!(
                    "read http error response from adapter failed: {e:?}"
                )),
                StreamCopyError::WriteFailed(e) => ServerTaskError::ClientTcpWriteFailed(e),
            })?;
            recv_body.save_connection().await;
        } else {
            clt_w
                .flush()
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        }

        Ok(())
    }

    /// 把 Upgrade 请求头（原样或经 ICAP 改写的 `adapted_req`）写向上游，
    /// 随后接收并处理响应。Upgrade 请求无请求体，只需发送头部。
    async fn send_request<CW, UR, UW>(
        &mut self,
        adapted_req: Option<HttpTransparentRequest>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let req = adapted_req.as_ref().unwrap_or(&self.req);
        let head_bytes = req.serialize_for_origin();
        rsp_io
            .ups_w
            .write_all_flush(&head_bytes)
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        self.http_notes.mark_ups_send_header();

        self.recv_response(rsp_io).await
    }

    /// 在配置的超时窗口内解析上游响应头，随后透传给客户端。
    /// 超时归因于上游应用层超时（`UpstreamAppTimeout`）。
    async fn recv_response<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(
            self.ctx.h1_rsp_hdr_recv_timeout(),
            HttpTransparentResponse::parse(
                &mut rsp_io.ups_r,
                &self.req.method,
                self.req.keep_alive(),
                self.ctx.h1_interception().rsp_head_max_size,
            ),
        )
        .await
        {
            Ok(Ok((rsp, head_bytes))) => self.send_response(rsp, head_bytes, rsp_io).await,
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ServerTaskError::UpstreamAppTimeout(
                "timeout to receive response header",
            )),
        }
    }

    /// 把上游响应头原样写回客户端，并判定协议切换结果：
    /// - 101 Switching Protocols：从响应 Upgrade 头取实际切换协议；WebSocket
    ///   需收集响应头到 ws_notes，Connect-Udp（extended CONNECT）从 :protocol
    ///   语义的 URI 解析目标；其余协议以 Host 头作为权威目标。缺 Upgrade 头的
    ///   101 或缺 Host 的目标解析都会终止（并关闭连接）。
    /// - 其它状态码：若有响应体则透传完毕后返回 None（切换未发生）。
    async fn send_response<CW, UR, UW>(
        &mut self,
        mut rsp: HttpTransparentResponse,
        rsp_head: Bytes,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<(HttpUpgradeToken, UpstreamAddr)>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.send_error_response = false;
        self.http_notes.origin_status = rsp.code;
        self.http_notes.mark_rsp_recv_hdr();
        if !rsp.keep_alive() {
            self.should_close = true;
        }

        rsp_io
            .clt_w
            .write_all(&rsp_head)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        self.http_notes.rsp_status = self.http_notes.origin_status;

        if rsp.code == StatusCode::SWITCHING_PROTOCOLS {
            // 101：切换成功，确定实际切换到的协议令牌
            let upgrade_protocol = match rsp.upgrade {
                Some(p) => p,
                None => {
                    // 101 却没有 Upgrade 头：协议定义冲突，必须断连
                    self.should_close = true;
                    return Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "no upgrade header found in 101 response"
                    )));
                }
            };

            match upgrade_protocol {
                HttpUpgradeToken::Websocket => {
                    // WebSocket：把响应侧头存入 ws_notes，目标稍后从 Host 解析
                    let mut ws_notes = WebSocketNotes::new(self.req.uri.clone());
                    ws_notes.append_response_headers(rsp.end_to_end_headers.drain());
                    self.ws_notes = Some(ws_notes);
                }
                HttpUpgradeToken::ConnectUdp => {
                    // extended CONNECT (RFC 8441)：权威目标由 :authority 伪等价信息解析
                    let upstream = self
                        .req
                        .uri
                        .get_connect_udp_upstream()
                        .map_err(ServerTaskError::from)?;
                    return Ok(Some((upgrade_protocol, upstream)));
                }
                _ => {}
            }

            // 其余协议（WebSocket、h2c 等）：请求的 Host 即权威目标地址
            let upstream = self
                .req
                .host
                .take()
                .ok_or(ServerTaskError::InvalidClientProtocol(
                    "no Host header found in http upgrade request",
                ))?;
            Ok(Some((upgrade_protocol, upstream)))
        } else if let Some(body_type) = rsp.body_type(&self.req.method) {
            // 非 101 且有响应体（如鉴权 407）：透传错误体后返回 None
            self.send_response_body(rsp_io, body_type).await?;
            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// 切换失败时把上游响应体拷贝给客户端。
    /// 拷贝循环中周期性检查：空闲计数超限（区分"读上游停滞"与"写客户端停滞"）、
    /// 用户被封禁、服务器强制退出——三类都会中断拷贝并返回对应错误。
    async fn send_response_body<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        body_type: HttpBodyType,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut body_reader = HttpBodyReader::new(
            &mut rsp_io.ups_r,
            body_type,
            self.ctx.h1_interception().body_line_max_len,
        );

        let mut ups_to_clt = StreamCopy::new(
            &mut body_reader,
            &mut rsp_io.clt_w,
            &self.ctx.server_config.limited_copy_config(),
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut ups_to_clt => {
                    return match r {
                        Ok(_) => {
                            // clt_w is already flushed（拷贝结束时客户端写端已 flush，无需再刷）
                            Ok(())
                        }
                        Err(StreamCopyError::ReadFailed(e)) => {
                            // 读失败也要把已缓冲的数据送达客户端再报错
                            let _ = ups_to_clt.write_flush().await;
                            Err(ServerTaskError::UpstreamReadFailed(e))
                        }
                        Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::ClientTcpWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if ups_to_clt.is_idle() {
                        idle_count += n;
                        if idle_count >= self.ctx.max_idle_count {
                            return if ups_to_clt.no_cached_data() {
                                // 上游不再吐数据：判定为上游空闲超时
                                Err(ServerTaskError::UpstreamAppTimeout("idle while reading response body"))
                            } else {
                                // 还有数据积压未写出：客户端消费不动，判定为客户端空闲超时
                                Err(ServerTaskError::ClientAppTimeout("idle while sending response body"))
                            };
                        }
                    } else {
                        idle_count = 0;
                        ups_to_clt.reset_active();
                    }

                    if self.ctx.belongs_to_blocked_user() {
                        let _ = ups_to_clt.write_flush().await;
                        return Err(ServerTaskError::CanceledAsUserBlocked);
                    }

                    if self.ctx.server_force_quit() {
                        let _ = ups_to_clt.write_flush().await;
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }

    /// 切换完成后构造下一层检测状态机：检测深度 +1，按切换协议分发——
    /// 升级到 HTTP/2 交给 H2 拦截对象；WebSocket 附带收集的双侧头部交给
    /// WebSocket 拦截对象；残留的 h2-over-TLS 或 tls ALPN 切换不受支持，报
    /// [`H1InterceptionError::InvalidUpgradeProtocol`]；其它未知协议按原始隧道流处理
    /// （如策略需要可在下游禁止）。
    pub(super) fn into_upgrade(
        mut self,
        req_io: HttpRequestIo<BoxAsyncRead>,
        rsp_io: HttpResponseIo<BoxAsyncWrite, BoxAsyncRead, BoxAsyncWrite>,
        protocol: HttpUpgradeToken,
        upstream: UpstreamAddr,
    ) -> Result<StreamInspection<SC>, H1InterceptionError> {
        let (clt_r, clt_w, ups_r, ups_w) = super::convert_io(req_io, rsp_io);

        let mut ctx = self.ctx;
        ctx.increase_inspection_depth();

        match protocol {
            HttpUpgradeToken::Http(Version::HTTP_2) => {
                StreamInspectLog::new(&ctx).log(InspectSource::HttpUpgrade, Protocol::Http2);
                let mut h2_obj = crate::inspect::http::H2InterceptObject::new(
                    ctx,
                    upstream,
                    self.keylog_buffer.clone(),
                );
                h2_obj.set_io(OnceBufReader::with_no_buf(clt_r), clt_w, ups_r, ups_w);
                Ok(StreamInspection::H2(h2_obj))
            }
            HttpUpgradeToken::Http(_) | HttpUpgradeToken::Tls(_, _) => {
                // 101 后切回 HTTP/1.x 或声明 TLS：本代理不支持作为下一层检测入口
                Err(H1InterceptionError::InvalidUpgradeProtocol(protocol))
            }
            HttpUpgradeToken::Websocket => {
                let mut ws_notes = self.ws_notes.unwrap();
                ws_notes.append_request_headers(self.req.end_to_end_headers.drain());
                StreamInspectLog::new(&ctx).log(InspectSource::HttpUpgrade, Protocol::Websocket);
                let mut websocket_obj = crate::inspect::websocket::H1WebsocketInterceptObject::new(
                    ctx, upstream, ws_notes,
                );
                websocket_obj.set_io(clt_r, clt_w, ups_r, ups_w);
                Ok(StreamInspection::Websocket(websocket_obj))
            }
            _ => {
                StreamInspectLog::new(&ctx).log(InspectSource::HttpUpgrade, Protocol::Unknown);
                let mut stream_obj =
                    crate::inspect::stream::StreamInspectObject::new(ctx, upstream);
                stream_obj.set_io(clt_r, clt_w, ups_r, ups_w);
                // Just treat it as unknown. Unknown protocol should be forbidden if needed.
                Ok(StreamInspection::StreamUnknown(stream_obj))
            }
        }
    }
}
