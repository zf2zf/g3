/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1 CONNECT 方法隧道建立的拦截检测。
//!
//! [`H1ConnectTask`] 负责把客户端的 CONNECT 请求原样（或经 ICAP reqmod 改写后）
//! 发给上游，解析 2xx 响应判定隧道是否建立成功：成功则返回权威目标地址
//! `UpstreamAddr`，由上层把流交给逐流检测状态机；失败（鉴权 407、被阻断等）
//! 则回复客户端错误并视情况关闭连接。非 2xx 响应若有响应体则透传回客户端。

use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_http::client::HttpTransparentResponse;
use g3_http::server::{HttpTransparentRequest, UriExt};
use g3_http::{HttpBodyReader, HttpBodyType};
use g3_icap_client::reqmod::IcapReqmodClient;
use g3_icap_client::reqmod::h1::{
    H1ReqmodAdaptationError, HttpAdapterErrorResponse, HttpRequestAdapter,
    ReqmodAdaptationMidState, ReqmodAdaptationRunState, ReqmodRecvHttpResponseBody,
};
use g3_io_ext::{LimitedWriteExt, StreamCopy, StreamCopyError};
use g3_slog_types::{LtDateTime, LtDuration, LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use super::{HttpRequest, HttpRequestIo, HttpResponseIo};
use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext, StreamInspection};
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::{ServerIdleChecker, ServerTaskError, ServerTaskResult};

// CONNECT 转发任务的审计日志宏：附带请求 ID、下一跳上游、各阶段耗时等字段。
macro_rules! intercept_log {
    ($obj:tt, $r:expr, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "HttpConnect",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "request_id" => $obj.req_id,
                "next_upstream" => $r.as_ref().map(LtUpstreamAddr),
                "received_at" => LtDateTime(&$obj.http_notes.receive_datetime),
                "rsp_status" => $obj.http_notes.rsp_status,
                "origin_status" => $obj.http_notes.origin_status,
                "dur_req_send_hdr" => LtDuration($obj.http_notes.dur_req_send_hdr),
                "dur_req_pipeline" => LtDuration($obj.http_notes.dur_req_pipeline),
                "dur_rsp_recv_hdr" => LtDuration($obj.http_notes.dur_rsp_recv_hdr),
            );
        }
    };
}

/// CONNECT 请求各阶段的状态码与耗时快照，用于拦截审计日志。
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

/// HTTP/1 CONNECT 隧道建立任务：处理单个 CONNECT 请求直到隧道就绪或失败。
pub(super) struct H1ConnectTask<SC: ServerConfig> {
    ctx: StreamInspectContext<SC>,
    req: HttpTransparentRequest,
    req_id: usize,
    // 是否还可以向客户端发送错误响应；一旦响应头已经写出（含错误响应）即置 false
    send_error_response: bool,
    // 本次交互后连接是否必须关闭（keep-alive 失效、错误已回复等）
    should_close: bool,
    http_notes: HttpForwardTaskNotes,
}

impl<SC> H1ConnectTask<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建 CONNECT 隧道任务；审计快照以请求到达时刻为基准初始化。
    pub(super) fn new(ctx: StreamInspectContext<SC>, req: HttpRequest, req_id: usize) -> Self {
        let http_notes = HttpForwardTaskNotes::new(req.datetime_received, req.time_received);
        H1ConnectTask {
            ctx,
            req: req.inner,
            req_id,
            send_error_response: true,
            should_close: false,
            http_notes,
        }
    }

    /// 上层据此决定是否关闭整条客户端连接
    #[inline]
    pub(super) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 把任务错误尽量映射为 HTTP 错误响应回给客户端；
    /// 响应本身要求关闭或写失败时更新 [`Self::should_close`]。
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

    /// 经 ICAP reqmod 送检后建立 CONNECT 隧道。
    /// 返回 `Some(UpstreamAddr)` 表示隧道建立成功（收到 2xx）；`None` 表示失败，
    /// 此时若尚未向客户端写出任何响应，会先回复错误。
    pub(super) async fn forward_icap<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        reqmod_client: &IcapReqmodClient,
    ) -> Option<UpstreamAddr>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match self.do_forward(rsp_io, reqmod_client).await {
            Ok(v) => {
                intercept_log!(self, &v, "ok");
                v
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, &None, "{e}");
                None
            }
        }
    }

    /// 不经 ICAP、原样转发 CONNECT 请求建立隧道。
    /// 返回值语义同 [`Self::forward_icap`]。
    pub(super) async fn forward_original<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> Option<UpstreamAddr>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match self.send_request(None, rsp_io).await {
            Ok(v) => {
                intercept_log!(self, &v, "ok");
                v
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, &None, "{e}");
                None
            }
        }
    }

    /// ICAP 路径的内部实现：创建 reqmod H1 adapter 并注入客户端地址/用户名等
    /// 上下文后执行送检转发；adapter 创建失败时，若配置了 bypass 则降级为
    /// 原样转发，否则直接报错。
    async fn do_forward<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        reqmod_client: &IcapReqmodClient,
    ) -> ServerTaskResult<Option<UpstreamAddr>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
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

    /// 执行 CONNECT 请求的 ICAP 送检并按中间状态分派：
    /// 原样转发 / 转发改写后的请求 / 直接返回适配器的错误响应（阻断）。
    async fn forward_with_adaptation<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        icap_adapter: HttpRequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> ServerTaskResult<Option<UpstreamAddr>>
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
    /// 该函数总是以 should_close=true 结束本连接：响应头写出后即禁止再发
    /// 代理层错误响应（send_error_response=false），错误响应体若存在则
    /// 经 ICAP 连接流式拷贝后归还连接池。
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

    /// 把 CONNECT 请求头（原样或经 ICAP 改写的 `adapted_req`）写向上游，
    /// 随后接收并处理响应。CONNECT 请求无请求体，只需发送头部。
    async fn send_request<CW, UR, UW>(
        &mut self,
        adapted_req: Option<HttpTransparentRequest>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<UpstreamAddr>>
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
    ) -> ServerTaskResult<Option<UpstreamAddr>>
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

    /// 把上游响应头原样写回客户端，并判定 CONNECT 隧道结果：
    /// 2xx（200..300）表示隧道打通，返回从请求 URI 解析出的权威目标
    /// `UpstreamAddr`（缺省端口按 443）；其它状态码则把可选的响应体透传
    /// 回客户端并返回 `None`（隧道未建立）。
    async fn send_response<CW, UR, UW>(
        &mut self,
        rsp: HttpTransparentResponse,
        rsp_head: Bytes,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<Option<UpstreamAddr>>
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

        if rsp.code >= 200 && rsp.code < 300 {
            let upstream = self
                .req
                .uri
                .get_upstream_with_default_port(443)
                .map_err(ServerTaskError::from)?;
            Ok(Some(upstream))
        } else if let Some(body_type) = rsp.body_type(&self.req.method) {
            self.send_response_body(rsp_io, body_type).await?;
            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// 隧道建立失败时（如代理认证 407），把上游响应体拷贝给客户端。
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

    /// 隧道建立成功后，把四个裸 IO 交给逐流检测对象 `StreamInspectObject`，
    /// 在权威目标 `upstream` 上继续做源站内容检测。
    pub(super) fn into_connect(
        self,
        req_io: HttpRequestIo<BoxAsyncRead>,
        rsp_io: HttpResponseIo<BoxAsyncWrite, BoxAsyncRead, BoxAsyncWrite>,
        upstream: UpstreamAddr,
    ) -> StreamInspection<SC> {
        let (clt_r, clt_w, ups_r, ups_w) = super::convert_io(req_io, rsp_io);

        let mut stream_obj = crate::inspect::stream::StreamInspectObject::new(self.ctx, upstream);
        stream_obj.set_io(clt_r, clt_w, ups_r, ups_w);
        StreamInspection::StreamInspect(stream_obj)
    }
}
