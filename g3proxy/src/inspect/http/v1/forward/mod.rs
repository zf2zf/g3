/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 普通方法（GET/POST 等）请求的转发拦截。
//!
//! [`H1ForwardTask`] 是检测流水线中处理单个非 CONNECT、非 Upgrade 请求的任务：
//! 将请求头（可选经 ICAP reqmod 改写、并携带请求体）转发到上游，接收响应头
//! （自动处理 100 Continue / 103 Early Hints 临时响应），响应头与响应体可再经
//! ICAP respmod 送检后回传客户端。全程记录各阶段耗时供拦截审计日志使用。

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use http::header;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_http::client::HttpTransparentResponse;
use g3_http::server::HttpTransparentRequest;
use g3_http::{HttpBodyReader, HttpBodyType};
use g3_icap_client::reqmod::h1::{
    HttpAdapterErrorResponse, HttpRequestAdapter, ReqmodAdaptationEndState,
    ReqmodAdaptationRunState, ReqmodRecvHttpResponseBody,
};
use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple, IcapReqmodClient};
use g3_icap_client::respmod::h1::{
    HttpResponseAdapter, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use g3_io_ext::{LimitedBufReadExt, LimitedWriteExt, StreamCopy, StreamCopyError};
use g3_slog_types::{LtDateTime, LtDuration, LtHttpHeaderValue, LtHttpMethod, LtHttpUri, LtUuid};
use g3_types::net::HttpHeaderMap;
use g3_types::net::TlsKeyLogBuffer;

use super::{HttpRequest, HttpRequestIo, HttpResponseIo};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::{ServerIdleChecker, ServerTaskError, ServerTaskResult};

mod adaptation;
pub(crate) use adaptation::HttpRequestWriterForAdaptation;

// 转发任务审计日志宏：附带方法、URI、Host、各阶段状态码与耗时。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "HttpForward",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "request_id" => $obj.req_id,
                "received_at" => LtDateTime(&$obj.http_notes.receive_datetime),
                "method" => LtHttpMethod(&$obj.req.method),
                "uri" => LtHttpUri::new(&$obj.req.uri, $obj.ctx.log_uri_max_chars()),
                "host" => $obj.req.end_to_end_headers.get(header::HOST).map(|v| LtHttpHeaderValue(v.inner())),
                "rsp_status" => $obj.http_notes.rsp_status,
                "origin_status" => $obj.http_notes.origin_status,
                "dur_req_send_hdr" => LtDuration($obj.http_notes.dur_req_send_hdr),
                "dur_req_pipeline" => LtDuration($obj.http_notes.dur_req_pipeline),
                "dur_req_send_all" => LtDuration($obj.http_notes.dur_req_send_all),
                "dur_rsp_recv_hdr" => LtDuration($obj.http_notes.dur_rsp_recv_hdr),
                "dur_rsp_recv_all" => LtDuration($obj.http_notes.dur_rsp_recv_all),
            );
        }
    };
}

/// 单个转发请求的状态码与各阶段耗时快照，用于拦截审计日志。
/// rsp_status 为客户端实际收到的状态码，origin_status 为上游返回的状态码，
/// 二者在响应经改写或尚未发出时会不同；未发生的阶段保持 0/默认值。
struct HttpForwardTaskNotes {
    rsp_status: u16,
    origin_status: u16,
    receive_ins: Instant,
    receive_datetime: DateTime<Utc>,
    dur_req_send_hdr: Duration,
    dur_req_pipeline: Duration,
    dur_req_send_all: Duration,
    dur_rsp_recv_hdr: Duration,
    dur_rsp_recv_all: Duration,
}

impl HttpForwardTaskNotes {
    /// 以请求到达时刻为基准创建快照；`dur_req_pipeline` 是请求在流水线
    /// channel 中排队等待主循环处理的时间。
    fn new(datetime_received: DateTime<Utc>, time_received: Instant) -> Self {
        let dur_req_pipeline = time_received.elapsed();
        HttpForwardTaskNotes {
            rsp_status: 0,
            origin_status: 0,
            receive_datetime: datetime_received,
            receive_ins: time_received,
            dur_req_send_hdr: Duration::default(),
            dur_req_pipeline,
            dur_req_send_all: Duration::default(),
            dur_rsp_recv_hdr: Duration::default(),
            dur_rsp_recv_all: Duration::default(),
        }
    }

    /// 记录请求头发送完成的耗时
    pub(crate) fn mark_req_send_hdr(&mut self) {
        self.dur_req_send_hdr = self.receive_ins.elapsed();
    }

    /// 无请求体的请求：发送全部耗时等于发送头部耗时
    pub(crate) fn mark_req_no_body(&mut self) {
        self.dur_req_send_all = self.dur_req_send_hdr;
    }

    /// 记录请求（头+体）全部发送完成的耗时
    pub(crate) fn mark_req_send_all(&mut self) {
        self.dur_req_send_all = self.receive_ins.elapsed();
    }

    /// 记录上游响应头接收完成的耗时
    pub(crate) fn mark_rsp_recv_hdr(&mut self) {
        self.dur_rsp_recv_hdr = self.receive_ins.elapsed();
    }

    /// 无响应体的应答：接收全部耗时等于接收头部耗时
    pub(crate) fn mark_rsp_no_body(&mut self) {
        self.dur_rsp_recv_all = self.dur_rsp_recv_hdr;
    }

    /// 记录响应（头+体）全部接收转发的耗时
    pub(crate) fn mark_rsp_recv_all(&mut self) {
        self.dur_rsp_recv_all = self.receive_ins.elapsed();
    }
}

/// HTTP/1 普通请求转发任务。req 以引用借用主循环持有的已解析请求，
/// 任务结束后请求仍归调用方所有。
pub(super) struct H1ForwardTask<'a, SC: ServerConfig> {
    ctx: StreamInspectContext<SC>,
    req: &'a HttpTransparentRequest,
    req_id: usize,
    // 是否还允许向客户端发送代理层错误响应；响应头一旦写出即置 false
    send_error_response: bool,
    // 本次交互后连接是否必须关闭
    should_close: bool,
    http_notes: HttpForwardTaskNotes,
    // TLS keylog 缓冲，供 ICAP 送检时导出会话密钥解密 HTTPS 流量
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<'a, SC: ServerConfig> H1ForwardTask<'a, SC> {
    /// 创建转发任务；请求不保持 keep-alive 时初始即要求关闭连接。
    pub(super) fn new(
        ctx: StreamInspectContext<SC>,
        req: &'a HttpRequest,
        req_id: usize,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        let http_notes = HttpForwardTaskNotes::new(req.datetime_received, req.time_received);
        let should_close = !req.inner.keep_alive();
        H1ForwardTask {
            ctx,
            req: &req.inner,
            req_id,
            send_error_response: true,
            should_close,
            http_notes,
            keylog_buffer,
        }
    }

    /// 上层据此决定是否关闭整条客户端连接
    #[inline]
    pub(super) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 把任务错误映射为 HTTP 错误响应回给客户端。
    /// 关键细节：若请求体尚未读完（body_pending），即使错误响应本身可复用连接，
    /// 残留的请求体会破坏下一个请求的解析，因此强制按关闭处理；
    /// 无法生成错误响应（如响应已部分发出）且有残留体时同样必须断开。
    async fn reply_task_err<CW>(&mut self, e: &ServerTaskError, clt_w: &mut CW)
    where
        CW: AsyncWrite + Unpin,
    {
        let body_pending = self.req.body_type().is_some();
        let rsp = HttpProxyClientResponse::from_task_err(
            e,
            self.req.version,
            self.should_close || body_pending,
        );

        if let Some(rsp) = rsp {
            if rsp.should_close() {
                self.should_close = true;
            }

            if rsp.reply_err_to_request(clt_w).await.is_err() {
                self.should_close = true;
            } else {
                self.http_notes.rsp_status = rsp.status();
            }
        } else if body_pending {
            self.should_close = true;
        }
    }

    /// 转发无请求体的请求（读端留在流水线解析任务中，不经本函数）。
    /// 失败时若仍允许发错误响应则回复客户端，最终一律打拦截日志，不向外抛错。
    pub(super) async fn forward_without_body<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) where
        CW: AsyncWrite + Send + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if let Err(e) = self.do_forward_without_body(rsp_io).await {
            if self.send_error_response {
                self.reply_task_err(&e, &mut rsp_io.clt_w).await;
            }
            intercept_log!(self, "{e}");
        } else {
            intercept_log!(self, "ok");
        }
    }

    /// 经 ICAP reqmod 送检并转发带请求体的请求。
    /// 流程：创建 adapter（注入客户端地址、用户名、连接五元组、TLS keylog）→
    /// 运行送检 → 用适配器的实测耗时回填审计字段；客户端数据未读完或上游
    /// 未写全时强制关闭连接（残留字节会破坏流水线上的下一个请求）。
    /// adapter 创建失败且配置了 bypass 时降级为普通转发。
    pub(super) async fn adapt_with_io<CR, CW, UR, UW>(
        &mut self,
        req_io: &mut HttpRequestIo<CR>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        reqmod_client: &IcapReqmodClient,
    ) where
        CR: AsyncRead + Send + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Send + Unpin,
    {
        let adapter = match reqmod_client
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
                /* added by wming for repid audit */
                // 注入真实连接五元组，便于 ICAP 服务端按会话做审计/改写决策
                let tuple = ConnectionTuple {
                    server_addr: self.ctx.connect_notes.client_addr,
                    remote_addr: self.ctx.connect_notes.server_addr,
                    protocol: ConnectionProtocol::Tcp,
                };
                adapter.set_connection_tuple(tuple);
                if let Some(ref keylog) = self.keylog_buffer {
                    adapter.set_keylog_buffer(keylog.clone());
                }

                adapter
            }
            Err(e) => {
                if reqmod_client.bypass() {
                    self.forward_with_io(req_io, rsp_io).await;
                } else {
                    let e = ServerTaskError::InternalAdapterError(e);
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                    intercept_log!(self, "{e:?}");
                }
                return;
            }
        };

        let mut adaptation_state = ReqmodAdaptationRunState::new(self.http_notes.receive_ins);
        let r = self
            .run_with_adaptation(req_io, rsp_io, adapter, &mut adaptation_state)
            .await;

        // 送检路径下请求头/体的实际发送耗时由适配器统计，回填到审计快照
        if let Some(dur) = adaptation_state.dur_ups_send_header {
            self.http_notes.dur_req_send_hdr = dur;
        }
        if let Some(dur) = adaptation_state.dur_ups_send_all {
            self.http_notes.dur_req_send_all = dur;
        }
        if !adaptation_state.clt_read_finished || !adaptation_state.ups_write_finished {
            self.should_close = true;
        }

        match r {
            Ok(_) => {
                intercept_log!(self, "ok");
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, "{e}");
            }
        }
    }

    /// 不经 ICAP 的普通转发入口：按请求是否带体选择实现路径，
    /// 错误时视情况回复客户端并记录拦截日志。
    pub(super) async fn forward_with_io<CR, CW, UR, UW>(
        &mut self,
        req_io: &mut HttpRequestIo<CR>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let r = if let Some(body_type) = self.req.body_type() {
            self.do_forward_with_body(req_io, rsp_io, body_type).await
        } else {
            self.do_forward_without_body(rsp_io).await
        };
        match r {
            Ok(_) => {
                intercept_log!(self, "ok");
            }
            Err(e) => {
                if self.send_error_response {
                    self.reply_task_err(&e, &mut rsp_io.clt_w).await;
                }
                intercept_log!(self, "{e}");
            }
        }
    }

    /// ICAP reqmod 送检的核心循环：并发执行"适配器搬运请求（客户端→ICAP→上游）"
    /// 与"探测上游响应"两路任务。
    /// 上游提前返回响应（常见于鉴权 401 或请求被拒）时：临时响应（100/103）直接
    /// 透传后继续等待；最终响应到达则提前 break——此时请求体可能未搬完，
    /// 之后据 clt_read_finished/ups_write_finished 决定是否断连。
    /// 适配器若返回错误响应（阻断），则直接把它回给客户端并结束。
    async fn run_with_adaptation<CR, CW, UR, UW>(
        &mut self,
        req_io: &mut HttpRequestIo<CR>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        icap_adapter: HttpRequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Send + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Send + Unpin,
    {
        let mut ups_w_adaptation = HttpRequestWriterForAdaptation {
            inner: &mut rsp_io.ups_w,
        };
        let mut adaptation_fut = icap_adapter
            .xfer(
                adaptation_state,
                self.req,
                Some(&mut req_io.clt_r),
                &mut ups_w_adaptation,
            )
            .boxed();

        let mut rsp_head: Option<(HttpTransparentResponse, Bytes)> = None;
        loop {
            tokio::select! {
                biased;

                r = rsp_io.ups_r.fill_wait_data() => {
                    match r {
                        Ok(true) => {
                            // we got some data from upstream（上游提前返回数据，开始解析响应头）
                            let (rsp, bytes) = self.recv_response_header(&mut rsp_io.ups_r).await?;
                            match rsp.code {
                                100 | 103 => {
                                    // CONTINUE | Early Hints：临时响应透传，继续等最终响应
                                    self.send_response_header(&mut rsp_io.clt_w, bytes).await?;
                                }
                                _ => {
                                    rsp_head = Some((rsp, bytes));
                                    break;
                                }
                            }
                        }
                        Ok(false) => return Err(ServerTaskError::ClosedByUpstream),
                        Err(e) => return Err(ServerTaskError::UpstreamReadFailed(e)),
                    }
                }
                r = &mut adaptation_fut => {
                    match r {
                        Ok(ReqmodAdaptationEndState::OriginalTransferred) => {
                            // 请求原样搬运完毕，等待上游最终响应
                            break;
                        }
                        Ok(ReqmodAdaptationEndState::AdaptedTransferred(_r)) => {
                            // TODO add log for adapted request?
                            break;
                        }
                        Ok(ReqmodAdaptationEndState::HttpErrResponse(rsp, rsp_recv_body)) => {
                            return self.send_adaptation_error_response(&mut rsp_io.clt_w, rsp, rsp_recv_body).await;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        drop(adaptation_fut);

        // 若循环因上游提前响应而退出，rsp_head 已备好；否则在这里带超时地
        // 等待最终响应头（跳过所有 100/103 临时响应）
        let rsp_head = match rsp_head {
            Some(header) => {
                if !adaptation_state.clt_read_finished || !adaptation_state.ups_write_finished {
                    // not all client data transferred, drop the connection
                    self.should_close = true;
                }
                header
            }
            None => {
                match tokio::time::timeout(
                    self.ctx.h1_rsp_hdr_recv_timeout(),
                    self.recv_final_response_header(rsp_io),
                )
                .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ServerTaskError::UpstreamAppTimeout(
                            "timeout to receive response header",
                        ));
                    }
                }
            }
        };

        self.send_response(
            rsp_head.0,
            rsp_head.1,
            rsp_io,
            // 把 reqmod 阶段 ICAP 附加的共享响应头带入 respmod 送检
            adaptation_state.take_respond_shared_headers(),
        )
        .await?;

        Ok(())
    }

    /// 把 ICAP 适配器返回的错误响应（阻断页）透传给客户端。
    /// 响应头写出后禁止再发代理层错误响应；错误响应体若存在则流式拷贝后
    /// 归还 ICAP 连接到连接池。整个连接此后必须关闭。
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

    /// 序列化请求头（面向源站的透明转发形式）并写入上游，随后打点。
    async fn send_request_header<UW>(&mut self, ups_w: &mut UW) -> ServerTaskResult<()>
    where
        UW: AsyncWrite + Unpin,
    {
        let head_bytes = self.req.serialize_for_origin();
        ups_w
            .write_all_flush(&head_bytes)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;

        self.http_notes.mark_req_send_hdr();
        Ok(())
    }

    /// 无请求体路径：发送请求头后带超时等待上游响应头并转发响应。
    /// 超时归因为上游应用层超时。
    async fn do_forward_without_body<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<()>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.send_request_header(&mut rsp_io.ups_w).await?;
        self.http_notes.mark_req_no_body();

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
            Ok(Ok((rsp, head_bytes))) => self.send_response(rsp, head_bytes, rsp_io, None).await,
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ServerTaskError::UpstreamAppTimeout(
                "timeout to receive response header",
            )),
        }
    }

    /// 带请求体路径：发送请求头后，并发进行"客户端请求体→上游"的流式拷贝
    /// 与"上游响应头探测"——支持上游提前响应（expect-continue、鉴权拒绝等）。
    /// 空闲检查区分停滞方向：无缓存数据=客户端不吐体（ClientAppTimeout），
    /// 有积压=上游不收（UpstreamAppTimeout）。任一方向未搬完都会置 should_close，
    /// 因为残留字节会破坏流水线上下一个请求的边界。
    async fn do_forward_with_body<CR, CW, UR, UW>(
        &mut self,
        req_io: &mut HttpRequestIo<CR>,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        body_type: HttpBodyType,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.send_request_header(&mut rsp_io.ups_w).await?;

        let mut clt_body_reader = HttpBodyReader::new(
            &mut req_io.clt_r,
            body_type,
            self.ctx.h1_interception().body_line_max_len,
        );
        let mut rsp_head: Option<(HttpTransparentResponse, Bytes)> = None;

        let mut clt_to_ups = StreamCopy::new(
            &mut clt_body_reader,
            &mut rsp_io.ups_w,
            &self.ctx.server_config.limited_copy_config(),
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = rsp_io.ups_r.fill_wait_data() => {
                    match r {
                        Ok(true) => {
                            // we got some data from upstream（上游提前返回数据，开始解析响应头）
                            let (rsp, bytes) = self.recv_response_header(&mut rsp_io.ups_r).await?;
                            match rsp.code {
                                100 | 103 => {
                                    // CONTINUE | Early Hints：临时响应透传，继续搬请求体
                                    self.send_response_header(&mut rsp_io.clt_w, bytes).await?;
                                }
                                _ => {
                                    rsp_head = Some((rsp, bytes));
                                    break;
                                }
                            }
                        }
                        Ok(false) => return Err(ServerTaskError::ClosedByUpstream),
                        Err(e) => return Err(ServerTaskError::UpstreamReadFailed(e)),
                    }
                }
                r = &mut clt_to_ups => {
                    r.map_err(|e| match e {
                        StreamCopyError::ReadFailed(e) => ServerTaskError::ClientTcpReadFailed(e),
                        StreamCopyError::WriteFailed(e) => ServerTaskError::UpstreamWriteFailed(e),
                    })?;
                    // 请求体全部搬运完成的打点
                    self.http_notes.mark_req_send_all();
                    break;
                }
                n = idle_interval.tick() => {
                    if clt_to_ups.is_idle() {
                        idle_count += n;
                        if idle_count >= self.ctx.max_idle_count {
                            return if clt_to_ups.no_cached_data() {
                                Err(ServerTaskError::ClientAppTimeout("idle while reading request body"))
                            } else {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while sending request body"))
                            };
                        }
                    } else {
                        idle_count = 0;
                        clt_to_ups.reset_active();
                    }

                    if self.ctx.belongs_to_blocked_user() {
                        return Err(ServerTaskError::CanceledAsUserBlocked);
                    }

                    if self.ctx.server_force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }

        let copy_done = clt_to_ups.finished();
        let rsp_head = match rsp_head {
            Some(header) => {
                if !clt_body_reader.finished() {
                    // not all client data read in, drop the client connection
                    self.should_close = true;
                }
                if !copy_done {
                    // not all client data sent out, drop the remote connection
                    self.should_close = true;
                }
                header
            }
            None => {
                match tokio::time::timeout(
                    self.ctx.h1_rsp_hdr_recv_timeout(),
                    self.recv_final_response_header(rsp_io),
                )
                .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ServerTaskError::UpstreamAppTimeout(
                            "timeout to receive response header",
                        ));
                    }
                }
            }
        };

        self.send_response(rsp_head.0, rsp_head.1, rsp_io, None)
            .await?;

        Ok(())
    }

    /// 从上游读端解析一个响应头（可能带 body_type 所需信息），返回响应对象
    /// 与其原始字节。解析失败按请求错误路径处理。
    async fn recv_response_header<UR>(
        &mut self,
        ups_r: &mut UR,
    ) -> ServerTaskResult<(HttpTransparentResponse, Bytes)>
    where
        UR: AsyncBufRead + Unpin,
    {
        HttpTransparentResponse::parse(
            ups_r,
            &self.req.method,
            self.req.keep_alive(),
            self.ctx.h1_interception().rsp_head_max_size,
        )
        .await
        .map_err(|e| e.into())
    }

    /// 循环读取直到拿到最终响应头：100 Continue 透传后立即再读一个响应
    /// （1xx 后不允许插入其它临时响应），103 Early Hints 可多次出现、持续透传，
    /// 其它状态码即为最终响应直接返回。
    async fn recv_final_response_header<CW, UR, UW>(
        &mut self,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<(HttpTransparentResponse, Bytes)>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            let (rsp, bytes) = self.recv_response_header(&mut rsp_io.ups_r).await?;
            match rsp.code {
                100 => {
                    // HTTP CONTINUE
                    self.send_response_header(&mut rsp_io.clt_w, bytes).await?;
                    // recv the final response header
                    return self.recv_response_header(&mut rsp_io.ups_r).await;
                }
                103 => {
                    // HTTP Early Hints
                    self.send_response_header(&mut rsp_io.clt_w, bytes).await?;
                }
                _ => {
                    return Ok((rsp, bytes));
                }
            }
        }
    }

    /// 响应处理总入口：统一处理 keep-alive 协商与打点后，按是否配置 ICAP
    /// respmod 分流——有 respmod 时把响应送检（可被改写/阻断），并把
    /// reqmod 阶段传来的共享响应头注入适配器；adapter 创建失败且未配 bypass
    /// 时直接报错，bypass 时降级为原样转发。
    /// send_error_response 的更新规则见各分支内注释。
    async fn send_response<CW, UR, UW>(
        &mut self,
        mut rsp: HttpTransparentResponse,
        rsp_head: Bytes,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        adaptation_respond_shared_headers: Option<HttpHeaderMap>,
    ) -> ServerTaskResult<()>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if self.should_close {
            rsp.set_no_keep_alive();
        }
        if !rsp.keep_alive() {
            self.should_close = true;
        }
        self.http_notes.origin_status = rsp.code;
        self.http_notes.rsp_status = 0;
        self.http_notes.mark_rsp_recv_hdr();

        if let Some(respmod) = self.ctx.audit_handle.icap_respmod_client() {
            match respmod
                .h1_adapter(
                    self.ctx.server_config.limited_copy_config(),
                    self.ctx.h1_interception().body_line_max_len,
                    self.ctx.idle_checker(),
                )
                .await
            {
                Ok(mut adapter) => {
                    let mut adaptation_state = RespmodAdaptationRunState::new(
                        self.http_notes.receive_ins,
                        self.http_notes.dur_rsp_recv_hdr,
                    );
                    adapter.set_client_addr(self.ctx.task_notes.client_addr);
                    if let Some(username) = self.ctx.raw_user_name() {
                        adapter.set_client_username(username.clone());
                    }
                    adapter.set_respond_shared_headers(adaptation_respond_shared_headers);
                    let r = self
                        .send_response_with_adaptation(rsp, rsp_io, adapter, &mut adaptation_state)
                        .await;
                    if !adaptation_state.clt_write_finished || !adaptation_state.ups_read_finished {
                        self.should_close = true;
                    }
                    if let Some(dur) = adaptation_state.dur_ups_recv_all {
                        self.http_notes.dur_rsp_recv_all = dur;
                    }
                    // 客户端尚未收到任何响应字节时才允许继续发代理错误响应
                    self.send_error_response = !adaptation_state.clt_write_started;
                    return r;
                }
                Err(e) => {
                    // respmod 不可用：未配置 bypass 则视为内部错误，配置则走原样转发
                    if !respmod.bypass() {
                        return Err(ServerTaskError::InternalAdapterError(e));
                    }
                }
            }
        }

        self.send_response_without_adaptation(rsp, rsp_head, rsp_io)
            .await
    }

    /// 响应经 ICAP respmod 送检后回传客户端。
    /// rsp_status 按"原始透传"或"改写后应答"分别取上游码或适配器的新码。
    async fn send_response_with_adaptation<CW, UR, UW>(
        &mut self,
        rsp: HttpTransparentResponse,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
        icap_adapter: HttpResponseAdapter<ServerIdleChecker>,
        adaptation_state: &mut RespmodAdaptationRunState,
    ) -> ServerTaskResult<()>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Send + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match icap_adapter
            .xfer(
                adaptation_state,
                self.req,
                &rsp,
                &mut rsp_io.ups_r,
                &mut rsp_io.clt_w,
            )
            .await
        {
            Ok(RespmodAdaptationEndState::OriginalTransferred) => {
                self.http_notes.rsp_status = rsp.code;
                Ok(())
            }
            Ok(RespmodAdaptationEndState::AdaptedTransferred(adapted_rsp)) => {
                self.http_notes.rsp_status = adapted_rsp.code;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 响应不经送检的原样回传：有体时头体一并流式拷贝（头作为预置数据），
    /// 无体时只发头并打"无体"标记。自此之后不再允许发代理层错误响应。
    async fn send_response_without_adaptation<CW, UR, UW>(
        &mut self,
        rsp: HttpTransparentResponse,
        rsp_head: Bytes,
        rsp_io: &mut HttpResponseIo<CW, UR, UW>,
    ) -> ServerTaskResult<()>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        self.send_error_response = false;

        if let Some(body_type) = rsp.body_type(&self.req.method) {
            // the following function must send rsp header out
            //（send_response_body 以头作为预置数据，必然会写出响应头，
            //  因此可提前把 rsp_status 认定为上游状态码）
            self.http_notes.rsp_status = self.http_notes.origin_status;
            self.send_response_body(
                rsp_head.into(),
                &mut rsp_io.ups_r,
                &mut rsp_io.clt_w,
                body_type,
            )
            .await
        } else {
            self.send_response_header(&mut rsp_io.clt_w, rsp_head)
                .await?;
            self.http_notes.rsp_status = self.http_notes.origin_status;
            self.http_notes.mark_rsp_no_body();
            Ok(())
        }
    }

    /// 把响应头原始字节写出并立即 flush（临时响应/无体响应均走此路径）。
    async fn send_response_header<CW>(
        &mut self,
        clt_w: &mut CW,
        head_bytes: Bytes,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
    {
        clt_w
            .write_all_flush(&head_bytes)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)
    }

    /// 把响应头（作为预置数据）+ 按 body_type 解析出的响应体流式拷贝给客户端。
    /// 空闲/封禁/退出检查语义与 CONNECT 路径的响应体拷贝相同（见
    /// `H1ConnectTask::send_response_body`），此处不再赘述。
    async fn send_response_body<UR, CW>(
        &mut self,
        header: Vec<u8>,
        ups_r: &mut UR,
        clt_w: &mut CW,
        body_type: HttpBodyType,
    ) -> ServerTaskResult<()>
    where
        UR: AsyncBufRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        let mut body_reader = HttpBodyReader::new(
            ups_r,
            body_type,
            self.ctx.h1_interception().body_line_max_len,
        );

        let mut ups_to_clt = StreamCopy::with_data(
            &mut body_reader,
            clt_w,
            &self.ctx.server_config.limited_copy_config(),
            header,
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut ups_to_clt => {
                    return match r {
                        Ok(_) => {
                            self.http_notes.mark_rsp_recv_all();
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
                                Err(ServerTaskError::UpstreamAppTimeout("idle while reading response body"))
                            } else {
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
}
