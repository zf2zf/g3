/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/2 普通方法（非 CONNECT）请求/响应的流级转发与检测。
//!
//! [`H2ForwardTask`] 处理 [`stream::transfer`](super::stream) 分派来的常规请求：
//! 向源站开流并发送请求头/请求体（可选经 ICAP reqmod 改编），接收响应头/
//! 响应体（可选经 ICAP respmod 改编）后回给客户端；体转发循环内同时做空闲
//! 计数、用户封锁与服务退出检查。[`HttpForwardTaskNotes`] 记录各阶段耗时与
//! 状态码供收尾日志。

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{Reason, RecvStream, StreamId};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use tokio::time::Instant;

use g3_h2::{H2StreamBodyTransferError, H2StreamFromChunkedTransferError, RequestExt};
use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple};

use g3_icap_client::reqmod::h2::{
    H2RequestAdapter, HttpAdapterErrorResponse, ReqmodAdaptationEndState, ReqmodAdaptationRunState,
    ReqmodRecvHttpResponseBody,
};
use g3_icap_client::respmod::h2::{
    H2ResponseAdapter, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use g3_slog_types::{LtDateTime, LtDuration, LtH2StreamId, LtHttpMethod, LtHttpUri, LtUuid};
use g3_types::net::{HttpHeaderMap, TlsKeyLogBuffer};

use super::{H2BodyTransfer, H2StreamTransferError};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;
use crate::serve::ServerIdleChecker;

/// 以 "H2StreamForward" 为拦截类型输出单流转发的全生命周期日志，附带
/// 方法/URI、两侧流 ID 与各阶段耗时。未配置检测日志器时不输出。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2StreamForward",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "clt_stream" => LtH2StreamId(&$obj.clt_stream_id),
                "ups_stream" => $obj.ups_stream_id.as_ref().map(LtH2StreamId),
                "started_at" => LtDateTime(&$obj.http_notes.started_datetime),
                "method" => LtHttpMethod(&$obj.http_notes.method),
                "uri" => LtHttpUri::new(&$obj.http_notes.uri, $obj.ctx.log_uri_max_chars()),
                "ready_time" => LtDuration($obj.http_notes.ready_time),
                "rsp_status" => $obj.http_notes.rsp_status,
                "origin_status" => $obj.http_notes.origin_status,
                "dur_req_send_hdr" => LtDuration($obj.http_notes.dur_req_send_hdr),
                "dur_req_send_all" => LtDuration($obj.http_notes.dur_req_send_all),
                "dur_rsp_recv_hdr" => LtDuration($obj.http_notes.dur_rsp_recv_hdr),
                "dur_rsp_recv_all" => LtDuration($obj.http_notes.dur_rsp_recv_all),
            );
        }
    };
}

/// 单流转发的耗时与结果记录，仅用于任务收尾日志。
struct HttpForwardTaskNotes {
    /// 请求方法（GET/POST 等）
    method: Method,
    /// 请求 URI
    uri: Uri,
    /// 等待源站流就绪（h2s.ready）所花的时间
    ready_time: Duration,
    /// 实际发送给客户端的响应状态码（0 表示未发送）
    rsp_status: u16,
    /// 源站返回的原始状态码（0 表示未收到）
    origin_status: u16,
    /// 本任务开始时刻（单调时钟），各耗时字段以此为基准
    started_ins: Instant,
    /// 本任务开始的壁钟时间，用于日志展示
    started_datetime: DateTime<Utc>,
    /// 请求头发送完成时刻距开始时间的偏移
    dur_req_send_hdr: Duration,
    /// 请求头+请求体全部发送完成时刻距开始时间的偏移
    dur_req_send_all: Duration,
    /// 响应头接收完成时刻距开始时间的偏移
    dur_rsp_recv_hdr: Duration,
    /// 响应头+响应体全部接收完成时刻距开始时间的偏移
    dur_rsp_recv_all: Duration,
}

impl HttpForwardTaskNotes {
    /// 以请求的方法与 URI 建表，计时起点为当下。
    fn new(method: Method, uri: Uri) -> Self {
        HttpForwardTaskNotes {
            method,
            uri,
            ready_time: Duration::default(),
            rsp_status: 0,
            origin_status: 0,
            started_datetime: Utc::now(),
            started_ins: Instant::now(),
            dur_req_send_hdr: Duration::default(),
            dur_req_send_all: Duration::default(),
            dur_rsp_recv_hdr: Duration::default(),
            dur_rsp_recv_all: Duration::default(),
        }
    }

    /// 记录源站流就绪（h2s.ready 返回）耗时。
    pub(crate) fn mark_stream_ready(&mut self) {
        self.ready_time = self.started_ins.elapsed();
    }

    /// 记录请求头发送完成时刻。
    pub(crate) fn mark_req_send_hdr(&mut self) {
        self.dur_req_send_hdr = self.started_ins.elapsed();
    }

    /// 无请求体的请求：请求整体发送完成时刻即请求头完成时刻。
    pub(crate) fn mark_req_no_body(&mut self) {
        self.dur_req_send_all = self.dur_req_send_hdr;
    }

    /// 记录请求头+请求体全部发送完成时刻。
    pub(crate) fn mark_req_send_all(&mut self) {
        self.dur_req_send_all = self.started_ins.elapsed();
    }

    /// 记录响应头接收完成时刻。
    pub(crate) fn mark_rsp_recv_hdr(&mut self) {
        self.dur_rsp_recv_hdr = self.started_ins.elapsed();
    }

    /// 无响应体的响应：响应整体接收完成时刻即响应头完成时刻。
    pub(crate) fn mark_rsp_no_body(&mut self) {
        self.dur_rsp_recv_all = self.dur_rsp_recv_hdr;
    }

    /// 记录响应头+响应体全部接收完成时刻。
    pub(crate) fn mark_rsp_recv_all(&mut self) {
        self.dur_rsp_recv_all = self.started_ins.elapsed();
    }
}

/// 普通方法请求的转发任务：一个实例对应一条客户端逻辑流。
pub(crate) struct H2ForwardTask<SC: ServerConfig> {
    /// 检测上下文（ICAP 客户端、ACL 动作、空闲配置等）
    ctx: StreamInspectContext<SC>,
    /// 客户端侧逻辑流 ID，用于日志关联
    clt_stream_id: StreamId,
    /// 源站侧逻辑流 ID；请求头尚未发出时为 None
    ups_stream_id: Option<StreamId>,
    /// 是否允许失败时向客户端合成错误响应。仅在请求头已发往源站、且响应
    /// 尚未开始发给客户端的阶段为 true；一旦已应答就不能再改写
    send_error_response: bool,
    /// 各阶段耗时/状态记录
    http_notes: HttpForwardTaskNotes,
    /// TLS 密钥日志缓冲，透传给 ICAP 适配器用于解密审计
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC> H2ForwardTask<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建转发任务，方法与 URI 取自客户端请求用于日志。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        clt_stream_id: StreamId,
        req: &Request<RecvStream>,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        let http_notes = HttpForwardTaskNotes::new(req.method().clone(), req.uri().clone());
        H2ForwardTask {
            ctx,
            clt_stream_id,
            ups_stream_id: None,
            send_error_response: false,
            http_notes,
            keylog_buffer,
        }
    }

    /// 任务失败收尾：若错误类型允许合成响应（build_reply 返回 Some），
    /// 把对应的 4xx/5xx 响应发给客户端，避免流被无声重置。
    fn reply_task_err(&mut self, mut clt_send_rsp: SendResponse<Bytes>, e: &H2StreamTransferError) {
        if let Some(rsp) = e.build_reply() {
            let rsp_status = rsp.status().as_u16();
            if clt_send_rsp.send_response(rsp, true).is_ok() {
                self.http_notes.rsp_status = rsp_status;
            }
        }
    }

    /// 对带 Expect 头的请求回 417（EXPECTATION_FAILED）：h2 目前不支持
    /// 100-continue 语义，只能显式拒绝而非静默丢弃时仍转发请求。
    fn reply_expectation_failed(
        &mut self,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        let response = Response::builder()
            .version(Version::HTTP_2)
            .status(StatusCode::EXPECTATION_FAILED)
            .body(())
            .map_err(|_| {
                H2StreamTransferError::InternalServerError(
                    "failed to build expectation failed error response",
                )
            })?;
        // 本函数已完整应答，后续错误不应再触发 reply_task_err
        self.send_error_response = false;
        let rsp_code = response.status().as_u16();
        if clt_send_rsp.send_response(response, true).is_ok() {
            self.http_notes.rsp_status = rsp_code;
        }
        Ok(())
    }

    /// 转发任务入口：执行完整请求/响应交换，失败时按需回错误响应并记录日志。
    /// 返回即代表本流结束。
    pub(crate) async fn forward(
        mut self,
        clt_req: Request<RecvStream>,
        mut clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        if let Err(e) = self.do_forward(clt_req, &mut clt_send_rsp, h2s).await {
            if self.send_error_response {
                self.reply_task_err(clt_send_rsp, &e);
            }
            intercept_log!(self, "{e}");
        } else {
            intercept_log!(self, "finished");
        }
    }

    /// 转发主流程：处理 Expect 头 -> 向源站开流 -> （可选）ICAP reqmod
    /// 改编转发 -> 否则直通转发。
    async fn do_forward(
        &mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: &mut SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        let (mut parts, clt_body) = clt_req.into_parts();
        if self.ctx.h2_interception().silent_drop_expect_header {
            // just drop the Expect header to avoid 100-continue response, which currently is not supported by h2
            // 直接丢弃 Expect 头：h2 尚不支持 100-continue，避免源站苦等放体
            parts.headers.remove(http::header::EXPECT);
        } else if parts.headers.contains_key(http::header::EXPECT) {
            // 未配置静默丢弃时，显式回 417 让客户端走不带 Expect 的重试
            return self.reply_expectation_failed(clt_send_rsp);
        }

        // 等待源站连接允许开新流（带超时）；失败时把 reset 原因透传回客户端流
        let ups_send_req = match tokio::time::timeout(
            self.ctx.h2_interception().upstream_stream_open_timeout,
            h2s.ready(),
        )
        .await
        {
            Ok(Ok(d)) => {
                self.http_notes.mark_stream_ready();
                d
            }
            Ok(Err(e)) => {
                let reason = e.reason().unwrap_or(Reason::REFUSED_STREAM);
                clt_send_rsp.send_reset(reason);
                return Err(H2StreamTransferError::UpstreamStreamOpenFailed(e));
            }
            Err(_) => {
                clt_send_rsp.send_reset(Reason::REFUSED_STREAM);
                return Err(H2StreamTransferError::UpstreamStreamOpenTimeout);
            }
        };

        /* added by wming for repid audit */
        // 为 repid 审计提取请求体长度，后面据此决定是否送 ICAP 改编
        let content_length = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // 请求头即将发往源站：此后响应尚未送出，出错时可合成错误响应
        self.send_error_response = true;
        let ups_req = Request::from_parts(parts, ());

        // 配置了 ICAP 请求修改服务时进入适配分支；适配器启动失败按 bypass
        // 配置决定报错终止还是退化为直通
        if let Some(reqmod) = self.ctx.audit_handle.icap_reqmod_client() {
            match reqmod
                .h2_adapter(
                    self.ctx.server_config.limited_copy_config(),
                    self.ctx.h1_interception().body_line_max_len,
                    self.ctx.h2_interception().max_header_list_size as usize,
                    self.ctx.h2_rsp_hdr_recv_timeout(),
                    true,
                    self.ctx.idle_checker(),
                )
                .await
            {
                Ok(mut adapter) => {
                    let mut adaptation_state =
                        ReqmodAdaptationRunState::new(self.http_notes.started_ins);
                    adapter.set_client_addr(self.ctx.task_notes.client_addr);
                    if let Some(username) = self.ctx.raw_user_name() {
                        adapter.set_client_username(username.clone());
                    }

                    /* added by wming for repid audit */
                    // 把客户端-代理连接四元组告知 ICAP，便于其审计日志关联 repid
                    let tuple = ConnectionTuple {
                        server_addr: self.ctx.connect_notes.client_addr,
                        remote_addr: self.ctx.connect_notes.server_addr,
                        protocol: ConnectionProtocol::Tcp,
                    };
                    adapter.set_connection_tuple(tuple);

                    // 附带 TLS 密钥日志，ICAP 可解密内层 TLS 流量做内容审计
                    if let Some(ref keylog) = self.keylog_buffer {
                        adapter.set_keylog_buffer(keylog.clone());
                    }

                    let cfg = self.ctx.h1_interception();

                    let mut use_icap = true;

                    // 按请求策略裁剪无须送检的请求：req_hasbody 时，空体或
                    // 小于阈值的请求体直接跳过 ICAP，减少小请求的适配开销
                    if cfg.req_hasbody {
                        if clt_body.is_end_stream() {
                            use_icap = false;
                        } else if let Some(cl) = content_length
                            && (cl < cfg.req_body_min_size as u64)
                        {
                            use_icap = false;
                        }
                    }

                    if use_icap {
                        let r = self
                            .forward_with_adaptation(
                                ups_send_req,
                                ups_req,
                                clt_body,
                                clt_send_rsp,
                                adapter,
                                &mut adaptation_state,
                            )
                            .await;
                        // 适配器内部记录了更精确的阶段耗时，回填到本任务日志表
                        if let Some(dur) = adaptation_state.dur_ups_send_header {
                            self.http_notes.dur_req_send_hdr = dur;
                        }
                        if let Some(dur) = adaptation_state.dur_ups_send_all {
                            self.http_notes.dur_req_send_all = dur;
                        }
                        if let Some(dur) = adaptation_state.dur_ups_recv_header {
                            self.http_notes.dur_rsp_recv_hdr = dur;
                        }
                        return r;
                    }
                }
                Err(e) => {
                    if !reqmod.bypass() {
                        return Err(H2StreamTransferError::InternalAdapterError(e));
                    }
                }
            }
        }

        // 未配置 ICAP、被 bypass 或请求太小：直通转发
        self.forward_without_adaptation(ups_send_req, ups_req, clt_body, clt_send_rsp)
            .await
    }

    /// 经 ICAP reqmod 改编后完成整条流的转发：适配终态若是"原始/改编后请求
    /// 已转发完成"则继续处理响应；若是适配器直接给出的错误响应则原样回客户端。
    async fn forward_with_adaptation(
        &mut self,
        ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_body: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
        icap_adapter: H2RequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> Result<(), H2StreamTransferError> {
        // 保留原始请求头的副本：respmod 适配与日志都需要"客户端原请求"
        let orig_req = ups_req.clone_header();

        // reqmod 全程代理"客户端体->ICAP->源站"的请求转发，返回响应头后再走
        // 本地响应处理；respond_shared_headers 让 respmod 复用 reqmod 会话信息
        match icap_adapter
            .xfer(adaptation_state, ups_req, clt_body, ups_send_req)
            .await
        {
            Ok(ReqmodAdaptationEndState::OriginalTransferred(ups_rsp)) => {
                self.send_response(
                    orig_req,
                    ups_rsp,
                    clt_send_rsp,
                    adaptation_state.take_respond_shared_headers(),
                )
                .await
            }
            Ok(ReqmodAdaptationEndState::AdaptedTransferred(_http_req, ups_rsp)) => {
                self.send_response(
                    orig_req,
                    ups_rsp,
                    clt_send_rsp,
                    adaptation_state.take_respond_shared_headers(),
                )
                .await
            }
            // 适配器直接给出错误响应：请求未发往源站，响应就地回给客户端
            Ok(ReqmodAdaptationEndState::HttpErrResponse(err_rsp, recv_body)) => {
                self.send_adaptation_error_response(clt_send_rsp, err_rsp, recv_body)
                    .await
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 把 ICAP 适配器生成的错误响应以 h2 响应的形式发给客户端：带体时逐块
    /// 转发并把 ICAP 连接归还连接池（save_connection），无体时直接 end_stream。
    async fn send_adaptation_error_response(
        &mut self,
        clt_send_rsp: &mut SendResponse<Bytes>,
        rsp: HttpAdapterErrorResponse,
        rsp_recv_body: Option<ReqmodRecvHttpResponseBody>,
    ) -> Result<(), H2StreamTransferError> {
        let response = Response::new(());
        let (mut parts, _) = response.into_parts();
        parts.version = Version::HTTP_2;
        parts.status = rsp.status;
        parts.headers = rsp.headers.into();
        let response = Response::from_parts(parts, ());

        // 响应即将由本函数发出，属于已应答，不能再被 reply_task_err 二次改写
        self.send_error_response = false;
        let rsp_status = response.status().as_u16();
        if let Some(mut recv_body) = rsp_recv_body {
            let mut clt_send_stream = clt_send_rsp
                .send_response(response, false)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = rsp_status;

            let body_transfer = recv_body.body_transfer(&mut clt_send_stream);
            body_transfer.await.map_err(|e| match e {
                H2StreamFromChunkedTransferError::ReadError(e) => {
                    H2StreamTransferError::InternalAdapterError(anyhow!(
                        "read http error response from adapter failed: {e:?}"
                    ))
                }
                H2StreamFromChunkedTransferError::SendDataFailed(e) => {
                    H2StreamTransferError::ResponseBodyTransferFailed(
                        H2StreamBodyTransferError::SendDataFailed(e),
                    )
                }
                H2StreamFromChunkedTransferError::SendTrailerFailed(e) => {
                    H2StreamTransferError::ResponseBodyTransferFailed(
                        H2StreamBodyTransferError::SendTrailersFailed(e),
                    )
                }
                H2StreamFromChunkedTransferError::SenderNotInSendState => {
                    H2StreamTransferError::ResponseBodyTransferFailed(
                        H2StreamBodyTransferError::SenderNotInSendState,
                    )
                }
            })?;

            recv_body.save_connection().await;
        } else {
            clt_send_rsp
                .send_response(response, true)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = rsp_status;
        }

        Ok(())
    }

    /// 直通（无 ICAP）转发：按客户端请求流是否还带数据选择无体/有体路径。
    async fn forward_without_adaptation(
        &mut self,
        ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_body: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        if clt_body.is_end_stream() {
            self.forward_without_body(ups_send_req, ups_req, clt_send_rsp)
                .await
        } else {
            self.forward_with_body(ups_send_req, ups_req, clt_body, clt_send_rsp)
                .await
        }
    }

    /// 无请求体的请求（GET/HEAD 等）：发头即 end_stream，随后带超时等待响应头。
    async fn forward_without_body(
        &mut self,
        mut ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        // 保留原始请求头副本供 respmod / 审计使用
        let orig_req = ups_req.clone_header();

        let (ups_rsp_fut, _) = ups_send_req
            .send_request(ups_req, true)
            .map_err(H2StreamTransferError::RequestHeadSendFailed)?; // do not send REFUSED_STREAM, use the default rst in h2
        // 不主动挑 reset 码：开流失败时让 h2 按默认 GOAWAY/REFUSED 语义处理
        self.ups_stream_id = Some(ups_rsp_fut.stream_id());
        self.http_notes.mark_req_send_hdr();
        self.http_notes.mark_req_no_body();

        // there shouldn't be 100 response in this case
        // 请求不带体，不会触发 100-continue，可直接等待最终响应头
        let ups_rsp =
            match tokio::time::timeout(self.ctx.h2_rsp_hdr_recv_timeout(), ups_rsp_fut).await {
                Ok(Ok(d)) => {
                    self.http_notes.mark_rsp_recv_hdr();
                    d
                }
                Ok(Err(e)) => return Err(H2StreamTransferError::ResponseHeadRecvFailed(e)),
                Err(_) => return Err(H2StreamTransferError::ResponseHeadRecvTimeout),
            };

        self.send_response(orig_req, ups_rsp, clt_send_rsp, None)
            .await
    }

    /// 带请求体的请求：一边把客户端体转发给源站，一边等待响应头——两者并发
    /// 进行，以支持源站提前应答（如 413）而不必等请求体传完。
    async fn forward_with_body(
        &mut self,
        mut ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_body: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        let orig_req = ups_req.clone_header();

        let (mut ups_rsp_fut, ups_send_stream) = ups_send_req
            .send_request(ups_req, false)
            .map_err(H2StreamTransferError::RequestHeadSendFailed)?; // do not send REFUSED_STREAM, use the default rst in h2
        self.ups_stream_id = Some(ups_rsp_fut.stream_id());
        self.http_notes.mark_req_send_hdr();

        let mut req_body_transfer = H2BodyTransfer::new(
            clt_body,
            ups_send_stream,
            self.ctx.server_config.limited_copy_config().yield_size(),
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        // 记录是否已提前收到响应头，用于循环结束后分流
        let mut ups_rsp: Option<Response<RecvStream>> = None;

        loop {
            tokio::select! {
                biased;

                r = &mut req_body_transfer => {
                    match r {
                        Ok(_) => {
                            self.http_notes.mark_req_send_all();
                            break;
                        }
                        Err(e) => {
                            return Err(H2StreamTransferError::RequestBodyTransferFailed(e));
                        }
                    }
                }
                r = &mut ups_rsp_fut => {
                    match r {
                        Ok(rsp) => {
                            // 源站提前应答：停止等待体传完，直接进响应处理
                            self.http_notes.mark_rsp_recv_hdr();
                            ups_rsp = Some(rsp);
                            break;
                        }
                        Err(e) => {
                            return Err(H2StreamTransferError::ResponseHeadRecvFailed(e));
                        }
                    }
                }
                n = idle_interval.tick() => {
                    // 体转发无进展则累计空闲次数，超限终止本流
                    if req_body_transfer.is_idle() {
                        idle_count += n;

                        if idle_count > self.ctx.max_idle_count {
                            return Err(H2StreamTransferError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        idle_count = 0;

                        req_body_transfer.reset_active();
                    }

                    // 策略检查：用户被封锁或服务强制退出时立即掐断本流
                    if self.ctx.belongs_to_blocked_user() {
                        return Err(H2StreamTransferError::CanceledAsUserBlocked);
                    }

                    if self.ctx.server_force_quit() {
                        return Err(H2StreamTransferError::CanceledAsServerQuit)
                    }
                }
            }
        }

        if let Some(ups_rsp) = ups_rsp {
            // 循环中已收到响应头，直接进入响应处理
            self.send_response(orig_req, ups_rsp, clt_send_rsp, None)
                .await
        } else {
            // 请求体已全部送达，再单独等待响应头（带超时）
            let ups_rsp =
                match tokio::time::timeout(self.ctx.h2_rsp_hdr_recv_timeout(), ups_rsp_fut).await {
                    Ok(Ok(d)) => {
                        self.http_notes.mark_rsp_recv_hdr();
                        d
                    }
                    Ok(Err(e)) => return Err(H2StreamTransferError::ResponseHeadRecvFailed(e)),
                    Err(_) => return Err(H2StreamTransferError::ResponseHeadRecvTimeout),
                };

            self.send_response(orig_req, ups_rsp, clt_send_rsp, None)
                .await
        }
    }

    /// 响应处理入口：若配置了 ICAP 响应修改服务则交给 respmod 适配转发
    /// （并透传 reqmod 阶段的共享头部），否则直接把源站响应转发给客户端。
    async fn send_response(
        &mut self,
        ups_req: Request<()>,
        ups_rsp: Response<RecvStream>,
        clt_send_rsp: &mut SendResponse<Bytes>,
        adaptation_respond_shared_headers: Option<HttpHeaderMap>,
    ) -> Result<(), H2StreamTransferError> {
        let (parts, ups_body) = ups_rsp.into_parts();
        let clt_rsp = Response::from_parts(parts, ());

        self.http_notes.origin_status = clt_rsp.status().as_u16();

        // 配置了 ICAP 响应修改服务：适配失败时按 bypass 配置决定报错或直通
        if let Some(respmod) = self.ctx.audit_handle.icap_respmod_client() {
            match respmod
                .h2_adapter(
                    self.ctx.server_config.limited_copy_config(),
                    self.ctx.h1_interception().body_line_max_len,
                    self.ctx.h2_interception().max_header_list_size as usize,
                    self.ctx.idle_checker(),
                )
                .await
            {
                Ok(mut adapter) => {
                    let mut adaptation_state = RespmodAdaptationRunState::new(
                        self.http_notes.started_ins,
                        self.http_notes.dur_rsp_recv_hdr,
                    );
                    adapter.set_client_addr(self.ctx.task_notes.client_addr);
                    if let Some(username) = self.ctx.raw_user_name() {
                        adapter.set_client_username(username);
                    }
                    // 复用 reqmod 阶段与 ICAP 会话共享的头部（如 X-Preview 结果）
                    adapter.set_respond_shared_headers(adaptation_respond_shared_headers);
                    let r = self
                        .send_response_with_adaptation(
                            &ups_req,
                            clt_rsp,
                            ups_body,
                            clt_send_rsp,
                            adapter,
                            &mut adaptation_state,
                        )
                        .await;
                    if let Some(dur) = adaptation_state.dur_ups_recv_all {
                        self.http_notes.dur_rsp_recv_all = dur;
                    }
                    // 适配器已把响应写给客户端：后续错误不能再合成响应
                    if adaptation_state.clt_write_started {
                        self.send_error_response = false;
                    }
                    return r;
                }
                Err(e) => {
                    if !respmod.bypass() {
                        return Err(H2StreamTransferError::InternalAdapterError(e));
                    }
                }
            }
        }

        self.send_response_without_adaptation(clt_rsp, ups_body, clt_send_rsp)
            .await
    }

    /// 经 ICAP respmod 改编后把响应发给客户端；两种终态都表示数据已完整送达，
    /// 仅记录状态码（改编前后对客户端可见的状态码以原始为准）。
    async fn send_response_with_adaptation(
        &mut self,
        ups_req: &Request<()>,
        clt_rsp: Response<()>,
        ups_body: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
        icap_adapter: H2ResponseAdapter<ServerIdleChecker>,
        adaptation_state: &mut RespmodAdaptationRunState,
    ) -> Result<(), H2StreamTransferError> {
        let rsp_code = clt_rsp.status().as_u16();
        match icap_adapter
            .xfer(adaptation_state, ups_req, clt_rsp, ups_body, clt_send_rsp)
            .await
        {
            Ok(RespmodAdaptationEndState::OriginalTransferred) => {
                self.http_notes.rsp_status = rsp_code;
                Ok(())
            }
            Ok(RespmodAdaptationEndState::AdaptedTransferred(_rsp)) => {
                self.http_notes.rsp_status = rsp_code;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 直通响应转发：无体响应直接 end_stream 发头；带体响应边收边发，
    /// 并在循环中做空闲计数、用户封锁与服务退出检查。
    async fn send_response_without_adaptation(
        &mut self,
        clt_rsp: Response<()>,
        ups_body: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        // 响应即将发出（或已发出），失败不应答由源站语义决定而非合成响应
        self.send_error_response = false;

        if ups_body.is_end_stream() {
            self.http_notes.mark_rsp_no_body();
            let _ = clt_send_rsp
                .send_response(clt_rsp, true)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;
        } else {
            let clt_send_stream = clt_send_rsp
                .send_response(clt_rsp, false)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;

            let mut rsp_body_transfer = H2BodyTransfer::new(
                ups_body,
                clt_send_stream,
                self.ctx.server_config.limited_copy_config().yield_size(),
            );

            let mut idle_interval = self.ctx.idle_wheel.register();
            let mut idle_count = 0;

            loop {
                tokio::select! {
                    biased;

                    r = &mut rsp_body_transfer => {
                        match r {
                            Ok(_) => {
                                self.http_notes.mark_rsp_recv_all();
                                break;
                            },
                            Err(e) => return Err(H2StreamTransferError::ResponseBodyTransferFailed(e)),
                        }
                    }
                    n = idle_interval.tick() => {
                        // 体转发无进展则累计空闲次数，超限终止本流
                        if rsp_body_transfer.is_idle() {
                            idle_count += n;

                            if idle_count > self.ctx.max_idle_count {
                                return Err(H2StreamTransferError::Idle(idle_interval.period(), idle_count));
                            }
                        } else {
                            idle_count = 0;

                            rsp_body_transfer.reset_active();
                        }

                        // 策略检查：用户被封锁或服务强制退出时立即掐断本流
                        if self.ctx.belongs_to_blocked_user() {
                            return Err(H2StreamTransferError::CanceledAsUserBlocked);
                        }

                        if self.ctx.server_force_quit() {
                            return Err(H2StreamTransferError::CanceledAsServerQuit)
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
