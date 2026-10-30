/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/2 CONNECT 方法（含扩展 CONNECT）的请求头交换公共实现。
//!
//! [`ExchangeHead`] 负责 CONNECT 建隧道前的"头部交换"阶段：向源站开流、
//! 发送 CONNECT 请求头（可选经 ICAP reqmod 改编）、接收响应头并回给客户端；
//! 成功时返回四条半流句柄（客户端请求体/响应体、源站请求体/响应体）供
//! 隧道字节中继使用，失败时按需合成错误响应。
//! [`HttpConnectTaskNotes`] 记录各阶段耗时与状态码供收尾日志。
//! 具体协议分支见 standard（标准 CONNECT 隧道）与 extended（扩展 CONNECT）。

use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream, StreamId};
use http::{Request, Response, Version};
use tokio::time::Instant;

use g3_h2::{H2BodyTransfer, H2StreamBodyTransferError, H2StreamFromChunkedTransferError};
use g3_icap_client::reqmod::h1::HttpAdapterErrorResponse;
use g3_icap_client::reqmod::h2::{
    H2RequestAdapter, ReqmodAdaptationMidState, ReqmodAdaptationRunState,
    ReqmodRecvHttpResponseBody,
};
use g3_types::net::WebSocketNotes;

use super::H2StreamTransferError;
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;
use crate::serve::ServerIdleChecker;

mod standard;
pub(super) use standard::H2ConnectTask;

mod extended;
pub(super) use extended::H2ExtendedConnectTask;

/// CONNECT 头部交换阶段的耗时与结果记录，仅用于任务收尾日志。
struct HttpConnectTaskNotes {
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
    /// 响应头接收完成时刻距开始时间的偏移
    dur_rsp_recv_hdr: Duration,
}

impl Default for HttpConnectTaskNotes {
    fn default() -> Self {
        HttpConnectTaskNotes {
            ready_time: Duration::default(),
            rsp_status: 0,
            origin_status: 0,
            started_datetime: Utc::now(),
            started_ins: Instant::now(),
            dur_req_send_hdr: Duration::default(),
            dur_rsp_recv_hdr: Duration::default(),
        }
    }
}

impl HttpConnectTaskNotes {
    /// 记录源站流就绪（h2s.ready 返回）耗时。
    pub(crate) fn mark_stream_ready(&mut self) {
        self.ready_time = self.started_ins.elapsed();
    }

    /// 记录请求头发送完成时刻。
    pub(crate) fn mark_req_send_hdr(&mut self) {
        self.dur_req_send_hdr = self.started_ins.elapsed();
    }

    /// 记录响应头接收完成时刻。
    pub(crate) fn mark_rsp_recv_hdr(&mut self) {
        self.dur_rsp_recv_hdr = self.started_ins.elapsed();
    }
}

/// 一次 CONNECT 头部交换的执行上下文：跨请求/响应阶段收集状态，
/// 并在失败时决定是否允许向客户端补发合成的错误响应。
struct ExchangeHead<'a, SC: ServerConfig> {
    /// 检测上下文（ICAP 客户端、空闲配置、ACL 动作等）
    ctx: &'a StreamInspectContext<SC>,
    /// 成功向源站发出请求后记录的源站流 ID，供上层日志取用
    ups_stream_id: Option<StreamId>,
    /// 是否允许失败时向客户端合成错误响应。仅在请求头已发往源站、且响应
    /// 尚未开始发给客户端的阶段为 true；一旦已应答就不能再改写
    send_error_response: bool,
    /// 耗时/状态记录表
    http_notes: &'a mut HttpConnectTaskNotes,
    /// WebSocket 升级场景的头部记录表；非 websocket 为 None
    ws_notes: Option<&'a mut WebSocketNotes>,
}

impl<'a, SC: ServerConfig> ExchangeHead<'a, SC> {
    /// 创建普通 CONNECT 的头部交换上下文。
    fn new(ctx: &'a StreamInspectContext<SC>, http_notes: &'a mut HttpConnectTaskNotes) -> Self {
        ExchangeHead {
            ctx,
            ups_stream_id: None,
            send_error_response: false,
            http_notes,
            ws_notes: None,
        }
    }

    /// 创建 websocket 扩展 CONNECT 的头部交换上下文，附带 WebSocket 头部记录。
    fn new_websocket(
        ctx: &'a StreamInspectContext<SC>,
        http_notes: &'a mut HttpConnectTaskNotes,
        ws_notes: &'a mut WebSocketNotes,
    ) -> Self {
        ExchangeHead {
            ctx,
            ups_stream_id: None,
            send_error_response: false,
            http_notes,
            ws_notes: Some(ws_notes),
        }
    }

    /// 执行头部交换。成功时返回隧道中继所需的四条半流
    /// （客户端请求体、客户端响应体、源站响应体、源站请求体）；
    /// 返回 Ok(None) 表示流程已就地终结（错误响应已发出、无需建隧道）。
    /// 失败时若 send_error_response 允许，先给客户端补发 build_reply 合成的
    /// 错误响应再上抛错误。
    async fn run(
        &mut self,
        clt_req: Request<RecvStream>,
        mut clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        match self.do_run(clt_req, &mut clt_send_rsp, h2s).await {
            Ok(d) => Ok(d),
            Err(e) => {
                if self.send_error_response
                    && let Some(rsp) = e.build_reply()
                {
                    let rsp_status = rsp.status().as_u16();
                    if clt_send_rsp.send_response(rsp, true).is_ok() {
                        self.http_notes.rsp_status = rsp_status;
                    }
                }
                Err(e)
            }
        }
    }

    /// 头部交换主流程：向源站开流 -> （可选）ICAP reqmod 改编 -> 直接发送请求。
    async fn do_run(
        &mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: &mut SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        let (parts, clt_r) = clt_req.into_parts();

        let http_config = self.ctx.h2_interception();

        // 等待源站连接允许开新流（受 upstream_stream_open_timeout 约束）；
        // 失败时把源站给出的 reset 原因（缺省 REFUSED_STREAM）转发给客户端流，
        // 客户端据此可以安全重试
        let ups_send_req =
            match tokio::time::timeout(http_config.upstream_stream_open_timeout, h2s.ready()).await
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

        // 请求头即将发往源站：此后只要响应还没开始发给客户端，出错时都可合成错误响应
        self.send_error_response = true;
        let ups_req = Request::from_parts(parts, ());

        // 若配置了 ICAP 请求修改服务则先走适配流程；适配器启动失败时，
        // 按 bypass 配置决定报错终止还是退化为直连转发
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
                    return self
                        .forward_with_adaptation(
                            ups_send_req,
                            ups_req,
                            clt_r,
                            clt_send_rsp,
                            adapter,
                            &mut adaptation_state,
                        )
                        .await;
                }
                Err(e) => {
                    if !reqmod.bypass() {
                        return Err(H2StreamTransferError::InternalAdapterError(e));
                    }
                }
            }
        }

        self.send_request(ups_send_req, ups_req, clt_r, clt_send_rsp)
            .await
    }

    /// 经 ICAP reqmod 改编后转发：根据适配中间状态选择原始请求、改编后请求，
    /// 或直接采用适配器给出的错误响应（此时请求根本不发往源站）。
    async fn forward_with_adaptation(
        &mut self,
        ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_r: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
        icap_adapter: H2RequestAdapter<ServerIdleChecker>,
        adaptation_state: &mut ReqmodAdaptationRunState,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        match icap_adapter.xfer_connect(adaptation_state, ups_req).await {
            Ok(ReqmodAdaptationMidState::OriginalRequest(orig_req)) => {
                self.send_request(ups_send_req, orig_req, clt_r, clt_send_rsp)
                    .await
            }
            Ok(ReqmodAdaptationMidState::AdaptedRequest(_http_req, final_req)) => {
                self.send_request(ups_send_req, final_req, clt_r, clt_send_rsp)
                    .await
            }
            // 适配器直接给出错误响应：发给客户端后本流终结，无法建立隧道
            Ok(ReqmodAdaptationMidState::HttpErrResponse(err_rsp, recv_body)) => {
                self.send_adaptation_error_response(clt_send_rsp, err_rsp, recv_body)
                    .await?;
                Ok(None)
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

        // 响应即将由本函数发出，属于已应答，不能再被上层 build_reply 二次改写
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

    /// 向源站发送 CONNECT 请求头（end_stream=false，请求流保留给隧道上行），
    /// 然后带超时等待响应头，成功后交给 send_response 分流处理。
    async fn send_request(
        &mut self,
        mut ups_send_req: SendRequest<Bytes>,
        ups_req: Request<()>,
        clt_r: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        let (ups_response_fut, ups_w) = ups_send_req
            .send_request(ups_req, false)
            .map_err(H2StreamTransferError::RequestHeadSendFailed)?;
        self.ups_stream_id = Some(ups_response_fut.stream_id());
        self.http_notes.mark_req_send_hdr();

        match tokio::time::timeout(self.ctx.h2_rsp_hdr_recv_timeout(), ups_response_fut).await {
            Ok(Ok(ups_rsp)) => {
                self.http_notes.mark_rsp_recv_hdr();
                self.send_response(ups_rsp, ups_w, clt_r, clt_send_rsp)
                    .await
            }
            Ok(Err(e)) => Err(H2StreamTransferError::ResponseHeadRecvFailed(e)),
            Err(_) => Err(H2StreamTransferError::ResponseHeadRecvTimeout),
        }
    }

    /// 按源站 CONNECT 响应状态码分流：2xx 表示隧道建立成功，交接四条半流；
    /// 非 2xx 则把（可能带错误页体的）响应透传给客户端并结束本流。
    async fn send_response(
        &mut self,
        ups_rsp: Response<RecvStream>,
        ups_w: SendStream<Bytes>,
        clt_r: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        // 源站已应答，后续失败应如实透传，而非合成响应
        self.send_error_response = false;
        self.http_notes.origin_status = ups_rsp.status().as_u16();

        if ups_rsp.status().is_success() {
            self.send_ok_response(ups_rsp, ups_w, clt_r, clt_send_rsp)
                .await
        } else {
            self.send_err_response(ups_rsp, clt_send_rsp).await?;
            Ok(None)
        }
    }

    /// 隧道建立成功路径：把 2xx 响应头发给客户端。若源站响应流已无数据
    /// （is_end_stream，异常情形）则只发头并返回 None；否则返回四条半流
    /// 供上层做双向字节中继。
    async fn send_ok_response(
        &mut self,
        ups_rsp: Response<RecvStream>,
        ups_w: SendStream<Bytes>,
        clt_r: RecvStream,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<
        Option<(RecvStream, SendStream<Bytes>, RecvStream, SendStream<Bytes>)>,
        H2StreamTransferError,
    > {
        let (parts, ups_r) = ups_rsp.into_parts();

        // websocket 场景：把源站响应头记录进 ws_notes 供审计日志
        if let Some(ws_notes) = self.ws_notes.take() {
            for (name, value) in &parts.headers {
                ws_notes.append_response_header(name, value);
            }
        }

        let ups_rsp = Response::from_parts(parts, ());

        if ups_r.is_end_stream() {
            let _ = clt_send_rsp
                .send_response(ups_rsp, true)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;
            Ok(None)
        } else {
            let clt_w = clt_send_rsp
                .send_response(ups_rsp, false)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;
            Ok(Some((clt_r, clt_w, ups_r, ups_w)))
        }
    }

    /// CONNECT 被拒（非 2xx）路径：把源站响应透传给客户端；若源站带了错误页
    /// 响应体，则边收边发地中继，并在循环中做空闲计数、用户封锁与服务退出检查。
    async fn send_err_response(
        &mut self,
        ups_rsp: Response<RecvStream>,
        clt_send_rsp: &mut SendResponse<Bytes>,
    ) -> Result<(), H2StreamTransferError> {
        let (parts, ups_r) = ups_rsp.into_parts();
        let ups_rsp = Response::from_parts(parts, ());

        if ups_r.is_end_stream() {
            let _ = clt_send_rsp
                .send_response(ups_rsp, true)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;
        } else {
            let clt_send_stream = clt_send_rsp
                .send_response(ups_rsp, false)
                .map_err(H2StreamTransferError::ResponseHeadSendFailed)?;
            self.http_notes.rsp_status = self.http_notes.origin_status;

            let mut rsp_body_transfer = H2BodyTransfer::new(
                ups_r,
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
                            Ok(_) => break,
                            Err(e) => return Err(H2StreamTransferError::ResponseBodyTransferFailed(e)),
                        }
                    }
                    n = idle_interval.tick() => {
                        // 体传输无进展则累计空闲次数，超限终止本流
                        if rsp_body_transfer.is_idle() {
                            idle_count += n;

                            if idle_count > self.ctx.max_idle_count {
                                return Err(H2StreamTransferError::Idle(idle_interval.period(), idle_count));
                            }
                        } else {
                            idle_count = 0;

                            rsp_body_transfer.reset_active();
                        }

                        // 策略检查：用户被封锁或服务强制退出时立即掐断错误页传输
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
