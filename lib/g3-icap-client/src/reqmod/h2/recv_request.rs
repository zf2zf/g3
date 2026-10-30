/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 决策之后：把（原始或改写的）请求发给 h2 上游的各收尾分支。
//!
//! 与 h1 版的差异：
//! - "改写的请求"来自 ICAP 响应里**降级序列化的 HTTP/1.1 头块**
//!   （`HttpAdaptedRequest`），发送前要用 `RequestExt::adapt_to()` 转回 h2
//!   请求：method/uri 取自改写结果，但 `:authority`（原 uri 的 authority）与
//!   `TE` 等 hop-by-hop 头保持客户端原值；
//! - 请求体不再是从 socket 上读到的原始字节，而是三种来源之一：
//!   h2 `RecvStream` 直拷（原样放行）、内存中的预览数据（`H2PreviewData`）、
//!   或 ICAP 连接的 chunked 流（改写体，需 `H2StreamFromChunkedTransfer`
//!   解码为 h2 数据帧）。
//!
//! 每个分支的共同收尾：按 ICAP 的 keep-alive 归还连接 + 用
//! `recv_ups_response_head_after_transfer` 带上超时地等上游响应头。

use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use h2::client::{ResponseFuture, SendRequest};
use http::{Request, Response};

use g3_h2::{
    H2BodyTransfer, H2PreviewData, H2StreamBodyTransferError, H2StreamFromChunkedTransfer,
    H2StreamFromChunkedTransferError, RequestExt,
};
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::IdleCheck;

use super::{
    H2ReqmodAdaptationError, H2RequestAdapter, ReqmodAdaptationEndState, ReqmodAdaptationMidState,
    ReqmodAdaptationRunState,
};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> H2RequestAdapter<I> {
    /// 原样放行（ICAP 回 204）且请求无 body：直接发头并结束流。
    ///
    /// `send_request(.., true)` 的 `true` 表示 END_STREAM —— h2 由此告知上游
    /// "这个流无请求体"，等价于 h1 的 `Content-Length: 0`。
    pub(super) async fn handle_original_http_request_without_body(
        self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_request: Request<()>,
        mut ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 无封装内容需要再读，连接可以立刻归还
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        let (ups_recv_rsp, _) = ups_send_request
            .send_request(http_request, true)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed)?;
        state.mark_ups_send_header();
        state.mark_ups_send_no_body();

        let ups_rsp =
            recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout)
                .await?;
        state.mark_ups_recv_header();

        Ok(ReqmodAdaptationEndState::OriginalTransferred(ups_rsp))
    }

    /// 原样放行但请求有 body（预览阶段 ICAP 就回了 204）。
    ///
    /// body 走"h2 流直拷 h2 流"（`H2BodyTransfer`），不经过 chunked 重编码：
    /// 先内存中的预览数据 + 多读的尾巴，再搬运 `clt_body` 剩余部分。
    /// 上游响应头可能先于 body 到达，所以两者并发轮询。
    pub(super) async fn handle_original_http_request_with_body(
        self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_request: Request<()>,
        preview_data: H2PreviewData,
        clt_body: RecvStream,
        mut ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        // `false`：END_STREAM 先不发，body 还要继续搬运
        let (mut ups_recv_rsp, mut ups_send_stream) = ups_send_request
            .send_request(http_request, false)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed)?;
        state.mark_ups_send_header();

        // no reserve of capacity, let the driver buffer it
        // 预览数据已在内存中，直接写入 h2 发送缓冲（不预先申请 flow-control 额度）
        preview_data
            .h2_unbounded_send_all(&mut ups_send_stream)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendDataFailed)?;

        // 剩余 body 与 trailer 由搬运器负责（含 h2 流控窗口释放）
        let mut body_transfer =
            H2BodyTransfer::new(clt_body, ups_send_stream, self.copy_config.yield_size());

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        // h2 侧的搬运错误 -> 本模块统一错误的映射：读端问题归客户端，
        // 写端问题归上游
        fn convert_transfer_error(e: H2StreamBodyTransferError) -> H2ReqmodAdaptationError {
            match e {
                H2StreamBodyTransferError::RecvDataFailed(e)
                | H2StreamBodyTransferError::RecvTrailersFailed(e)
                | H2StreamBodyTransferError::ReleaseRecvCapacityFailed(e) => {
                    H2ReqmodAdaptationError::HttpClientRecvDataFailed(e)
                }
                H2StreamBodyTransferError::SendDataFailed(e)
                | H2StreamBodyTransferError::SendTrailersFailed(e)
                | H2StreamBodyTransferError::WaitSendCapacityFailed(e)
                | H2StreamBodyTransferError::GracefulCloseError(e) => {
                    H2ReqmodAdaptationError::HttpUpstreamSendDataFailed(e)
                }
                H2StreamBodyTransferError::SenderNotInSendState => {
                    H2ReqmodAdaptationError::HttpUpstreamNotInSendState
                }
            }
        }

        loop {
            tokio::select! {
                biased;

                // 上游响应头先到：h2 允许"请求体未发完即回响应"，
                // 此时提前返回，剩余搬运由 h2 驱动自行处理
                r = &mut ups_recv_rsp => {
                    return match r {
                        Ok(ups_rsp) => {
                            state.mark_ups_recv_header();
                            Ok(ReqmodAdaptationEndState::OriginalTransferred(ups_rsp))
                        }
                        Err(e) => Err(H2ReqmodAdaptationError::HttpUpstreamRecvResponseFailed(e)),
                    };
                }
                // body 全部发完：再带超时地等上游响应头
                r = &mut body_transfer => {
                    match r {
                        Ok(_) => {
                            state.mark_ups_send_all();
                            break;
                        }
                        Err(e) => return Err(convert_transfer_error(e)),
                    }
                }
                // 缓存空 => 卡在读客户端，否则卡在写上游
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H2ReqmodAdaptationError::HttpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }

        let ups_rsp =
            recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout)
                .await?;
        state.mark_ups_recv_header();

        Ok(ReqmodAdaptationEndState::OriginalTransferred(ups_rsp))
    }

    /// CONNECT 专用：只从 ICAP 连接读出"改写的请求头"，返回中间状态，
    /// **不**发送上游（隧道的建立由调用方完成）。
    pub(super) async fn recv_icap_http_request_without_body(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: Request<()>,
    ) -> Result<ReqmodAdaptationMidState, H2ReqmodAdaptationError> {
        // http_header_size 是本次读取的硬上限：只吃改写头，不碰后续数据
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        // 降级头块 -> h2 请求：保留原 :authority / TE
        let final_req = orig_http_request.adapt_to(&http_req);
        Ok(ReqmodAdaptationMidState::AdaptedRequest(
            http_req, final_req,
        ))
    }

    /// ICAP 改写了请求但无改写体：用改写后的头 + 原始（已上报完的）请求发送上游。
    pub(super) async fn handle_icap_http_request_without_body(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: Request<()>,
        mut ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        let final_req = orig_http_request.adapt_to(&http_req);

        // 无改写体 => 直接 END_STREAM
        let (ups_recv_rsp, _) = ups_send_request
            .send_request(final_req, true)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed)?;
        state.mark_ups_send_header();
        state.mark_ups_send_no_body();

        let ups_rsp =
            recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout)
                .await?;
        state.mark_ups_recv_header();

        Ok(ReqmodAdaptationEndState::AdaptedTransferred(
            http_req, ups_rsp,
        ))
    }

    /// ICAP 返回"改写请求 + chunked 请求体"，且上行方向已经结束（body 已
    /// 全部上报或已放弃）：单方向把 ICAP 的 chunked 解码为 h2 数据帧发给上游。
    pub(super) async fn handle_icap_http_request_with_body_after_transfer(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: Request<()>,
        mut ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 1) 先按 http_header_size 读出降级形式的改写头
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;

        // 2) 转回 h2 请求并发送（END_STREAM 不置位，body 紧随其后）
        let final_req = orig_http_request.adapt_to(&http_req);
        let (mut ups_recv_rsp, mut ups_send_stream) = ups_send_request
            .send_request(final_req, false)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed)?;
        state.mark_ups_send_header();

        // 3) ICAP 连接上剩余的 chunked 流 -> h2 数据帧
        //    （行/chunk 大小受 http_body_line_max_size、trailer 受 http_trailer_max_size 限制）
        let mut body_transfer = H2StreamFromChunkedTransfer::new(
            &mut self.icap_connection.reader,
            &mut ups_send_stream,
            &self.copy_config,
            self.http_body_line_max_size,
            self.http_trailer_max_size,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                // 上游响应头先到达：此时若改写 body 未读完，连接不能归还（会留残余数据）
                r = &mut ups_recv_rsp => {
                    return match r {
                        Ok(ups_rsp) => {
                            state.mark_ups_recv_header();
                            if body_transfer.finished() {
                                self.icap_connection.mark_reader_finished();
                                if icap_rsp.keep_alive {
                                    self.icap_client.save_connection(self.icap_connection);
                                }
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred(http_req, ups_rsp))
                        }
                        Err(e) => Err(H2ReqmodAdaptationError::HttpUpstreamRecvResponseFailed(e)),
                    };
                }
                // 改写 body 全部转给上游：可以安全结束 ICAP 读并归还连接
                r = &mut body_transfer => {
                    match r {
                        Ok(_) => {
                            state.mark_ups_send_all();
                            self.icap_connection.mark_reader_finished();
                            if icap_rsp.keep_alive {
                                self.icap_client.save_connection(self.icap_connection);
                            }
                            break;
                        }
                        Err(H2StreamFromChunkedTransferError::ReadError(e)) => return Err(H2ReqmodAdaptationError::IcapServerReadFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => return Err(H2ReqmodAdaptationError::HttpUpstreamSendDataFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => return Err(H2ReqmodAdaptationError::HttpUpstreamSendTrailedFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => return Err(H2ReqmodAdaptationError::HttpUpstreamNotInSendState),
                    }
                }
                // 搬运器空闲：缓存空 => 没读到数据，否则 => 写上游被堵住
                // （此处沿用与"原样放行"分支相同的 HttpClientReadIdle 变体命名）
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H2ReqmodAdaptationError::HttpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }

        let ups_rsp =
            recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout)
                .await?;
        state.mark_ups_recv_header();

        Ok(ReqmodAdaptationEndState::AdaptedTransferred(
            http_req, ups_rsp,
        ))
    }
}

/// 请求体发完后，带超时地等待上游响应头。
///
/// h2 的 `ResponseFuture` 本身不带超时：上游若收下请求却迟迟不响应，
/// 这里用 `http_rsp_head_recv_timeout` 兜底，超时归类为专门错误便于
/// 上层区分"上游无响应"与"上游连接故障"。
pub(super) async fn recv_ups_response_head_after_transfer(
    response_fut: ResponseFuture,
    timeout: Duration,
) -> Result<Response<RecvStream>, H2ReqmodAdaptationError> {
    match tokio::time::timeout(timeout, response_fut).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(H2ReqmodAdaptationError::HttpUpstreamRecvResponseFailed(e)),
        Err(_) => Err(H2ReqmodAdaptationError::HttpUpstreamRecvResponseTimeout),
    }
}
