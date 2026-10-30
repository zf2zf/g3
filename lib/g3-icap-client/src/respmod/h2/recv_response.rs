/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2：收到 ICAP 最终响应之后的各收尾分支。
//!
//! 每个方法对应一种"ICAP 应答形态 -> h2 客户端"的转换组合，与 h1 版
//! 对称，差异在于发送侧全部走 h2 `SendStream`：
//! - 原样放行（204）：把降级前的原始 h2 响应直接 `send_response` 发出；
//! - 应用改写：先用 `adapt_to()` 把 ICAP 返回的 HTTP/1.1 改写响应头
//!   合并回 h2 响应再发送，其 chunked body（若有）由
//!   `H2StreamFromChunkedTransfer` 解码为 h2 数据帧流式发出；
//! - 所有分支结束时按 keep-alive / 连接是否干净决定是否回池。

use h2::RecvStream;
use http::Response;

use g3_h2::{
    H2BodyTransfer, H2PreviewData, H2StreamBodyTransferError, H2StreamFromChunkedTransfer,
    H2StreamFromChunkedTransferError, ResponseExt,
};
use g3_http::client::HttpAdaptedResponse;
use g3_io_ext::IdleCheck;

use super::{
    H2RespmodAdaptationError, H2ResponseAdapter, H2SendResponseToClient, RespmodAdaptationEndState,
    RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> H2ResponseAdapter<I> {
    /// ICAP 返回 2xx 但没有封装任何 HTTP 报文：属于协议违例，回池后报错。
    pub(super) async fn handle_icap_ok_without_payload(
        self,
        icap_rsp: RespmodResponse,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError> {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(H2RespmodAdaptationError::IcapServerErrorResponse(
            IcapErrorReason::NoBodyFound,
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 204 + 原始响应无 body：把原始 h2 响应以 end_of_stream=true 直接
    /// 发给客户端（未做任何改写）。
    pub(super) async fn handle_original_http_response_without_body<CW>(
        self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_response: Response<()>,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        state.mark_clt_send_start();
        clt_send_response
            .send_response(http_response, true)
            .map_err(H2RespmodAdaptationError::HttpClientSendHeadFailed)?;
        state.mark_clt_send_header();
        state.mark_clt_send_no_body();

        Ok(RespmodAdaptationEndState::OriginalTransferred)
    }

    /// 204 + 原始响应带 body（preview 阶段 ICAP 就返回 204）：不再把
    /// 剩余数据发给 ICAP，将已缓存的预览数据 + h2 上游剩余 body 原样
    /// 直通转发给客户端（h2 -> h2，无需 chunked 转码）。
    pub(super) async fn handle_original_http_response_with_body<CW>(
        self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_response: Response<()>,
        preview_data: H2PreviewData,
        ups_body: RecvStream,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        state.mark_clt_send_start();
        let mut clt_send_stream = clt_send_response
            .send_response(http_response, false)
            .map_err(H2RespmodAdaptationError::HttpClientSendHeadFailed)?;
        state.mark_clt_send_header();

        // 预览缓存数据直接作为 h2 数据帧发出（不预分配容量，交给 h2 driver 缓冲）
        // no reserve of capacity, let the driver buffer it
        preview_data
            .h2_unbounded_send_all(&mut clt_send_stream)
            .map_err(H2RespmodAdaptationError::HttpClientSendDataFailed)?;

        // 剩余上游 body 走普通 h2 -> h2 搬运（含 trailer），带 idle 检查
        let mut body_transfer =
            H2BodyTransfer::new(ups_body, clt_send_stream, self.copy_config.yield_size());

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        // 搬运错误归一化：接收侧失败归上游，发送侧失败归客户端
        fn convert_transfer_error(e: H2StreamBodyTransferError) -> H2RespmodAdaptationError {
            match e {
                H2StreamBodyTransferError::RecvDataFailed(e)
                | H2StreamBodyTransferError::RecvTrailersFailed(e)
                | H2StreamBodyTransferError::ReleaseRecvCapacityFailed(e) => {
                    H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e)
                }
                H2StreamBodyTransferError::SendDataFailed(e)
                | H2StreamBodyTransferError::SendTrailersFailed(e)
                | H2StreamBodyTransferError::WaitSendCapacityFailed(e)
                | H2StreamBodyTransferError::GracefulCloseError(e) => {
                    H2RespmodAdaptationError::HttpClientSendDataFailed(e)
                }
                H2StreamBodyTransferError::SenderNotInSendState => {
                    H2RespmodAdaptationError::HttpClientNotInSendState
                }
            }
        }

        loop {
            tokio::select! {
                biased;

                r = &mut body_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_clt_send_all();
                            Ok(RespmodAdaptationEndState::OriginalTransferred)
                        }
                        Err(e) => Err(convert_transfer_error(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H2RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// ICAP 返回的改写响应只有头（无 body）：解析该 h1 形式响应头并
    /// `adapt_to` 合并进原始 h2 响应后，以空 body 直接发给客户端。
    pub(super) async fn handle_icap_http_response_without_body<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_header_size: usize,
        orig_http_response: Response<()>,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        let http_rsp =
            HttpAdaptedResponse::parse(&mut self.icap_connection.reader, http_header_size).await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        // 把 ICAP 的 HTTP/1.1 改写响应头合并回原始 h2 响应（头升级回转）
        let final_rsp = orig_http_response.adapt_to(&http_rsp);
        state.mark_clt_send_start();
        clt_send_response
            .send_response(final_rsp, true)
            .map_err(H2RespmodAdaptationError::HttpClientSendHeadFailed)?;
        state.mark_clt_send_header();
        state.mark_clt_send_no_body();

        Ok(RespmodAdaptationEndState::AdaptedTransferred(http_rsp))
    }

    /// ICAP 返回带 body 的改写响应，且上报侧已终结：单向顺序收尾——
    /// 读改写响应头并发给客户端，再把 ICAP 的 chunked 响应体解码为
    /// h2 数据帧持续写出，全程带 idle 检查；完成后可按 keep-alive 回池。
    pub(super) async fn handle_icap_http_response_with_body_after_transfer<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_header_size: usize,
        orig_http_response: Response<()>,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        let http_rsp =
            HttpAdaptedResponse::parse(&mut self.icap_connection.reader, http_header_size).await?;

        // 头升级回转：原始 h2 响应 + ICAP 改写的 h1 响应头 -> 最终 h2 响应
        let final_rsp = orig_http_response.adapt_to(&http_rsp);
        state.mark_clt_send_start();
        let mut clt_send_stream = clt_send_response
            .send_response(final_rsp, false)
            .map_err(H2RespmodAdaptationError::HttpClientSendHeadFailed)?;
        state.mark_clt_send_header();

        // 下行：ICAP 的 chunked 改写 body -> h2 数据帧（含 trailer 回转）
        let mut body_transfer = H2StreamFromChunkedTransfer::new(
            &mut self.icap_connection.reader,
            &mut clt_send_stream,
            &self.copy_config,
            self.http_body_line_max_size,
            self.http_trailer_max_size,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_clt_send_all();
                            self.icap_connection.mark_reader_finished();
                            if icap_rsp.keep_alive {
                                self.icap_client.save_connection(self.icap_connection);
                            }
                            Ok(RespmodAdaptationEndState::AdaptedTransferred(http_rsp))
                        }
                        Err(H2StreamFromChunkedTransferError::ReadError(e)) => Err(H2RespmodAdaptationError::IcapServerReadFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendDataFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendTrailerFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => Err(H2RespmodAdaptationError::HttpClientNotInSendState),
                    };
                }
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2RespmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H2RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
