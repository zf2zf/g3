/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2 双向流处理：在"向上游 ICAP 持续转发 body"的同时读取
//! ICAP 已经返回的响应，两条方向并发、互不阻塞（`tokio::select!` 驱动）。
//!
//! 与 h1 版职责相同，但上行 transfer 的输入是 h2 `RecvStream`（数据帧），
//! 由 `H2StreamToChunkedTransfer` 负责将 h2 body 重新做 chunked 编码后
//! 写入 ICAP 连接；下行 transfer 的输入是 ICAP 返回的 chunked 响应体，
//! 由 `H2StreamFromChunkedTransfer` 解码为 h2 数据帧发给客户端。
//!
//! 两个结构体分别对应两个阶段：
//! - [`BidirectionalRecvIcapResponse`]：ICAP 尚未回最终响应，一边续传
//!   body 一边等它的状态行/头（典型场景：无 preview 全量上报，或 preview
//!   收到 100-continue 之后）；
//! - [`BidirectionalRecvHttpResponse`]：ICAP 已回 2xx 且带改写响应，
//!   但上游 body 还没传完——此时一边把剩余 h2 body 推给 ICAP，一边把
//!   ICAP 改写的 chunked 响应流式发给客户端。

use std::sync::Arc;

use http::Response;

use g3_h2::{
    H2StreamFromChunkedTransfer, H2StreamFromChunkedTransferError, H2StreamToChunkedTransfer,
    H2StreamToChunkedTransferError, ResponseExt,
};
use g3_io_ext::{IdleCheck, LimitedBufReadExt, StreamCopyConfig};

use super::{
    H2RespmodAdaptationError, H2SendResponseToClient, HttpAdaptedResponse,
    RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::response::RespmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// 阶段一：持续把 h2 body（chunked 重编码后）写入 ICAP，同时并发等待
/// ICAP 的最终响应报文。ICAP 通常要收完全部数据才回响应，但也可能提前
/// 出错返回，所以需要 select 并发。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 并发执行"上行 body 续传"与"下行 ICAP 响应接收"，直到其中一个完成。
    ///
    /// 时序：先等 `body_transfer`（写 ICAP）或 `icap_reader` 有可读数据；
    /// 只要 ICAP 读取侧一旦有数据到达（ICAP 提前回了响应），就立即中止
    /// 关注上行、转入解析响应；idle 定时器每触发一次检查两侧是否静止，
    /// 静止累计超限则按"读上游空闲"或"写 ICAP 空闲"报错。
    pub(super) async fn transfer_and_recv(
        self,
        mut body_transfer: &mut H2StreamToChunkedTransfer<'_, IcapClientWriter>,
    ) -> Result<RespmodResponse, H2RespmodAdaptationError> {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                // 上行 body 全部写完（h2 数据流结束 + chunked 终止块已发出）：
                // 此时 ICAP 必然已收到完整请求，转而读取它的响应
                r = &mut body_transfer => {
                    return match r {
                        Ok(_) => self.recv_icap_response().await,
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2RespmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvTrailerFailed(e)),
                    };
                }
                // ICAP 连接上已收到数据：ICAP 提前返回响应（如提前的 200/错误），
                // 无需等 body 传完，直接解析响应
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(H2RespmodAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(H2RespmodAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                // idle 检查：上行传输静止则累计空闲计数，超限后按数据
                // 是否已缓存区分"读上游慢"还是"写 ICAP 慢"；有活动则清零
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H2RespmodAdaptationError::IcapServerWriteIdle)
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

    /// 解析 ICAP 最终响应，并校验状态码。
    ///
    /// 由于本函数只在"已发送 100-continue 之后的续传阶段"或"全量上报"
    /// 场景被调用，204/206 属于非法时序（预览后不允许再返回 204/206），
    /// 其它非 2xx 统一按未知错误响应处理。
    pub(super) async fn recv_icap_response(
        self,
    ) -> Result<RespmodResponse, H2RespmodAdaptationError> {
        let rsp = RespmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            204 | 206 => Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                IcapErrorReason::InvalidResponseAfterContinue,
                rsp.code,
                rsp.reason,
            )),
            n if (200..300).contains(&n) => Ok(rsp),
            _ => Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                IcapErrorReason::UnknownResponseAfterContinue,
                rsp.code,
                rsp.reason,
            )),
        }
    }
}

/// 阶段二：ICAP 返回了带 body 的改写响应（2xx + `HttpResponseWithBody`），
/// 但上游 h2 body 尚未全部传给 ICAP。此时并发做两件事：
/// 1. 继续把剩余 h2 body 以 chunked 编码写给 ICAP（`ups_body_transfer`）；
/// 2. 从 ICAP 连接读取已改写的 chunked 响应头 + body，解码成 h2 数据帧
///    流式发给客户端（`adp_body_transfer`）。
///
/// 这样 ICAP 不必收完全文即可提前返回改写结果，降低整体时延。
pub(super) struct BidirectionalRecvHttpResponse<'a, I: IdleCheck> {
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) http_body_line_max_size: usize,
    pub(super) http_trailer_max_size: usize,
    pub(super) idle_checker: &'a I,
    /// ICAP 响应中封装的改写 HTTP 响应头的长度（偏移量已消费，此处为纯头部长）
    pub(super) http_header_size: usize,
    /// ICAP 侧数据是否已读完，供调用方决定连接能否回池复用
    pub(super) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpResponse<'_, I> {
    /// 先解析 ICAP 封装的改写响应头，把原 h2 响应与之合并（`adapt_to`）
    /// 后发给 h2 客户端，随后进入上/下行双向并发搬运 body 的循环。
    pub(super) async fn transfer<CW>(
        &mut self,
        state: &mut RespmodAdaptationRunState,
        mut ups_body_transfer: &mut H2StreamToChunkedTransfer<'_, IcapClientWriter>,
        orig_http_response: Response<()>,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        // 从 ICAP 连接读取其改写后的 HTTP/1.1 响应头（长度即响应的
        // Encapsulated 偏移中 res-body 之前的部分）
        let http_rsp = HttpAdaptedResponse::parse(self.icap_reader, self.http_header_size).await?;

        // 用改写后的状态/头部覆盖原始 h2 响应，得到最终要发给客户端的 h2 响应
        let final_rsp = orig_http_response.adapt_to(&http_rsp);
        state.mark_clt_send_start();
        let mut clt_send_stream = clt_send_response
            .send_response(final_rsp, false)
            .map_err(H2RespmodAdaptationError::HttpClientSendHeadFailed)?;
        state.mark_clt_send_header();

        // 下行：ICAP 的 chunked 响应体 -> 解码为 h2 数据帧发给客户端
        let mut adp_body_transfer = H2StreamFromChunkedTransfer::new(
            &mut self.icap_reader,
            &mut clt_send_stream,
            &self.copy_config,
            self.http_body_line_max_size,
            self.http_trailer_max_size,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                // 上行：剩余 h2 body 全部以 chunked 写给 ICAP 完成
                // （ICAP 可能仍会继续输出改写结果，需把下行也搬完才算结束）
                r = &mut ups_body_transfer => {
                    return match r {
                        Ok(_) => {
                            match adp_body_transfer.await {
                                Ok(_) => {
                                    state.mark_clt_send_all();
                                    self.icap_read_finished = true;
                                    Ok(RespmodAdaptationEndState::AdaptedTransferred(http_rsp))
                                }
                                Err(H2StreamFromChunkedTransferError::ReadError(e)) => Err(H2RespmodAdaptationError::IcapServerReadFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendDataFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendTrailerFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => Err(H2RespmodAdaptationError::HttpClientNotInSendState),
                            }
                        }
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2RespmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpUpstreamRecvTrailerFailed(e)),
                    };
                }
                // 下行：ICAP 改写响应全部发给客户端完成（上行可能还有残余
                // 数据不再需要，调用方后续视情况丢弃或继续读）
                r = &mut adp_body_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_clt_send_all();
                            self.icap_read_finished = true;
                            Ok(RespmodAdaptationEndState::AdaptedTransferred(http_rsp))
                        }
                        Err(H2StreamFromChunkedTransferError::ReadError(e)) => Err(H2RespmodAdaptationError::IcapServerReadFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendDataFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => Err(H2RespmodAdaptationError::HttpClientSendTrailerFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => Err(H2RespmodAdaptationError::HttpClientNotInSendState),
                    };
                }
                // idle 检查：需上、下两条流同时静止才累计空闲；
                // 超限时按是哪一侧停滞区分四种空闲错误
                n = idle_interval.tick() => {
                    if ups_body_transfer.is_idle() && adp_body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if ups_body_transfer.is_idle() {
                                if ups_body_transfer.no_cached_data() {
                                    Err(H2RespmodAdaptationError::HttpUpstreamReadIdle)
                                } else {
                                    Err(H2RespmodAdaptationError::IcapServerWriteIdle)
                                }
                            } else if adp_body_transfer.no_cached_data() {
                                Err(H2RespmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H2RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        ups_body_transfer.reset_active();
                        adp_body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
