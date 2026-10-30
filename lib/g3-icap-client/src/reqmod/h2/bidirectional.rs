/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! h2 REQMOD 的双向流处理：客户端 body 上报与 ICAP 响应接收**并发**进行。
//!
//! 与 h1 版的差异在于两端搬运的"字节流"性质：
//! - 上行：`H2StreamToChunkedTransfer` 把 h2 `RecvStream` 的数据帧重编码为
//!   chunked 写入 ICAP 连接（含 h2 trailer → chunked trailer）；
//! - 下行：ICAP 若在 body 未发完时就回响应，改写请求的 body 是 chunked，
//!   需用 `H2StreamFromChunkedTransfer` 解码回 h2 数据帧写入上游流。
//!
//! 因此这里用 `tokio::select!` 同时轮询 2~3 个 future（ICAP 读、上行 body
//! 搬运、下行 body 搬运）+ idle 定时器，任一方先完成都要正确收尾，
//! 避免出现"ICAP 还在等 body、我们已把连接收回"的半截状态。
//!
//! 两个结构体的分工：
//! - `BidirectionalRecvIcapResponse`：只负责"发 body 的同时等 ICAP 最终响应头"；
//! - `BidirectionalRecvHttpRequest`：进一步在收到"带 body 的改写请求"后，
//!   继续把 ICAP 的 chunked body 转给上游，同时把客户端剩余 body 转给 ICAP。

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use http::Request;

use g3_h2::{
    H2StreamFromChunkedTransfer, H2StreamFromChunkedTransferError, H2StreamToChunkedTransfer,
    H2StreamToChunkedTransferError, RequestExt,
};
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::{IdleCheck, LimitedBufReadExt, StreamCopyConfig};

use super::recv_request::recv_ups_response_head_after_transfer;
use super::{H2ReqmodAdaptationError, ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// "边上报 body 边等 ICAP 响应头"的并发协程（响应到达即结束）。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 并发执行：把 `body_transfer`（h2 → chunked）搬到 ICAP 连接，
    /// 同时等 ICAP 把响应头推过来，谁先完成谁胜出。
    ///
    /// 注意时序：ICAP 完全可以在收到 preview 或全部 body 之前就回响应，
    /// 此时 `fill_wait_data` 分支会先返回 —— 若响应"不需要剩余 body"
    /// （如直接回 HTTP 错误响应），调用方可以提前结束上行搬运。
    pub(super) async fn transfer_and_recv(
        self,
        mut body_transfer: &mut H2StreamToChunkedTransfer<'_, IcapClientWriter>,
    ) -> Result<ReqmodResponse, H2ReqmodAdaptationError> {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                // biased: 优先处理搬运/读取，idle 定时器排最后
                biased;

                // 上行 body 搬运完毕：此时 ICAP 已收到完整请求，必定会给最终响应
                r = &mut body_transfer => {
                    return match r {
                        Ok(_) => self.recv_icap_response().await,
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2ReqmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvTrailerFailed(e)),
                    };
                }
                // ICAP 连接上出现可读数据：提前进入响应解析
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(H2ReqmodAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(H2ReqmodAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                // idle 判定：只有搬运器自身也处于"没在干活"时才累计，
                // 累计次数达到阈值则按"缓存里是否还有未写出的数据"区分
                // 卡住的到底是"读客户端"还是"写 ICAP"
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H2ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H2ReqmodAdaptationError::IcapServerWriteIdle)
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
    }

    /// 解析 ICAP 响应头（状态行 + 头 + Encapsulated 语义 + 共享头提取）。
    async fn recv_icap_response(self) -> Result<ReqmodResponse, H2ReqmodAdaptationError> {
        let rsp = ReqmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;
        Ok(rsp)
    }
}

/// "ICAP 返回带 body 的改写请求、而客户端 body 还没发完"时的三向并发搬运。
///
/// 此时链路上同时存在三个流：
/// 1. 客户端 h2 body → chunked → ICAP（`clt_body_transfer`，由调用方持有）；
/// 2. ICAP 的 chunked body → h2 数据帧 → 上游（本结构的 `ups_body_transfer`）；
/// 3. 上游响应头（`ups_recv_rsp`，h2 允许响应先到）。
///
/// `icap_read_finished` 用于把"ICAP 连接是否已被读干净"这一内部状态回传给
/// 调用方，调用方据此决定能否 `mark_reader_finished` / 归还连接到池。
pub(super) struct BidirectionalRecvHttpRequest<'a, I: IdleCheck> {
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) http_body_line_max_size: usize,
    pub(super) http_trailer_max_size: usize,
    pub(super) http_rsp_head_recv_timeout: Duration,
    pub(super) http_req_add_no_via_header: bool,
    pub(super) idle_checker: &'a I,
    // ICAP 响应中封装的改写请求头的字节数，即 HttpAdaptedRequest::parse 的读取上限
    pub(super) http_header_size: usize,
    // 输出参数：ICAP 侧（含改写请求 body）是否已全部读完
    pub(super) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpRequest<'_, I> {
    /// 先解析 ICAP 的改写请求头，把它降级转成 h2 请求发给上游，
    /// 然后并发搬运"客户端 → ICAP"与"ICAP → 上游"两条 body 通路。
    pub(super) async fn transfer(
        &mut self,
        state: &mut ReqmodAdaptationRunState,
        mut clt_body_transfer: &mut H2StreamToChunkedTransfer<'_, IcapClientWriter>,
        orig_http_request: Request<()>,
        mut ups_send_request: SendRequest<Bytes>,
    ) -> Result<ReqmodAdaptationEndState, H2ReqmodAdaptationError> {
        // 只读取 http_header_size 字节（改写请求头的长度），之后连接上剩下的
        // 就是 chunked 形式的改写请求 body
        let http_req = HttpAdaptedRequest::parse(
            self.icap_reader,
            self.http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;

        // 用改写后的 method/uri/头去适配原 h2 请求（保留原 :authority 与 TE）
        let final_req = orig_http_request.adapt_to(&http_req);
        let (mut ups_recv_rsp, mut ups_send_stream) = ups_send_request
            .send_request(final_req, false)
            .map_err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed)?;
        state.mark_ups_send_header();

        // ICAP 的 chunked body → h2 数据帧（end_of_stream 先不置位，由搬运器判定）
        let mut ups_body_transfer = H2StreamFromChunkedTransfer::new(
            &mut self.icap_reader,
            &mut ups_send_stream,
            &self.copy_config,
            self.http_body_line_max_size,
            self.http_trailer_max_size,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                // 上游响应头先到达：h2 允许在请求 body 未发完时就回响应，
                // 此时直接结束（剩余搬运交给调用方按需处理）
                r = &mut ups_recv_rsp => {
                    return match r {
                        Ok(ups_rsp) => {
                            state.mark_ups_recv_header();
                            if ups_body_transfer.finished() {
                                self.icap_read_finished = true;
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred(http_req, ups_rsp))
                        }
                        Err(e) => Err(H2ReqmodAdaptationError::HttpUpstreamRecvResponseFailed(e)),
                    };
                }
                // 客户端 body 先搬完：把 trailer 之后剩下的 ICAP → 上游方向读完再收尾
                r = &mut clt_body_transfer => {
                    return match r {
                        Ok(_) => {
                            match ups_body_transfer.await {
                                Ok(_) => {
                                    state.mark_ups_send_all();
                                    self.icap_read_finished = true;
                                    let ups_rsp = recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout).await?;
                                    Ok(ReqmodAdaptationEndState::AdaptedTransferred(http_req, ups_rsp))
                                }
                                Err(H2StreamFromChunkedTransferError::ReadError(e)) => Err(H2ReqmodAdaptationError::IcapServerReadFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => Err(H2ReqmodAdaptationError::HttpUpstreamSendDataFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => Err(H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed(e)),
                                Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => Err(H2ReqmodAdaptationError::HttpUpstreamNotInSendState),
                            }
                        }
                        Err(H2StreamToChunkedTransferError::WriteError(e)) => Err(H2ReqmodAdaptationError::IcapServerWriteFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvDataFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvDataFailed(e)),
                        Err(H2StreamToChunkedTransferError::RecvTrailerFailed(e)) => Err(H2ReqmodAdaptationError::HttpClientRecvTrailerFailed(e)),
                    };
                }
                // ICAP 的改写 body 先读完：客户端方向若还剩数据，由调用方决定是否继续搬
                r = &mut ups_body_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_ups_send_all();
                            self.icap_read_finished = true;
                            let ups_rsp = recv_ups_response_head_after_transfer(ups_recv_rsp, self.http_rsp_head_recv_timeout).await?;
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred(http_req, ups_rsp))
                        }
                        Err(H2StreamFromChunkedTransferError::ReadError(e)) => Err(H2ReqmodAdaptationError::IcapServerReadFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendDataFailed(e)) => Err(H2ReqmodAdaptationError::HttpUpstreamSendDataFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SendTrailerFailed(e)) => Err(H2ReqmodAdaptationError::HttpUpstreamSendTrailedFailed(e)),
                        Err(H2StreamFromChunkedTransferError::SenderNotInSendState) => Err(H2ReqmodAdaptationError::HttpUpstreamNotInSendState),
                    };
                }
                // 两条搬运通路都空闲才累计 idle；任一条在动就同时复位两者
                n = idle_interval.tick() => {
                    if clt_body_transfer.is_idle() && ups_body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if clt_body_transfer.is_idle() {
                                if clt_body_transfer.no_cached_data() {
                                    Err(H2ReqmodAdaptationError::HttpClientReadIdle)
                                } else {
                                    Err(H2ReqmodAdaptationError::IcapServerWriteIdle)
                                }
                            } else if ups_body_transfer.no_cached_data() {
                                Err(H2ReqmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H2ReqmodAdaptationError::HttpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        clt_body_transfer.reset_active();
                        ups_body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H2ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
