/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 与 ICAP 之间的双向流水线（同一连接上"边写边读"）。
//!
//! ICAP 是单条 TCP 连接，REQMOD 上报 body 与接收响应在时间上是重叠的：
//! 服务端往往在 body 传完之前就能给出 200 改写结果（或 100-continue 之后的
//! 最终响应）。如果串行执行就会死锁式互等：
//! - 我们等 ICAP 收完 body 才回响应，ICAP 等我们继续发 body；
//! - 或上游写速跟不上，body 缓冲区堆满无法继续读客户端。
//! 因此这里用 `tokio::select!` 同时推进"向 ICAP 写剩余 body"和"读 ICAP 响应"
//! 两个 future，谁先完成就按谁的结果继续。两个结构分别对应状态机两处需求：
//! - `BidirectionalRecvIcapResponse`：只等 ICAP 的响应头（preview 100 之后、
//!   以及全量上报时），因为此时还不知道 ICAP 会不会带封装内容；
//! - `BidirectionalRecvHttpRequest`：ICAP 已返回改写后的请求（带 body），
//!   于是一边向 ICAP 续传客户端剩余 body，一边把改写后的 body 搬给真实上游。
//!
//! 空闲处理约定（各 select 循环一致）：只有当被监视的一侧在本轮 interval 内
//! 完全无进展时才累加 idle_count，由 `check_quit` 决定是否超时；
//! `check_force_quit` 则无条件立即退出。
//! `no_cached_data()` 用来区分卡在哪一侧，从而返回准确方向的 idle 错误。

use std::sync::Arc;

use anyhow::anyhow;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};

use g3_http::{H1BodyToChunkedTransfer, HttpBodyDecodeReader, HttpBodyReader};
use g3_io_ext::{IdleCheck, LimitedBufReadExt, StreamCopy, StreamCopyConfig, StreamCopyError};

use super::{
    H1ReqmodAdaptationError, HttpAdaptedRequest, HttpRequestForAdaptation,
    HttpRequestUpstreamWriter, ReqmodAdaptationEndState, ReqmodAdaptationRunState,
};
use crate::reqmod::response::ReqmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// 一边把客户端剩余 body 以 chunked 写给 ICAP，一边等 ICAP 的响应头。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 续传 body 与接收响应头并行推进，返回 ICAP 响应。
    ///
    /// 两条 IO 路径谁先结束就先返回结果：
    /// - body 传完 → 继续等响应（此时只剩读，转为 recv_icap_response）；
    /// - ICAP 先把响应发回来（可能提前给出最终结果）→ 立即解析响应，
    ///   调用方据此决定是否还需要把剩余 body 写完/丢弃。
    /// 读侧 `Ok(false)` 表示 ICAP 关闭连接，不能当作空响应处理。
    pub(super) async fn transfer_and_recv<CR>(
        self,
        mut body_transfer: &mut H1BodyToChunkedTransfer<'_, CR, IcapClientWriter>,
    ) -> Result<ReqmodResponse, H1ReqmodAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_transfer => {
                    return match r {
                        Ok(_) => self.recv_icap_response().await,
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::HttpClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(H1ReqmodAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(H1ReqmodAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_transfer.no_cached_data() {
                                Err(H1ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H1ReqmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// 从 ICAP 连接读取并解析响应头（含 Encapsulated 偏移与共享头）。
    async fn recv_icap_response(self) -> Result<ReqmodResponse, H1ReqmodAdaptationError> {
        let rsp = ReqmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;
        Ok(rsp)
    }
}

/// 一边向 ICAP 续传客户端剩余 body，一边接收 ICAP 改写后的 HTTP 请求转给上游。
pub(super) struct BidirectionalRecvHttpRequest<'a, I: IdleCheck> {
    pub(super) http_body_line_max_size: usize,
    pub(super) http_req_add_no_via_header: bool,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) idle_checker: &'a I,
    /// ICAP 响应中封装的改写请求头的字节数（Encapsulated 的 res-/req-hdr 偏移）。
    pub(crate) http_header_size: usize,
    /// 改写请求的 body（含 trailer）是否已全部读完，决定 ICAP 连接能否回池。
    pub(crate) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpRequest<'_, I> {
    /// 接收改写后的请求：先解析头并写给上游，再并行搬运两路 body。
    ///
    /// 时序要求：改写后的请求头必须先于 body 到达上游，所以这里
    /// 先 `send_request_header(&final_req)`，之后才开始搬运。
    /// ICAP 封装的 body 一定是 chunked；改写请求头里的 Content-Length 表示
    /// "期望的解码长度"，因此用 HttpBodyDecodeReader 解码并逐字节校验
    /// （`copied != expected` 即为 ICAP 服务实现有 bug）。
    /// 没有 Content-Length 时只能信任 chunked 边界，读到结束块为止，
    /// 此时 ICAP 连接是否干净由 `ups_body_transfer.finished()` 判断。
    pub(super) async fn transfer<H, CR, UW>(
        &mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_body_transfer: &mut H1BodyToChunkedTransfer<'_, CR, IcapClientWriter>,
        orig_http_request: &H,
        icap_reader: &mut IcapClientReader,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        CR: AsyncBufRead + Unpin,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_req = HttpAdaptedRequest::parse(
            icap_reader,
            self.http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        let body_content_length = http_req.content_length;

        let final_req = orig_http_request.adapt_with_body(http_req);
        ups_writer
            .send_request_header(&final_req)
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        state.mark_ups_send_header();

        match body_content_length {
            Some(0) => Err(H1ReqmodAdaptationError::InvalidHttpBodyFromIcapServer(
                anyhow!("Content-Length is 0 but the ICAP server response contains http-body"),
            )),
            Some(expected) => {
                let mut ups_body_reader =
                    HttpBodyDecodeReader::new_chunked(icap_reader, self.http_body_line_max_size);
                let mut ups_body_transfer =
                    StreamCopy::new(&mut ups_body_reader, ups_writer, &self.copy_config);
                self.do_transfer(clt_body_transfer, &mut ups_body_transfer)
                    .await?;

                state.mark_ups_send_all();
                let copied = ups_body_transfer.copied_size();
                // 读完 chunked 结束块后的 trailer（给一个小上限即可）；
                // 失败说明 ICAP 侧还有残留数据，本连接不能回池
                if ups_body_reader.trailer(128).await.is_ok() {
                    self.icap_read_finished = true;
                }

                if copied != expected {
                    return Err(H1ReqmodAdaptationError::InvalidHttpBodyFromIcapServer(
                        anyhow!("Content-Length is {expected} but decoded length is {copied}"),
                    ));
                }
                Ok(ReqmodAdaptationEndState::AdaptedTransferred(final_req))
            }
            None => {
                let mut ups_body_reader =
                    HttpBodyReader::new_chunked(icap_reader, self.http_body_line_max_size);
                let mut ups_body_transfer =
                    StreamCopy::new(&mut ups_body_reader, ups_writer, &self.copy_config);
                self.do_transfer(clt_body_transfer, &mut ups_body_transfer)
                    .await?;

                state.mark_ups_send_all();
                self.icap_read_finished = ups_body_transfer.finished();

                Ok(ReqmodAdaptationEndState::AdaptedTransferred(final_req))
            }
        }
    }

    /// 同时推进"写 ICAP 剩余 body"与"读 ICAP 改写 body 转上游"两条流。
    ///
    /// 任一条先结束就返回：
    /// - 客户端 body 先传完 → 剩余时间专注搬运改写后的 body（继续 await 另一侧）；
    /// - 改写 body 先搬完 → 直接返回，调用方按情况决定客户端剩余数据怎么办
    ///   （preview/forward_body 分支中会检查 finished() 再标记写侧结束）。
    /// 只有两条流同时无进展才累加空闲计数，避免"一路忙一路闲"被误判超时。
    async fn do_transfer<CR, IR, UW>(
        &self,
        mut clt_body_transfer: &mut H1BodyToChunkedTransfer<'_, CR, IcapClientWriter>,
        mut ups_body_transfer: &mut StreamCopy<'_, IR, UW>,
    ) -> Result<(), H1ReqmodAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
        IR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                r = &mut clt_body_transfer => {
                    return match r {
                        Ok(_) => {
                            match ups_body_transfer.await {
                                Ok(_) => Ok(()),
                                Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerReadFailed(e)),
                                Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed(e)),
                            }
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::HttpClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = &mut ups_body_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if clt_body_transfer.is_idle() && ups_body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if clt_body_transfer.is_idle() {
                                if clt_body_transfer.no_cached_data() {
                                    Err(H1ReqmodAdaptationError::HttpClientReadIdle)
                                } else {
                                    Err(H1ReqmodAdaptationError::IcapServerWriteIdle)
                                }
                            } else if ups_body_transfer.no_cached_data() {
                                Err(H1ReqmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H1ReqmodAdaptationError::HttpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        clt_body_transfer.reset_active();
                        ups_body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
