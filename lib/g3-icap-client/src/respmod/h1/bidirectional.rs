/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 双向流水线：一边继续把上游响应 body 发给 ICAP，一边读 ICAP 的响应。
//!
//! RFC 3507 允许 ICAP 服务器在不收完整个请求时就回包（例如提前返回错误，或在
//! preview + 100-continue 之后立刻返回改写结果）。若简单地"先写完再读"，就会
//! 死锁：ICAP 不再读取 socket → 我们写阻塞 → 它也在等我们读。本文件用
//! `tokio::select!` 把两个方向放在同一任务里并发推进，是 RESPMOD 状态机中
//! 唯一"上下行同时进行"的部分，与 `reqmod::h1::bidirectional` 对称。
//!
//! 两个结构体对应流水线的两个阶段：
//! - [`BidirectionalRecvIcapResponse`]：上行 body 还在传，等待 ICAP 的**响应状态**
//!   （100-continue 之后的最终响应，或提前到来的错误响应）；
//! - [`BidirectionalRecvHttpResponse`]：ICAP 已回 200 且带改写后的响应，此时
//!   **上行**（剩余上游 body → ICAP）与**下行**（ICAP 改写 body → 客户端）同时拷贝。
//!
//! 上行 body 一律经 [`g3_http::H1BodyToChunkedTransfer`] 做 chunked 重编码：把
//! 上游的 Content-Length / 无长度 / chunked 三种 body 形态统一成 ICAP 请求体的
//! chunked 分帧；下行则用 `HttpBodyDecodeReader` / `HttpBodyReader` 解掉 chunked
//! 分帧后再写给客户端，客户端收到的长度形态由 ICAP 改写后的响应头决定。
//! 每个 select 循环都带 `idle_checker` 空闲计时：任一方向长时间无进展即按方向
//! 返回对应的 `*Idle` 错误。

use std::sync::Arc;

use anyhow::anyhow;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};

use g3_http::{H1BodyToChunkedTransfer, HttpBodyDecodeReader, HttpBodyReader};
use g3_io_ext::{IdleCheck, LimitedBufReadExt, StreamCopy, StreamCopyConfig, StreamCopyError};

use super::{
    H1RespmodAdaptationError, HttpAdaptedResponse, HttpResponseClientWriter,
    HttpResponseForAdaptation, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::respmod::response::RespmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// 阶段一：上行 body 续传与"等 ICAP 响应"并发。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 并发推进两个 future：`body_transfer`（上游 → ICAP）与 ICAP 读端。
    ///
    /// 谁先完成就返回谁的结果：
    /// - body 先传完 → 继续等 ICAP 响应（此时写端已到达 chunked 结束块）；
    /// - ICAP 先有数据 → 直接解析响应；上行 body 可能尚未传完，由调用方决定后续
    ///   是继续传（见 [`BidirectionalRecvHttpResponse::transfer`]）还是丢弃连接。
    ///
    /// 空闲判定基于 `body_transfer` 自身的活跃度：若上游迟迟不给数据且写端也没有
    /// 积压，报 `HttpUpstreamReadIdle`，否则报 `IcapServerWriteIdle`。
    pub(super) async fn transfer_and_recv<UR>(
        self,
        mut body_transfer: &mut H1BodyToChunkedTransfer<'_, UR, IcapClientWriter>,
    ) -> Result<RespmodResponse, H1RespmodAdaptationError>
    where
        UR: AsyncBufRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_transfer => {
                    return match r {
                        // 上行 body 全部发送完毕，此时才去读 ICAP 的最终响应
                        Ok(_) => self.recv_icap_response().await,
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        // ICAP 提前回包（不等我们写完）：直接解析
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(H1RespmodAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(H1RespmodAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 无积压数据说明卡在"读上游"，否则说明卡在"写 ICAP"
                            return if body_transfer.no_cached_data() {
                                Err(H1RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// 解析 ICAP 响应（状态行 + 头 + `Encapsulated` 载荷描述）。
    async fn recv_icap_response(self) -> Result<RespmodResponse, H1RespmodAdaptationError> {
        let rsp = RespmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;
        Ok(rsp)
    }
}

/// 阶段二：上行"剩余 body → ICAP"与下行"改写 body → 客户端"同时拷贝。
pub(super) struct BidirectionalRecvHttpResponse<'a, I: IdleCheck> {
    pub(super) http_body_line_max_size: usize,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) idle_checker: &'a I,
    /// ICAP 响应中封装的 HTTP 响应头字节数（来自 `Encapsulated: res-hdr=0, res-body=<off>`）。
    pub(super) http_header_size: usize,
    /// 输出标志：下行是否已读到 ICAP 报文边界（决定这条连接能否归还连接池）。
    pub(super) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpResponse<'_, I> {
    /// 接收 ICAP 改写后的响应头，发给客户端，然后进入双向拷贝。
    ///
    /// 时序（100-continue 之后收到 200 的情形）：
    /// 1. 解析封装响应头 → `adapt_with_body` 生成最终响应；
    /// 2. 立即把响应头写给客户端（此时上游剩余 body 还没传完，客户端已开始接收）；
    /// 3. [`Self::do_transfer`] 并发推进两个拷贝方向；
    /// 4. 校验并记录 trailer/结束标志，供调用方决定连接复用。
    ///
    /// body 长度分支：
    /// - `Content-Length = 0` 却带 http-body：协议违例，报错；
    /// - `Content-Length = n`：用 `HttpBodyDecodeReader` 解掉 chunked 分帧，拷贝结束后
    ///   比较解码字节数与 n，并再尝试读 128 字节 trailer 以确认到达边界；
    /// - 无 `Content-Length`：直接用 `HttpBodyReader` 读到 chunked 结束块，天然到达边界。
    pub(super) async fn transfer<H, UR, CW>(
        &mut self,
        state: &mut RespmodAdaptationRunState,
        ups_body_transfer: &mut H1BodyToChunkedTransfer<'_, UR, IcapClientWriter>,
        orig_http_response: &H,
        icap_reader: &mut IcapClientReader,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
        UR: AsyncBufRead + Unpin,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_rsp = HttpAdaptedResponse::parse(icap_reader, self.http_header_size).await?;
        let body_content_length = http_rsp.content_length;

        let final_rsp = orig_http_response.adapt_with_body(http_rsp);
        state.mark_clt_send_start();
        clt_writer
            .send_response_header(&final_rsp)
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
        state.mark_clt_send_header();

        match body_content_length {
            Some(0) => Err(H1RespmodAdaptationError::InvalidHttpBodyFromIcapServer(
                anyhow!("Content-Length is 0 but the ICAP server response contains http-body"),
            )),
            Some(expected) => {
                let mut clt_body_reader =
                    HttpBodyDecodeReader::new_chunked(icap_reader, self.http_body_line_max_size);
                let mut clt_body_transfer =
                    StreamCopy::new(&mut clt_body_reader, clt_writer, &self.copy_config);
                self.do_transfer(ups_body_transfer, &mut clt_body_transfer)
                    .await?;

                state.mark_clt_send_all();
                let copied = clt_body_transfer.copied_size();
                // 尝试吃掉 trailer 行：成功才说明 ICAP 侧报文读到了边界
                if clt_body_reader.trailer(128).await.is_ok() {
                    self.icap_read_finished = true;
                }

                // 解码长度必须与声明的 Content-Length 完全一致
                if copied != expected {
                    return Err(H1RespmodAdaptationError::InvalidHttpBodyFromIcapServer(
                        anyhow!("Content-Length is {expected} but decoded length is {copied}"),
                    ));
                }
                Ok(RespmodAdaptationEndState::AdaptedTransferred(final_rsp))
            }
            None => {
                let mut clt_body_reader =
                    HttpBodyReader::new_chunked(icap_reader, self.http_body_line_max_size);
                let mut clt_body_transfer =
                    StreamCopy::new(&mut clt_body_reader, clt_writer, &self.copy_config);
                self.do_transfer(ups_body_transfer, &mut clt_body_transfer)
                    .await?;

                state.mark_clt_send_all();
                // chunked 读到结束块即代表下行到达报文边界
                self.icap_read_finished = clt_body_transfer.finished();

                Ok(RespmodAdaptationEndState::AdaptedTransferred(final_rsp))
            }
        }
    }

    /// 两个方向都是流式拷贝，任一方完成/出错都要立刻返回。
    ///
    /// - 上行先完成：等下行也收尾后返回（客户端必须拿到完整改写 body）；
    /// - 下行先完成：说明 ICAP 已把改写响应发完，上行剩余的 body 不再有意义，
    ///   由调用方检查 `finished()` 决定是否还能复用 ICAP 连接。
    ///
    /// 空闲判定要求两个方向**同时**无进展才累计计数，报错时再精确指出究竟卡在
    /// 上游读 / ICAP 写 / ICAP 读 / 客户端写哪一个方向。
    async fn do_transfer<UR, IR, CW>(
        &self,
        mut ups_body_transfer: &mut H1BodyToChunkedTransfer<'_, UR, IcapClientWriter>,
        mut clt_body_transfer: &mut StreamCopy<'_, IR, CW>,
    ) -> Result<(), H1RespmodAdaptationError>
    where
        UR: AsyncBufRead + Unpin,
        IR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                r = &mut ups_body_transfer => {
                    return match r {
                        Ok(_) => {
                            // 上行写完，但仍要等改写 body 全部交付客户端
                            match clt_body_transfer.await {
                                Ok(_) => Ok(()),
                                Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::IcapServerReadFailed(e)),
                                Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::HttpClientWriteFailed(e)),
                            }
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = &mut clt_body_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::HttpClientWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    // 两个方向都无进展才累计空闲计数（任一方向在动就说明会话健康）
                    if ups_body_transfer.is_idle() && clt_body_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 逐个方向定位真正卡住的那一端，便于上层判断是谁超时
                            return if ups_body_transfer.is_idle() {
                                if ups_body_transfer.no_cached_data() {
                                    Err(H1RespmodAdaptationError::HttpUpstreamReadIdle)
                                } else {
                                    Err(H1RespmodAdaptationError::IcapServerWriteIdle)
                                }
                            } else if clt_body_transfer.no_cached_data() {
                                Err(H1RespmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        ups_body_transfer.reset_active();
                        clt_body_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
