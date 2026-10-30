/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! Preview 分支：先只上报响应 body 的前 N 字节，等 ICAP 决定是否放行。
//!
//! Preview 是 ICAP（RFC 3507）的核心优化：当响应很大时，代理不必把整个 body 灌给
//! ICAP 服务器。本文件先从上游读取最多 `preview_size` 字节的"预览体"，随响应头一起
//! 上报（`Encapsulated: req-hdr=0, res-hdr=<请求头长度>, res-body=<请求头长度+响应头长度>`
//! 加 `Preview: <预览字节数>`），然后等待 ICAP 的第一颗回包：
//! - **100 Continue**：ICAP 需要完整内容 → 继续把剩余上游 body 做 chunked 重编码
//!   灌给 ICAP，同时并发读取 ICAP 的最终响应（双向流水线）；
//! - **204**：ICAP 只看预览就判定不改写 → 原样转发，剩余上游 body 直接抄给客户端，
//!   省掉一整段 ICAP 传输；
//! - **200 + Encapsulated**：ICAP 只看预览就给出替代响应 → 丢弃上游剩余 body，
//!   把 ICAP 的响应转给客户端（注意此时响应头已经改写，客户端收到的是 ICAP 的内容）；
//! - **206**：仅部分改写，本库不支持，返回 `NotImplemented`；
//! - 其他：错误响应。
//!
//! 预览读取的两个"提前退出"捷径（省掉一次往返）：
//! - 若预览阶段就把 body 读到了结尾 → 其实没有"剩余部分"，直接改走
//!   `xfer_small_body` / `xfer_small_body_chunked`（一次性全量上报）；
//! - 若 body 为空 → 走 `xfer_without_body`（只报头，可接受 204）；
//! - 若预览数据在 `preview_data_read_timeout` 内一个字节都没读到 → 放弃 preview，
//!   退回 `xfer_without_preview` 全量上报（上游可能在等外部数据，preview 无意义）。
//!
//! chunked 重编码与偏移：三种上游 body 形态（Content-Length / 读到 EOF / chunked）
//! 分别用 `HttpBodyReader::new_fixed_length`、`new_read_until_end`、
//! `ChunkedDataDecodeReader` 读取**解码后**的裸数据作为预览体，再按 chunked 分帧写入
//! ICAP；chunked 场景还需记住"当前 chunk 剩余字节数" `left_chunk_size`，续传时用
//! `H1BodyToChunkedTransfer::new_chunked_after_preview` 从断点接着分块，避免把半个
//! chunk 当成新 chunk 发出。204 分支反向也要重放预览体：客户端收到的 body 必须先补上
//! 已读走的 preview_buf（chunked 场景还要补回 chunk 分帧）。
//!
//! 与 `reqmod::h1::preview` 对称（那边预览的是请求体，这里预览的是响应体），
//! 收尾动作则复用 `recv_response.rs` 与 `bidirectional.rs`。

use std::future::poll_fn;
use std::io::{IoSlice, Write};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use bytes::BufMut;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use g3_http::{ChunkedDataDecodeReader, H1BodyToChunkedTransfer, HttpBodyReader, HttpBodyType};
use g3_io_ext::{IdleCheck, LimitedWriteExt, StreamCopy, StreamCopyError};

use super::{
    BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse, H1RespmodAdaptationError,
    HttpResponseAdapter, HttpResponseClientWriter, HttpResponseForAdaptation,
    RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::h1::HttpRequestForAdaptation;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> HttpResponseAdapter<I> {
    /// 拼装 preview 请求的 ICAP 头块。
    ///
    /// 偏移量与全量上报一致：`res-hdr` = 请求头字节数，`res-body` = 请求头 +
    /// 响应头字节数；额外加 `Preview: <n>` 声明本次实际携带的预览字节数，
    /// 因此 ICAP 服务器知道报文在预览体结束块处就截止了。
    fn build_preview_request(
        &self,
        http_req_hdr_len: usize,
        http_rsp_hdr_len: usize,
        preview_size: usize,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        // do not send `Allow: 204, 206` as we don't want to accept 204/206 after 100-continue
        // 不声明 Allow: 204/206：ICAP 一旦回 100-continue，剩余 body 就必须发完，
        // 此时 204（不改写）已无意义，而 206（只改写一部分）本库并不支持。
        let body_offset = http_req_hdr_len + http_rsp_hdr_len;
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, res-hdr={http_req_hdr_len}, res-body={body_offset}\r\nPreview: {preview_size}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// preview 主流程：读预览体 → 上报 → 按 ICAP 首包（100/204/200/206/其他）分派。
    ///
    /// 阶段一（预览读取）：按上游 body 形态选择 reader，读取最多 `preview_size`
    /// 字节；同时把"剩余未发的 body 长度/形态"换算成新的 `ups_body_type`，供续传用
    /// （Content-Length 要减去已预览的字节数，chunked 要记录当前 chunk 的剩余大小）。
    /// 阶段二（发送 + 收 ICAP 首包）：见 [`Self::send_preview_data`] 与其后的 match。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn xfer_with_preview<R, H, UR, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        ups_body_type: HttpBodyType,
        ups_body_io: &mut UR,
        clt_writer: &mut CW,
        preview_size: usize,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        UR: AsyncBufRead + Unpin,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        // left_chunk_size：chunked 场景下"当前 chunk 还剩多少字节没读完"，续传时要接上
        let mut left_chunk_size = 0;
        let preview_buf: Vec<u8>;
        // 读预览体的同时重算"剩余待上报 body"的形态，供 100-continue 后续传使用
        let ups_body_type = match ups_body_type {
            // 读到 EOF 为止（无 Content-Length 的响应）
            HttpBodyType::ReadUntilEnd => {
                let mut ups_body_reader = HttpBodyReader::new_read_until_end(ups_body_io);
                match self
                    .read_plain_preview_data(
                        &mut ups_body_reader,
                        preview_size,
                        self.icap_client.config.preview_data_read_timeout,
                    )
                    .await
                {
                    Ok(Some(buf)) => preview_buf = buf,
                    Ok(None) => {
                        return self
                            .xfer_without_preview(
                                state,
                                http_request,
                                http_response,
                                ups_body_type,
                                ups_body_io,
                                clt_writer,
                            )
                            .await;
                    }
                    Err(e) => return Err(e),
                }
                // 预览阶段就已读到 EOF：不存在"剩余 body"，改走一次性分支
                if ups_body_reader.finished() {
                    if preview_buf.is_empty() {
                        // 完全没 body → 只报头（此分支可接受 ICAP 回 204）
                        state.mark_ups_recv_no_body();
                        return self
                            .xfer_without_body(state, http_request, http_response, clt_writer)
                            .await;
                    } else {
                        state.mark_ups_recv_all();
                        return self
                            .xfer_small_body(
                                state,
                                http_request,
                                http_response,
                                preview_buf,
                                clt_writer,
                            )
                            .await;
                    }
                }

                HttpBodyType::ReadUntilEnd
            }
            // 定长 body：只需读满 n 字节中的前 preview_size 个
            HttpBodyType::ContentLength(n) => {
                let mut ups_body_reader = HttpBodyReader::new_fixed_length(ups_body_io, n);
                match self
                    .read_plain_preview_data(
                        &mut ups_body_reader,
                        preview_size,
                        self.icap_client.config.preview_data_read_timeout,
                    )
                    .await
                {
                    Ok(Some(buf)) => preview_buf = buf,
                    Ok(None) => {
                        return self
                            .xfer_without_preview(
                                state,
                                http_request,
                                http_response,
                                ups_body_type,
                                ups_body_io,
                                clt_writer,
                            )
                            .await;
                    }
                    Err(e) => return Err(e),
                }
                if ups_body_reader.finished() {
                    state.mark_ups_recv_all();
                    return self
                        .xfer_small_body(
                            state,
                            http_request,
                            http_response,
                            preview_buf,
                            clt_writer,
                        )
                        .await;
                }

                // 续传长度 = 原长度 - 已预览字节数（预览体已随 ICAP 头一起写出）
                HttpBodyType::ContentLength(n - (preview_buf.len() as u64))
            }
            // 上游本身是 chunked：解码掉分帧取裸数据作预览，续传时再重新分帧
            HttpBodyType::Chunked => {
                let mut ups_body_reader =
                    ChunkedDataDecodeReader::new(ups_body_io, self.http_body_line_max_size);
                match self
                    .read_chunked_preview_data(
                        &mut ups_body_reader,
                        preview_size,
                        self.icap_client.config.preview_data_read_timeout,
                    )
                    .await
                {
                    Ok(Some(buf)) => preview_buf = buf,
                    Ok(None) => {
                        return self
                            .xfer_without_preview(
                                state,
                                http_request,
                                http_response,
                                ups_body_type,
                                ups_body_io,
                                clt_writer,
                            )
                            .await;
                    }
                    Err(e) => return Err(e),
                }
                if ups_body_reader.finished() {
                    // chunk 数据已全部读完，剩下的 trailer 也要转写给 ICAP 才不失真
                    let trailer_reader =
                        HttpBodyReader::new_trailer(ups_body_io, self.http_body_line_max_size);
                    return self
                        .xfer_small_body_chunked(
                            state,
                            http_request,
                            http_response,
                            preview_buf,
                            trailer_reader,
                            clt_writer,
                        )
                        .await;
                }
                // 记住"当前 chunk 还剩多少字节没读完"：续传时按此断点继续分块
                left_chunk_size = ups_body_reader.left_chunk_size().ok_or_else(|| {
                    H1RespmodAdaptationError::InternalServerError(
                        "broken chunked encoding after preview read",
                    )
                })?;

                HttpBodyType::Chunked
            }
        };

        // 上报 preview 请求：ICAP 头 + 请求头 + 响应头 + chunked 预览体 + 结束块
        self.send_preview_data(http_request, http_response, &preview_buf)
            .await?;

        // 只等 ICAP 的"首包"：可能是 100-continue，也可能直接就是最终响应
        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            // 100 Continue：ICAP 要看完整内容，续传剩余 body 并等最终响应
            100 => {
                // 按预览后的 body 形态续接 chunked 重编码（长度已扣掉预览字节）
                let mut body_transfer = match ups_body_type {
                    HttpBodyType::ReadUntilEnd => H1BodyToChunkedTransfer::new_read_until_end(
                        ups_body_io,
                        &mut self.icap_connection.writer,
                        self.copy_config,
                    ),
                    HttpBodyType::ContentLength(len) => H1BodyToChunkedTransfer::new_fixed_length(
                        ups_body_io,
                        &mut self.icap_connection.writer,
                        len,
                        self.copy_config,
                    ),
                    // 从预览断点接着分块：先补完当前 chunk 的剩余字节，再切新 chunk
                    HttpBodyType::Chunked => H1BodyToChunkedTransfer::new_chunked_after_preview(
                        ups_body_io,
                        &mut self.icap_connection.writer,
                        left_chunk_size,
                        self.http_body_line_max_size,
                        self.copy_config,
                    ),
                };
                let bidirectional_transfer = BidirectionalRecvIcapResponse {
                    icap_client: &self.icap_client,
                    icap_reader: &mut self.icap_connection.reader,
                    idle_checker: &self.idle_checker,
                };
                // 上行续传与下行读取并发：ICAP 也可能不等我们写完就回最终响应
                let rsp = bidirectional_transfer
                    .transfer_and_recv(&mut body_transfer)
                    .await?;
                if body_transfer.finished() {
                    state.mark_ups_recv_all();
                }

                match rsp.code {
                    // 请求侧未声明 Allow: 204/206，且 body 已在传输，这两个码都是非法响应
                    204 | 206 => {
                        return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                            IcapErrorReason::InvalidResponseAfterContinue,
                            rsp.code,
                            rsp.reason,
                        ));
                    }
                    n if (200..300).contains(&n) => {}
                    _ => {
                        return Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                            IcapErrorReason::UnknownResponseAfterContinue,
                            rsp.code,
                            rsp.reason,
                        ));
                    }
                }
                match rsp.payload {
                    IcapRespmodResponsePayload::NoPayload => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                        }
                        self.icap_connection.mark_reader_finished();
                        self.handle_icap_ok_without_payload(rsp).await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                        }
                        self.handle_icap_http_response_without_body(
                            state,
                            rsp,
                            header_size,
                            http_response,
                            clt_writer,
                        )
                        .await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                            self.handle_icap_http_response_with_body_after_transfer(
                                state,
                                rsp,
                                header_size,
                                http_response,
                                clt_writer,
                            )
                            .await
                        } else {
                            // 上行还没写完就收到带 body 的改写响应：上下行同时推进
                            let icap_keepalive = rsp.keep_alive;
                            let mut bidirectional_transfer = BidirectionalRecvHttpResponse {
                                http_body_line_max_size: self.http_body_line_max_size,
                                copy_config: self.copy_config,
                                idle_checker: &self.idle_checker,
                                http_header_size: header_size,
                                icap_read_finished: false,
                            };
                            let r = bidirectional_transfer
                                .transfer(
                                    state,
                                    &mut body_transfer,
                                    http_response,
                                    &mut self.icap_connection.reader,
                                    clt_writer,
                                )
                                .await?;
                            // 只有上行写完 + 下行读到边界，这条 ICAP 连接才可复用
                            if body_transfer.finished() {
                                state.mark_ups_recv_all();
                                self.icap_connection.mark_writer_finished();
                                if bidirectional_transfer.icap_read_finished {
                                    self.icap_connection.mark_reader_finished();
                                    if icap_keepalive {
                                        self.icap_client.save_connection(self.icap_connection);
                                    }
                                }
                            }
                            Ok(r)
                        }
                    }
                }
            }
            // 204：ICAP 只看预览就判定不改写。上行到此截止（预览体之后不再发），
            // 剩余上游 body 直接抄给客户端，省掉一整段 ICAP 传输。
            204 => {
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }

                state.mark_clt_send_start();
                clt_writer
                    .send_response_header(http_response)
                    .await
                    .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
                state.mark_clt_send_header();

                // 客户端收到的仍是上游原响应：必须先补回已被读走的预览体，再拷剩余 body
                match ups_body_type {
                    HttpBodyType::ReadUntilEnd | HttpBodyType::ContentLength(_) => {
                        self.send_original_plain_body_to_client(
                            rsp,
                            ups_body_type,
                            ups_body_io,
                            clt_writer,
                            preview_buf,
                        )
                        .await?;
                    }
                    HttpBodyType::Chunked => {
                        self.send_original_chunked_body_to_client(
                            rsp,
                            ups_body_io,
                            clt_writer,
                            preview_buf,
                            left_chunk_size,
                        )
                        .await?;
                    }
                }

                state.mark_ups_recv_all();
                state.mark_clt_send_all();

                Ok(RespmodAdaptationEndState::OriginalTransferred)
            }
            // 206 = ICAP 只改写了响应的一部分（例如只换头保留原 body），本库未实现
            206 => Err(H1RespmodAdaptationError::NotImplemented("ICAP-REQMOD-206")),
            // 2xx：ICAP 在预览阶段就给出了完整替代响应，上游剩余 body 直接丢弃
            n if (200..300).contains(&n) => {
                // FIXME we should stop send the pending HTTP body to ICAP server?
                self.icap_connection.mark_writer_finished();
                match rsp.payload {
                    IcapRespmodResponsePayload::NoPayload => {
                        self.icap_connection.mark_reader_finished();
                        self.handle_icap_ok_without_payload(rsp).await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                        self.handle_icap_http_response_without_body(
                            state,
                            rsp,
                            header_size,
                            http_response,
                            clt_writer,
                        )
                        .await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                        self.handle_icap_http_response_with_body_after_transfer(
                            state,
                            rsp,
                            header_size,
                            http_response,
                            clt_writer,
                        )
                        .await
                    }
                }
            }
            // 非 2xx/204/206：ICAP 针对 preview 回了错误响应，只能终止本次适配
            _ => {
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponseForPreview,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }

    /// 读取"非 chunked"上游 body 的预览数据（Content-Length 或读到 EOF）。
    ///
    /// 策略：
    /// 1. 第一口读带 `timeout`（preview 若迟迟没有数据，说明上游也卡住了，
    ///    继续用 preview 没有收益）→ 返回 `Ok(None)`，调用方退化为全量上报；
    /// 2. 之后用 `poll_read` 以"非阻塞"方式把缓冲区填到 `max_size`：一旦 `Pending`
    ///    （暂无更多数据）就立刻收工，绝不等满，这是 preview 低延迟的关键；
    /// 3. 读到 0 字节视为上游结束。
    ///
    /// 返回 `Some(buf)`（长度可小于 `max_size`），buf 就是解码后的裸预览数据。
    async fn read_plain_preview_data<R>(
        &mut self,
        reader: &mut R,
        max_size: usize,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, H1RespmodAdaptationError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = vec![0u8; max_size];
        let mut read_offset;
        match tokio::time::timeout(timeout, reader.read(&mut buf)).await {
            Ok(Ok(n)) => read_offset = n,
            Ok(Err(e)) => return Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
            Err(_) => return Ok(None),
        }

        // 首字节已到：后续只捡"现成可读"的数据填满缓冲区，Pending 即收工（不等待）
        let mut pin_reader = Pin::new(reader);
        while read_offset < max_size {
            let mut read_buf = ReadBuf::new(&mut buf[read_offset..]);
            match poll_fn(
                |cx| match pin_reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Ready(Ok(None)),
                },
            )
            .await
            {
                Ok(Some(0)) => break,
                Ok(Some(n)) => read_offset += n,
                Ok(None) => break,
                Err(e) => return Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
            }
        }

        buf.truncate(read_offset);
        Ok(Some(buf))
    }

    /// 读取"chunked 上游 body"的预览数据（解码分帧后返回裸数据）。
    ///
    /// 与 [`Self::read_plain_preview_data`] 的区别：
    /// - 解码器可能停在"半个 chunk / 半个 CRLF"上，此时不能随意丢弃 future，
    ///   因此只有 `pending_cancel_safe()` 为真（poll 未消耗任何字节，取消是安全的）
    ///   才把 `Pending` 当作"暂时无数据"提前收工，否则继续等待；
    /// - 因为可能真的等下去，这一路额外接入了 `idle_checker`：整个循环持续无进展
    ///   就直接报 `HttpUpstreamReadIdle`，而不是像 plain 版那样靠首口 timeout 兜底。
    async fn read_chunked_preview_data<R>(
        &mut self,
        reader: &mut ChunkedDataDecodeReader<'_, R>,
        max_size: usize,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, H1RespmodAdaptationError>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut buf = vec![0u8; max_size];
        let mut read_offset;
        match tokio::time::timeout(timeout, reader.read(&mut buf)).await {
            Ok(Ok(n)) => read_offset = n,
            Ok(Err(e)) => return Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
            Err(_) => return Ok(None),
        }

        let mut pin_reader = Pin::new(reader);
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;
        let mut is_active = false;

        while read_offset < max_size {
            let mut read_buf = ReadBuf::new(&mut buf[read_offset..]);

            let pin_read = poll_fn(
                |cx| match pin_reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // 只有 poll 没消耗任何字节（取消安全）才敢提前结束预览，
                        // 否则会留下半截 chunk 破坏后续续传的偏移
                        if pin_reader.pending_cancel_safe() {
                            Poll::Ready(Ok(None))
                        } else {
                            Poll::Pending
                        }
                    }
                },
            );

            tokio::select! {
                biased;

                r = pin_read => {
                    match r {
                        Ok(Some(0)) => break,
                        Ok(Some(n)) => {
                            is_active = true;
                            read_offset += n;
                        },
                        Ok(None) => break,
                        Err(e) => return Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                    }
                }
                n = idle_interval.tick() => {
                    if !is_active {
                        idle_count += n;

                        if self.idle_checker.check_quit(idle_count) {
                            return Err(H1RespmodAdaptationError::HttpUpstreamReadIdle);
                        }
                    } else {
                        idle_count = 0;
                        is_active = false;
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }

        buf.truncate(read_offset);
        Ok(Some(buf))
    }

    /// 写出 preview 请求：ICAP 头（含 `Preview: <n>`）+ 请求头 + 响应头 + 预览体。
    ///
    /// 预览体单独占一个 chunk（`<hex 长度>\r\n<data>\r\n`），随后紧跟结束块
    /// `0\r\n\r\n`：这样 ICAP 请求体自身是"合法的完整 chunked 报文"，服务器可以在
    /// 只看这点数据时就回 100/204/200。`Preview: n` 声明的正是这里的 data 长度。
    /// 写完立即 flush，因为接下来要等 ICAP 的首包。
    async fn send_preview_data<R, H>(
        &mut self,
        http_request: &R,
        http_response: &H,
        data: &[u8],
    ) -> Result<(), H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
    {
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();

        // Preview 值取实际读到的字节数（可能小于配置的 preview_size）
        let icap_header =
            self.build_preview_request(http_req_header.len(), http_rsp_header.len(), data.len());

        let chunk_start = format!("{:x}\r\n", data.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
                IoSlice::new(chunk_start.as_bytes()),
                IoSlice::new(data),
                IoSlice::new(b"\r\n0\r\n\r\n"),
            ])
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)
    }

    /// ICAP 回 204 且上游 body 是"非 chunked"：把原响应 body 原样交付客户端。
    ///
    /// 客户端仍按上游原响应头（Content-Length 或读到 EOF）接收，所以这里不做任何
    /// 重编码：先补回预览阶段已读走的 `preview_buf`，再把剩余 body 直接拷贝过去。
    /// 该方向不再经过 ICAP，因此先把 ICAP 连接归还（keep-alive）再慢慢拷 body。
    async fn send_original_plain_body_to_client<CR, UW>(
        self,
        icap_rsp: RespmodResponse,
        ups_body_type: HttpBodyType,
        ups_body_io: &mut CR,
        clt_writer: &mut UW,
        preview_buf: Vec<u8>,
    ) -> Result<(), H1RespmodAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // ICAP 侧已无后续交互，先归还连接再拷 body，避免占用池资源
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        clt_writer
            .write_all(&preview_buf)
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;

        // 原样拷贝剩余 body：保持上游的长度语义，不重新分帧
        let mut clt_body_reader =
            HttpBodyReader::new(ups_body_io, ups_body_type, self.http_body_line_max_size);
        let mut body_copy = StreamCopy::new(&mut clt_body_reader, clt_writer, &self.copy_config);

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_copy => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::HttpClientWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_copy.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_copy.no_cached_data() {
                                Err(H1RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_copy.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// ICAP 回 204 且上游 body 本身是 chunked：客户端也要收到 chunked 流。
    ///
    /// 预览阶段读走的是"解码后"的裸数据，所以这里必须先把 `preview_buf` 重新包成
    /// 一个 chunk（补上 `<hex 长度>\r\n` 头与 `\r\n` 尾），随后用
    /// `new_chunked_after_preview` 从 `left_chunk_size` 断点继续搬运，保证客户端
    /// 看到的 chunk 边界与上游一致、数据不多不少。
    async fn send_original_chunked_body_to_client<CR, UW>(
        self,
        icap_rsp: RespmodResponse,
        ups_body_io: &mut CR,
        clt_writer: &mut UW,
        preview_buf: Vec<u8>,
        left_chunk_size: u64,
    ) -> Result<(), H1RespmodAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        // 把预览体重新包成一个 chunk，补回上游的分帧（客户端要按 chunked 解析）
        let chunk_header = format!("{:x}\r\n", preview_buf.len());
        clt_writer
            .write_all_vectored([
                IoSlice::new(chunk_header.as_bytes()),
                IoSlice::new(&preview_buf),
                IoSlice::new(b"\r\n"),
            ])
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;

        // 从断点续搬：先补完当前 chunk 剩下的 left_chunk_size 字节，再按上游分帧继续
        let mut chunked_transfer = H1BodyToChunkedTransfer::new_chunked_after_preview(
            ups_body_io,
            clt_writer,
            left_chunk_size,
            self.http_body_line_max_size,
            self.copy_config,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut chunked_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::HttpUpstreamReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::HttpClientWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if chunked_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if chunked_transfer.no_cached_data() {
                                Err(H1RespmodAdaptationError::HttpUpstreamReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        chunked_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
