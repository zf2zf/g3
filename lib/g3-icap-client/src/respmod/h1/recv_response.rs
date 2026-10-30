/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 回包的收尾分支：把"原始响应"或"改写后的响应"交付给客户端。
//!
//! 上游 body 已经发送完毕（或本就没有 body）后，各转发分支（`forward_header` /
//! `forward_body` / `preview`）都会把 ICAP 的最终响应交给本文件处理。与
//! `reqmod::h1::recv_response`（处理 ICAP 改写后的**请求**并交给上游）方向相反：
//! 这里的交付对象是客户端，因此需要写响应头 + 拷贝 body。
//!
//! ICAP 响应载荷（`Encapsulated` 头）共三种，对应三个收尾函数：
//! - `NoPayload`：2xx 却没有封装内容 → 协议违例，只能报错（见
//!   [`HttpResponseAdapter::handle_icap_ok_without_payload`]）；
//! - `HttpResponseWithoutBody(res-hdr 长度)` → 只采纳 ICAP 的响应头，客户端不再收 body；
//! - `HttpResponseWithBody(res-hdr 长度)` → 采纳 ICAP 的响应头，并把其 chunked body
//!   解码后写给客户端。
//! 另外 ICAP 回 204（不改写）时，客户端要收到的是上游原响应：无 body 的情形由
//! [`HttpResponseAdapter::handle_original_http_response_without_body`] 只发响应头即可；
//! 带 body 的 204 出现在 preview 分支，剩余 body 的原样搬运在 `preview.rs` 内完成。
//!
//! 关键约束：ICAP 连接只有在**读到了报文边界**（body 的 chunked trailer 读完，或
//! 本就无 body）时才能标记 reader finished 并归还连接池，否则会破坏下一个请求。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_http::{HttpBodyDecodeReader, HttpBodyReader};
use g3_io_ext::{IdleCheck, StreamCopy, StreamCopyError};

use super::{
    H1RespmodAdaptationError, HttpAdaptedResponse, HttpResponseAdapter, HttpResponseClientWriter,
    HttpResponseForAdaptation, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> HttpResponseAdapter<I> {
    /// 处理"2xx 但没有 Encapsulated 载荷"的非法响应。
    ///
    /// RESPMOD 语义下 200 必须携带改写后的响应，缺载荷无法继续，统一按 ICAP 错误
    /// 响应返回（本函数因此永不返回 Ok）。连接是否归还由调用方决定。
    pub(super) async fn handle_icap_ok_without_payload<H>(
        self,
        icap_rsp: RespmodResponse,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a payload
        Err(H1RespmodAdaptationError::IcapServerErrorResponse(
            IcapErrorReason::NoBodyFound,
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// ICAP 回 204（不改写）且原响应无 body：把上游响应头原样发给客户端。
    ///
    /// 这是最快的一条通路——上报内容只有头，因此客户端也只需收到响应头即可结束。
    pub(super) async fn handle_original_http_response_without_body<H, CW>(
        self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_response: &H,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        state.mark_clt_send_start();
        clt_writer
            .send_response_header(http_response)
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
        clt_writer
            .flush()
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
        state.mark_clt_send_header();
        state.mark_clt_send_no_body();

        Ok(RespmodAdaptationEndState::OriginalTransferred)
    }

    /// ICAP 回 200 且改写后的响应**没有 body**：采纳 ICAP 的响应头，发给客户端后结束。
    ///
    /// `http_header_size` 来自 ICAP 响应 `Encapsulated: res-hdr=0, null-body=<off>`
    /// 中的 res-hdr 长度，用于告诉解析器封装响应头占多少字节。
    pub(super) async fn handle_icap_http_response_without_body<H, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_header_size: usize,
        orig_http_response: &H,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_rsp =
            HttpAdaptedResponse::parse(&mut self.icap_connection.reader, http_header_size).await?;
        // 只读头即可到达报文边界，可以安全复用连接
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        // 以原响应为基底，替换成 ICAP 给出的响应头
        let final_rsp = orig_http_response.adapt_without_body(http_rsp);
        state.mark_clt_send_start();
        clt_writer
            .send_response_header(&final_rsp)
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
        clt_writer
            .flush()
            .await
            .map_err(H1RespmodAdaptationError::HttpClientWriteFailed)?;
        state.mark_clt_send_header();
        state.mark_clt_send_no_body();

        Ok(RespmodAdaptationEndState::AdaptedTransferred(final_rsp))
    }

    /// ICAP 回 200 且改写后的响应**带 body**，且上游→ICAP 方向已全部写完。
    ///
    /// 处理步骤：
    /// 1. 解析封装响应头，据此重建要发给客户端的响应（`adapt_with_body`）；
    /// 2. 先写响应头（此后客户端已开始接收，无法再回退为"原样转发"）；
    /// 3. 按响应头声明的长度拷贝 body：
    ///    - `Content-Length = 0` 却带 body → 协议违例，直接报错；
    ///    - `Content-Length = n` → 用 `HttpBodyDecodeReader` 解码 ICAP 侧的 chunked
    ///      流，拷贝后校验解码长度是否恰为 n，并尝试读取 trailer 以判定能否复用连接；
    ///    - 无 `Content-Length` → ICAP 侧 body 以 chunked 结束（`0\r\n\r\n`），
    ///      读到结束即代表到达边界，拷贝完成后可复用连接。
    pub(super) async fn handle_icap_http_response_with_body_after_transfer<H, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        icap_rsp: RespmodResponse,
        http_header_size: usize,
        orig_http_response: &H,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_rsp =
            HttpAdaptedResponse::parse(&mut self.icap_connection.reader, http_header_size).await?;
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
                // ICAP 请求体统一用 chunked 承载，这里解码掉 chunk 分帧再写给客户端
                let mut body_reader = HttpBodyDecodeReader::new_chunked(
                    &mut self.icap_connection.reader,
                    self.http_body_line_max_size,
                );
                let mut body_copy =
                    StreamCopy::new(&mut body_reader, clt_writer, &self.copy_config);
                Self::send_response_body(&self.idle_checker, &mut body_copy).await?;

                state.mark_clt_send_all();
                let copied = body_copy.copied_size();

                // 读掉可能的 trailer（上限 128 字节）：成功才说明到达报文边界
                if body_reader.trailer(128).await.is_ok() {
                    self.icap_connection.mark_reader_finished();
                    if icap_rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }

                // 解码长度与声明的 Content-Length 必须一致，否则客户端会看到截断/超发的响应
                if copied != expected {
                    return Err(H1RespmodAdaptationError::InvalidHttpBodyFromIcapServer(
                        anyhow!("Content-Length is {expected} but decoded length is {copied}"),
                    ));
                }
                Ok(RespmodAdaptationEndState::AdaptedTransferred(final_rsp))
            }
            None => {
                // 无 Content-Length：以 chunked 结束块作为报文边界，边解边转发
                let mut body_reader = HttpBodyReader::new_chunked(
                    &mut self.icap_connection.reader,
                    self.http_body_line_max_size,
                );
                let mut body_copy =
                    StreamCopy::new(&mut body_reader, clt_writer, &self.copy_config);
                Self::send_response_body(&self.idle_checker, &mut body_copy).await?;

                state.mark_clt_send_all();
                self.icap_connection.mark_reader_finished();
                if icap_rsp.keep_alive {
                    self.icap_client.save_connection(self.icap_connection);
                }
                Ok(RespmodAdaptationEndState::AdaptedTransferred(final_rsp))
            }
        }
    }

    /// 带空闲保护的"ICAP body → 客户端"单方向拷贝。
    ///
    /// 拷贝本身由 [`StreamCopy`] 驱动；这里只在它长时间无进展时按"卡在读 ICAP 还是
    /// 卡在读端"归类为 `IcapServerReadIdle` / `HttpClientWriteIdle`。
    async fn send_response_body<R, W>(
        idle_checker: &I,
        mut body_copy: &mut StreamCopy<'_, R, W>,
    ) -> Result<(), H1RespmodAdaptationError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut idle_interval = idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_copy => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1RespmodAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1RespmodAdaptationError::HttpClientWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_copy.is_idle() {
                        idle_count += n;

                        let quit = idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_copy.no_cached_data() {
                                Err(H1RespmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H1RespmodAdaptationError::HttpClientWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_copy.reset_active();
                    }

                    if let Some(reason) = idle_checker.check_force_quit() {
                        return Err(H1RespmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
