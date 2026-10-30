/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP APPEND literal 的传输实现（无 preview 的 REQMOD 流程）。
//!
//! 封装后的 ICAP 请求整体形如：
//! ```text
//! REQMOD * ICAP/1.0\r\n
//! X-Transformed-From: IMAP\r\n
//! X-Client-IP: <客户端地址>\r\n              // 可选扩展头
//! X-Client-Port: <客户端端口>\r\n            // 可选扩展头
//! Allow: 204\r\n                             // 可选：内容已完整缓存且服务端支持 204
//! Encapsulated: req-hdr=0, req-body=<HTTP头长度>\r\n
//! \r\n
//! # ---- 以下为 ICAP 请求体，即被封装的伪 HTTP 报文 ----
//! # [req-hdr] 从偏移 0 开始（头部末尾的空行也计入 req-hdr）
//! PUT / HTTP/1.1\r\n
//! Content-Type: message/rfc822\r\n
//! Content-Length: <literal_size>\r\n
//! \r\n
//! # [req-body] 从偏移 <HTTP头长度> 开始
//! <literal_size 的小写十六进制>\r\n           // chunked 块长度行，手工写入
//! <literal 邮件内容>                           // 整段作为单个 chunk 上报
//! \r\n0\r\n\r\n                                // 结束块
//! ```
//! `Encapsulated:` 的偏移量相对 ICAP 头之后的报文起点：`req-hdr=0` 表示伪 HTTP
//! 头从第 0 字节开始，`req-body=<HTTP头长度>` 表示正文紧接头部之后。
//!
//! 两条路径按"literal 是否已完整缓存在内存中"区分（选择逻辑见 `xfer_append`）：
//! - `xfer_append_once`：literal 已完整缓存，把 ICAP 头 + HTTP 头 + chunked 块
//!   + 全部内容 + 结束块**一次性**写出并 flush，然后纯等待响应。因为请求已完整
//!   送达，可以拿到 **204（未修改）** 直接原样写入上游，无需双向并发。
//! - `xfer_append_without_preview`：缓存不足，还需从客户端继续读 `read_size`
//!   字节。此时"继续发正文"与"等 ICAP 响应"必须并发（见 `bidirectional` 子模块），
//!   否则容易死锁；响应若在正文发完前到达，剩余的发送与改写正文的接收会同时推进。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use g3_io_ext::{IdleCheck, LimitedWriteExt, StreamCopy};

use super::{HttpAdapterErrorResponse, ImapAdaptationError, ImapMessageAdapter};
use crate::reqmod::IcapReqmodResponsePayload;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;

// 边发正文边收响应 / 边收改写后正文的两路并发收发实现
mod bidirectional;
use bidirectional::{BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse};

// 响应中携带"改写后的伪 HTTP 请求"（200 替换原邮件）时的处理
mod recv_request;
// 响应中携带"替代 HTTP 错误响应"或无载荷时的处理
mod recv_response;

impl<I: IdleCheck> ImapMessageAdapter<I> {
    /// 拼装 ICAP 请求头（REQMOD + 扩展头 + 可选 Allow + Encapsulated 偏移表）。
    ///
    /// `http_header_len` 是伪 HTTP 头的字节数，等于 req-body 相对报文起点的偏移。
    /// `all_cached` 表示整段 literal 都已在内存中、本次请求可以一口气发完，
    /// 此时若服务端 OPTIONS 声明支持 204，就加上 `Allow: 204`，
    /// 让 ICAP 有机会用**零载荷**的 204 表示"邮件无需修改"，最省带宽。
    fn build_forward_all_request(&self, http_header_len: usize, all_cached: bool) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        // 预生成好的 "REQMOD * ICAP/1.0\r\n" + 方法名/服务名等公共部分
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        if self.icap_options.support_204 && all_cached {
            header.put_slice(b"Allow: 204\r\n");
        }
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, req-body={http_header_len}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 生成 chunked 传输编码的块长度行：`<literal_size 的小写十六进制>\r\n`。
    ///
    /// IMAP literal 长度已知且内容已在内存，因此整段邮件可以作为**单个 chunk**
    /// 上报，无需像 SMTP 那样边读边分块。
    fn build_chunked_header(&self) -> String {
        format!("{:x}\r\n", self.literal_size)
    }

    /// literal 已完整缓存时的一次性上报路径。
    ///
    /// 写出顺序（一次 vectored write，零拷贝拼接）：
    /// ICAP 头 → 伪 HTTP 头 → chunked 块长度行 → 全部缓存数据 → 结束块 `0\r\n\r\n`，
    /// 随后 flush 并标记写结束，接着**单向**等待 ICAP 响应。
    pub async fn xfer_append_once<UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        cached: &[u8],
        ups_w: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError>
    where
        UW: AsyncWrite + Unpin,
    {
        let http_header = self.build_http_header();
        let icap_header = self.build_forward_all_request(http_header.len(), true);
        // TODO support 204
        let chunked_header = self.build_chunked_header();

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_header),
                IoSlice::new(chunked_header.as_bytes()),
                IoSlice::new(cached),
                IoSlice::new(b"\r\n0\r\n\r\n"),
            ])
            .await
            .map_err(ImapAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(ImapAdaptationError::IcapServerWriteFailed)?;
        // 整个请求已发出，写方向不再有数据
        self.icap_connection.mark_writer_finished();

        let rsp = ReqmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;

        match rsp.code {
            204 => {
                // 204：ICAP 未做任何修改，直接把原始缓存内容写给上游
                self.icap_connection.mark_reader_finished();
                if rsp.keep_alive {
                    self.icap_client.save_connection(self.icap_connection);
                }

                ups_w
                    .write_all(cached)
                    .await
                    .map_err(ImapAdaptationError::ImapUpstreamWriteFailed)?;
                Ok(ReqmodAdaptationEndState::OriginalTransferred)
            }
            206 => Err(ImapAdaptationError::IcapServerErrorResponse(
                rsp.code, rsp.reason,
            )),
            n if (200..300).contains(&n) => match rsp.payload {
                IcapReqmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    self.handle_icap_ok_without_payload(rsp).await
                }
                IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                    self.handle_icap_http_request_without_body(state, rsp, header_size)
                        .await
                }
                IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                    // 请求已发完，可以安静地接收被改写后的邮件
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        ups_w,
                    )
                    .await
                }
                IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                    .handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None)),
                IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                    .handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))),
            },
            _ => {
                // 非 2xx：只有确认没有载荷残留时才需要把连接读干净并归还
                if rsp.payload == IcapReqmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(ImapAdaptationError::IcapServerErrorResponse(
                    rsp.code, rsp.reason,
                ))
            }
        }
    }

    /// literal 未完整缓存时的流式续传路径。
    ///
    /// `cached` 是已缓存的前缀，`read_size` 是还需从客户端读取的字节数
    /// （由 `xfer_append` 计算：`literal_size - cached.len()`）。
    /// 已缓存部分先随头部一起发出，剩余部分交给 `StreamCopy` 边读边写，
    /// 同时并发等待 ICAP 响应。
    pub async fn xfer_append_without_preview<CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        cached: &[u8],
        read_size: u64,
        ups_w: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let http_header = self.build_http_header();
        // all_cached=false：请求不能一次发完，故不带 Allow: 204
        let icap_header = self.build_forward_all_request(http_header.len(), false);
        // 注意：即使数据被拆成"已缓存 + 后续读取"两部分发送，块长度行仍然
        // 一次写满 literal_size，由 ICAP 的 chunked 编码器按该长度连续输出，
        // 所以后续只需追加裸数据，不再写新的长度行。
        let chunked_header = self.build_chunked_header();

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_header),
                IoSlice::new(chunked_header.as_bytes()),
                IoSlice::new(cached),
            ])
            .await
            .map_err(ImapAdaptationError::IcapServerWriteFailed)?;

        // take(read_size) 保证不会多读 literal 之后的 IMAP 命令数据
        let mut message_reader = clt_r.take(read_size);
        let mut body_transfer = StreamCopy::new(
            &mut message_reader,
            &mut self.icap_connection.writer,
            &self.copy_config,
        );

        // 一边继续发剩余正文，一边等 ICAP 响应
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        let rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        if body_transfer.finished() {
            state.clt_read_finished = true;
        }

        match rsp.payload {
            IcapReqmodResponsePayload::NoPayload => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_request_without_body(state, rsp, header_size)
                    .await
            }
            IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                if body_transfer.finished() {
                    // 正文已全部发出，转为单向接收被改写后的邮件
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        ups_w,
                    )
                    .await
                } else {
                    // 正文还没发完 ICAP 就返回了改写结果：
                    // 剩余正文与响应正文必须同时推进
                    let mut bidirectional_transfer = BidirectionalRecvHttpRequest {
                        icap_reader: &mut self.icap_connection.reader,
                        copy_config: self.copy_config,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        // 用于核对 ICAP 返回的邮件长度是否与 literal 一致
                        imap_message_size: self.literal_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(state, &mut body_transfer, ups_w)
                        .await?;
                    let icap_read_finished = bidirectional_transfer.icap_read_finished;
                    if body_transfer.finished() {
                        if message_reader.limit() == 0 {
                            // take() 的配额已用尽，说明 literal 的字节全部读完并发出
                            state.clt_read_finished = true;
                        }
                        self.icap_connection.mark_writer_finished();
                        if icap_read_finished {
                            // 收发两侧都干净结束，这条 ICAP 连接才可能复用
                            self.icap_connection.mark_reader_finished();
                            if rsp.keep_alive {
                                self.icap_client.save_connection(self.icap_connection);
                            }
                        }
                    }
                    Ok(r)
                }
            }
            IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                // ICAP 用一段 HTTP 响应替代本次 APPEND（由上层转成 IMAP 侧的失败应答）
                self.handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None))
            }
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                // 同上，但响应还带正文，需上层从 ICAP 连接继续读取
                self.handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body)))
            }
        }
    }
}
