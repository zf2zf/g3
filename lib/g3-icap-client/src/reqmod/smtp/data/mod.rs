/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP DATA 阶段邮件正文的双向传输（无 preview 的完整 REQMOD 流程）。
//!
//! 封装后的 ICAP 请求整体形如：
//! ```text
//! REQMOD * ICAP/1.0\r\n
//! X-Transformed-From: SMTP\r\n
//! X-Client-IP: <客户端地址>\r\n              // 可选扩展头
//! X-Client-Port: <客户端端口>\r\n            // 可选扩展头
//! Encapsulated: req-hdr=0, req-body=<HTTP头长度>\r\n
//! \r\n
//! # ---- 以下为 ICAP 请求体，即被封装的伪 HTTP 报文 ----
//! # [req-hdr] 从偏移 0 开始
//! PUT / HTTP/1.1\r\n
//! Content-Type: message/rfc822\r\n
//! X-SMTP-From: <reverse_path>\r\n
//! X-SMTP-To: <forward_path>\r\n
//! \r\n
//! # [req-body] 从偏移 <HTTP头长度> 开始，正文以 chunked 分块编码承载
//! <hex 长度>\r\n
//! <邮件正文数据块>\r\n
//! <hex 长度>\r\n
//! <邮件正文数据块>\r\n
//! 0\r\n\r\n                             // 结束块；本流程不写 trailer
//! ```
//! `Encapsulated:` 中的偏移量都相对于 ICAP 头之后的报文起点：`req-hdr=0` 表示
//! 伪 HTTP 请求头从第 0 字节开始，`req-body=<HTTP头长度>` 表示正文紧接在头部之后。
//! 头部末尾那个表示"头结束"的空行 `\r\n` 也计入 req-hdr，即 `<HTTP头长度>` 已包含它。
//!
//! 收发时序（关键：读和写必须同时进行）：
//! 1. 用 `write_all_vectored` 把 ICAP 头 + 伪 HTTP 头一次性写出，零拷贝。
//! 2. 边从 SMTP 客户端读正文，边把正文以 chunked 编码写入 ICAP 请求体。
//! 读出的数据先经过 `TextDataDecodeReader` 做 **SMTP 点转义（dot-stuffing）解码**：
//! 行首多出的那个 `.` 会被去掉，遇到终止行 `\r\n.\r\n` 则认为正文结束。
//! 3. 与第 2 步并发地等待 ICAP 响应（见 `bidirectional` 子模块）——
//! 由于没有 preview，ICAP 服务器可以在正文传完之前就提前给出结论。
//! 4. 按响应载荷分派：无载荷 / 改写后的伪 HTTP 请求（`recv_request`）/
//! 替代用的 HTTP 错误响应（`recv_response`）。204 场景表示"未修改，原样转发"，
//! 200 场景表示"用响应中的邮件替换原请求"。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite, BufWriter};

use g3_http::StreamToChunkedTransfer;
use g3_io_ext::{IdleCheck, LimitedWriteExt};
use g3_smtp_proto::command::{MailParam, RecipientParam};
use g3_smtp_proto::io::TextDataDecodeReader;

use super::{HttpAdapterErrorResponse, SmtpAdaptationError, SmtpMessageAdapter};
use crate::reqmod::IcapReqmodResponsePayload;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};

// 边发正文边收响应 / 边收改写后正文的两路并发收发实现
mod bidirectional;
use bidirectional::{BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse};

// 响应中携带"改写后的伪 HTTP 请求"（200 替换原邮件）时的处理
mod recv_request;
// 响应中携带"替代 HTTP 错误响应"或无载荷时的处理
mod recv_response;

impl<I: IdleCheck> SmtpMessageAdapter<I> {
    /// 拼装 ICAP 请求头（REQMOD + 扩展头 + Encapsulated 偏移表）。
    ///
    /// `http_header_len` 是 `build_http_header()` 产生的伪 HTTP 头字节数，
    /// 它正好等于正文（req-body）相对 ICAP 报文起点的偏移，因此
    /// `Encapsulated: req-hdr=0, req-body=<http_header_len>`。
    fn build_forward_all_request(&self, http_header_len: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        // 预生成好的 "REQMOD * ICAP/1.0\r\n" + 方法名/服务名等公共部分
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, req-body={http_header_len}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 不带 preview，完整流式传输整封邮件正文并审计。
    ///
    /// 与 `xfer_data` 的文档相同，只是这里明确走"全量转发"分支：
    /// 先把全部正文灌给 ICAP 服务器，同时并发地收响应。
    pub async fn xfer_data_without_preview<CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: &mut UW,
        mail_from: &MailParam,
        mail_to: &[RecipientParam],
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let http_header = self.build_http_header(mail_from, mail_to);
        // req-body 的偏移量就是伪 HTTP 头的字节数，两者必须严格对齐
        let icap_header = self.build_forward_all_request(http_header.len());

        // ICAP 头与 HTTP 头一起以 vectored write 发出，省掉一次内存拷贝
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(SmtpAdaptationError::IcapServerWriteFailed)?;

        // 客户端正文先做 SMTP 点转义解码（去掉行首多余的 "."，识别 "\r\n.\r\n" 结束）
        let mut message_reader = TextDataDecodeReader::new(clt_r, self.copy_config.buffer_size());
        // 写出侧套一层 BufWriter，减少小块 chunked 头部/尾部带来的系统调用
        let mut icap_buf_writer = BufWriter::new(&mut self.icap_connection.writer);
        // 把解码后的正文按 chunked 分块编码写入 ICAP req-body；
        // no_trailer 表示结束时只写 "0\r\n\r\n"，不附加 trailer
        let mut body_transfer = StreamToChunkedTransfer::new_with_no_trailer(
            &mut message_reader,
            &mut icap_buf_writer,
            self.copy_config.yield_size(),
        );

        // 一边继续发正文，一边等 ICAP 响应（无 preview 时两者并发进行）
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        let rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        if body_transfer.finished() {
            // 正文已全部读完并发出，标记客户端方向读结束
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
                    // 正文已经发完，可以安静地单向读完响应中的新邮件
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        ups_w,
                    )
                    .await
                } else {
                    // 正文还没发完 ICAP 就已经返回改写结果，
                    // 此时必须继续发剩余正文，同时把响应正文转给上游
                    let mut bidirectional_transfer = BidirectionalRecvHttpRequest {
                        icap_reader: &mut self.icap_connection.reader,
                        copy_config: self.copy_config,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(state, &mut body_transfer, ups_w)
                        .await?;
                    let icap_read_finished = bidirectional_transfer.icap_read_finished;
                    if body_transfer.finished() {
                        if message_reader.finished() {
                            // 解码器已读到 SMTP 终止行，客户端正文完整发送
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
                // ICAP 用一段 HTTP 响应替代原本的转发（例如返回给 SMTP 客户端错误说明）
                self.handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None))
            }
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                // 同上，但响应还带有正文，正文需后续从 ICAP 连接继续读取
                self.handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body)))
            }
        }
    }
}
