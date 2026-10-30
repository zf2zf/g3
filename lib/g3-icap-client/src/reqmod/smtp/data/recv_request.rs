/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应中携带"改写后的伪 HTTP 请求"时的处理（对应 REQMOD 的 200 场景）。
//!
//! ICAP 服务器若要替换邮件，会在 200 响应的 `res-body` 中再放一个伪 HTTP 请求：
//! ```text
//! PUT / HTTP/1.1\r\n
//! Content-Type: message/rfc822\r\n
//! X-SMTP-From: <reverse_path>\r\n
//! X-SMTP-To: <forward_path>\r\n
//! \r\n
//! <改写后的邮件正文，chunked 编码>
//! ```
//! 本文件负责解析这段 HTTP 请求头，并把 chunked 正文解码后按 SMTP 线格式
//! （重新做点转义、补终止行）写给上游。
//!
//! 两个入口的区别只在于**正文发送是否已经完成**：
//! - `handle_icap_http_request_with_body_after_transfer`：原邮件正文已全部发给
//!   ICAP，此时可以单线程地把响应正文读完并转给上游。
//! - 无正文的版本用于 ICAP 只回头部就结束的异常场景（视为错误响应）。

use tokio::io::{AsyncWrite, BufWriter};

use g3_http::HttpBodyDecodeReader;
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::{IdleCheck, StreamCopyError};
use g3_smtp_proto::io::TextDataEncodeTransfer;

use super::{SmtpAdaptationError, SmtpMessageAdapter};
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> SmtpMessageAdapter<I> {
    /// 处理"只有 HTTP 请求头、没有正文"的响应。
    ///
    /// 邮件必然有正文（哪怕是空正文也需要 chunked 结束块），所以这种响应
    /// 说明 ICAP 侧不符合约定，按错误处理；此时连接上没有残留数据要读，
    /// 可以安全地标记读结束并按 keep-alive 归还连接。
    pub(super) async fn handle_icap_http_request_without_body(
        mut self,
        _state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError> {
        let _http_req =
            HttpAdaptedRequest::parse(&mut self.icap_connection.reader, http_header_size, true)
                .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a message body
        Err(SmtpAdaptationError::IcapServerErrorResponse(
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 在原邮件正文**已全部发送完毕**之后，接收改写后的邮件并写给上游。
    ///
    /// 因为请求方向已经无数据可发，这里只需要关心"读 ICAP → 写上游"单一路径，
    /// 但仍要配合空闲检查，防止 ICAP 迟迟不吐正文。
    ///
    /// 转换链路：ICAP 连接（chunked 编码）→ `HttpBodyDecodeReader` 解码
    /// → `TextDataEncodeTransfer` 做 SMTP 点转义 → 上游 SMTP 连接。
    pub(super) async fn handle_icap_http_request_with_body_after_transfer<UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError>
    where
        UW: AsyncWrite + Unpin,
    {
        // http_header_size 是 ICAP 响应体中段内偏移，解析时按它定位请求头结束处
        let _http_req =
            HttpAdaptedRequest::parse(&mut self.icap_connection.reader, http_header_size, true)
                .await?;
        // TODO check request content type?

        // 改写后的邮件正文以 chunked 传输，256 是读取缓冲大小
        let mut body_reader =
            HttpBodyDecodeReader::new_chunked(&mut self.icap_connection.reader, 256);
        let mut ups_buf_writer = BufWriter::new(ups_writer);
        // 输出侧补回 SMTP 的点转义（行首的 "." 前再加一个 "."）
        let mut msg_transfer =
            TextDataEncodeTransfer::new(&mut body_reader, &mut ups_buf_writer, self.copy_config);

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut msg_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_ups_send_all();
                            // 尝试读完 chunked 的结束块/trailer：
                            // 只有彻底读完响应，这条 ICAP 连接才能复用
                            if body_reader.trailer(128).await.is_ok() {
                                self.icap_connection.mark_reader_finished();
                                if icap_rsp.keep_alive {
                                    self.icap_client.save_connection(self.icap_connection);
                                }
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                        },
                        Err(StreamCopyError::ReadFailed(e)) => Err(SmtpAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(SmtpAdaptationError::SmtpUpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if msg_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 缓冲里还有没写出去的数据 → 卡在写上游；
                            // 否则是上游已写完、卡在从 ICAP 读
                            return if msg_transfer.no_cached_data() {
                                Err(SmtpAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(SmtpAdaptationError::SmtpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        msg_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(SmtpAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
