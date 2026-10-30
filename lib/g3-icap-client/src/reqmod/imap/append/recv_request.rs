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
//! Content-Length: <改写后的邮件长度>\r\n   // 可能缺失；若存在必须等于原 literal 长度
//! \r\n
//! <改写后的邮件正文，chunked 编码>
//! ```
//! 本文件负责解析这段 HTTP 请求头、校验长度，并把 chunked 正文解码后写给上游。
//! IMAP 的 literal 是长度自明的字节串，因此不需要像 SMTP 那样补做点转义，
//! 直接用 `StreamCopy` 原样搬运即可。
//!
//! 与 SMTP 版本的区别就在于多了 **长度核对**：原始 APPEND 的 `{<n>}` 已声明了
//! 精确字节数，改写结果长度不符（`MessageSizeNotMatch`）时绝不能交给上游写入
//! mailbox，否则上游会按错误的长度取数据。

use tokio::io::{AsyncWrite, BufWriter};

use g3_http::HttpBodyDecodeReader;
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::{IdleCheck, StreamCopy, StreamCopyError};

use super::{ImapAdaptationError, ImapMessageAdapter};
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> ImapMessageAdapter<I> {
    /// 处理"只有 HTTP 请求头、没有正文"的响应。
    ///
    /// 邮件必然有正文（哪怕是空正文也需要 chunked 结束块），所以这种响应
    /// 说明 ICAP 侧不符合约定，按错误处理；连接上已无残留数据，可安全归还。
    pub(super) async fn handle_icap_http_request_without_body(
        mut self,
        _state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError> {
        let _http_req =
            HttpAdaptedRequest::parse(&mut self.icap_connection.reader, http_header_size, true)
                .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }
        // there should be a message body
        Err(ImapAdaptationError::IcapServerErrorResponse(
            icap_rsp.code,
            icap_rsp.reason.to_string(),
        ))
    }

    /// 在 ICAP 请求**已全部发送完毕**之后，接收改写后的邮件并写给上游。
    ///
    /// 请求方向已无数据可发，所以这里只需关心"读 ICAP → 写上游"单一路径，
    /// 但仍要配合空闲检查，防止 ICAP 迟迟不吐正文。
    ///
    /// 转换链路：ICAP 连接（chunked 编码）→ `HttpBodyDecodeReader` 解码
    /// → `StreamCopy` 原样搬运 → 上游 IMAP 连接。
    /// 长度校验分两级：头部若带 `Content-Length` 先做一次，实际拷贝完成后再
    /// 用真正写出的字节数做一次。
    pub(super) async fn handle_icap_http_request_with_body_after_transfer<UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError>
    where
        UW: AsyncWrite + Unpin,
    {
        // http_header_size 是 ICAP 响应体中段内的偏移，解析时按它定位请求头结束处
        let http_req =
            HttpAdaptedRequest::parse(&mut self.icap_connection.reader, http_header_size, true)
                .await?;
        // 改写后的邮件长度必须与原 literal 一致，否则上游 mailbox 会写入错位
        if let Some(len) = http_req.content_length
            && len != self.literal_size
        {
            return Err(ImapAdaptationError::MessageSizeNotMatch);
        }
        // TODO check request content type?

        // 改写后的邮件正文以 chunked 传输，256 是读取缓冲大小
        let mut body_reader =
            HttpBodyDecodeReader::new_chunked(&mut self.icap_connection.reader, 256);
        let mut ups_buf_writer = BufWriter::new(ups_writer);
        let mut msg_transfer =
            StreamCopy::new(&mut body_reader, &mut ups_buf_writer, &self.copy_config);

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut msg_transfer => {
                    return match r {
                        Ok(copied) => {
                            state.mark_ups_send_all();
                            // 尝试读完 chunked 的结束块/trailer：
                            // 只有彻底读完响应，这条 ICAP 连接才能复用
                            if body_reader.trailer(128).await.is_ok() {
                                self.icap_connection.mark_reader_finished();
                                if icap_rsp.keep_alive {
                                    self.icap_client.save_connection(self.icap_connection);
                                }
                            }
                            if copied != self.literal_size {
                                return Err(ImapAdaptationError::MessageSizeNotMatch);
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                        },
                        Err(StreamCopyError::ReadFailed(e)) => Err(ImapAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ImapAdaptationError::ImapUpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if msg_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 缓冲里还有未写出的数据 → 卡在写上游；
                            // 否则是上游已写完、卡在从 ICAP 读
                            return if msg_transfer.no_cached_data() {
                                Err(ImapAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(ImapAdaptationError::ImapUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        msg_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(ImapAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
