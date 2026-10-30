/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP APPEND literal 审计中的两路并发收发。
//!
//! 与 SMTP 场景同理：不支持 preview 时，"向 ICAP 发送剩余正文"与"从 ICAP 读响应"
//! 必须并发推进，否则双方缓冲区写满就会死锁。差别在于 IMAP 的 literal 长度已知，
//! 因此被改写后的邮件长度也要与原始 `literal_size` 逐一核对（`MessageSizeNotMatch`）。
//!
//! - `BidirectionalRecvIcapResponse`：发送阶段。边把剩余 literal 写入 ICAP，
//!   边等待响应头。由于正文是作为**单个 chunk** 上报的（长度行已提前写好），
//!   这里用普通的 `StreamCopy` 原样搬运字节即可；发送完成后需手工补上结束块
//!   `\r\n0\r\n\r\n`，请求才算完整。
//! - `BidirectionalRecvHttpRequest`：改写阶段。ICAP 提前返回了 200 且带有新的
//!   伪 HTTP 请求（改写后的邮件），此时补发剩余正文的同时，把响应的 chunked
//!   正文解码后直接写给上游（IMAP 的 literal 无需 SMTP 那样的点转义）。
//!
//! 两者都配合 `idle_checker` 做空闲统计，长时间无数据往来时按配置超时或强制终止。

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, BufWriter};

use g3_http::HttpBodyDecodeReader;
use g3_http::server::HttpAdaptedRequest;
use g3_io_ext::{
    IdleCheck, LimitedBufReadExt, LimitedWriteExt, StreamCopy, StreamCopyConfig, StreamCopyError,
};

use super::ImapAdaptationError;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// 发送侧：在继续上传剩余 literal 数据的同时等待并解析 ICAP 响应。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 并发执行"发送剩余 literal"与"接收 ICAP 响应"，返回解析后的响应。
    ///
    /// `msg_transfer` 是尚未启动的正文拷贝任务（其写入端就是 ICAP 连接）。
    /// `select!` 三个分支的含义：
    /// - 正文发送完毕 → 补写 chunked 结束块，然后纯等待 ICAP 响应
    /// - ICAP 读缓冲有数据 → 提前响应，剩余正文由调用方在改写阶段继续补发
    /// - 空闲计时器到期 → 累计空闲次数，必要时超时退出
    pub(super) async fn transfer_and_recv<CR>(
        self,
        mut msg_transfer: &mut StreamCopy<'_, CR, IcapClientWriter>,
    ) -> Result<ReqmodResponse, ImapAdaptationError>
    where
        CR: AsyncRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                // 优先保证发送推进
                biased;

                r = &mut msg_transfer => {
                    return match r {
                        Ok(_) => {
                            // literal 已按长度行发满，这里补上 chunked 的结束块，
                            // 请求体至此在协议上完整，之后才能安全地等响应
                            msg_transfer
                                .writer()
                                .write_all_flush(b"\r\n0\r\n\r\n")
                                .await
                                .map_err(ImapAdaptationError::IcapServerWriteFailed)?;
                            self.recv_icap_response().await
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ImapAdaptationError::ImapClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ImapAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        // ICAP 在正文发完前就回了响应：先收下，由调用方判断
                        // 是继续补发剩余正文还是直接结束
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(ImapAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(ImapAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if msg_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 缓冲区里是否还有未写出的数据，决定卡在读取还是写入
                            return if msg_transfer.no_cached_data() {
                                Err(ImapAdaptationError::ImapClientReadIdle)
                            } else {
                                Err(ImapAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        // 有数据流动，清零空闲计数
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

    /// 解析 ICAP 响应头，并把不可继续处理的状态码转成错误。
    ///
    /// 204 在这里被视为错误：走这条路径说明请求还没发完，客户端数据仍在上传，
    /// 上层无法在此安全地"原样转发"，因此统一按错误响应处理。
    /// 206 表示 ICAP 无法处理，同样是错误。其余 2xx 交给上层按载荷分派。
    pub(super) async fn recv_icap_response(self) -> Result<ReqmodResponse, ImapAdaptationError> {
        let rsp = ReqmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;

        match rsp.code {
            204 | 206 => Err(ImapAdaptationError::IcapServerErrorResponse(
                rsp.code, rsp.reason,
            )),
            n if (200..300).contains(&n) => Ok(rsp),
            _ => Err(ImapAdaptationError::IcapServerErrorResponse(
                rsp.code, rsp.reason,
            )),
        }
    }
}

/// 改写侧：一边补发剩余正文，一边接收改写后的邮件并写给上游。
pub(super) struct BidirectionalRecvHttpRequest<'a, I: IdleCheck> {
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) idle_checker: &'a I,
    /// ICAP 响应体中那段伪 HTTP 请求头的字节数，用于定位正文起点
    pub(super) http_header_size: usize,
    /// 原始 IMAP literal 的字节数，用于校验改写结果的长度
    pub(super) imap_message_size: u64,
    /// 输出参数：响应正文是否被干净读完（含 chunked 结束块），决定连接能否复用
    pub(super) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpRequest<'_, I> {
    /// 并发执行"补发剩余正文"与"接收改写后的邮件并写给上游"。
    ///
    /// 响应中的邮件是全新内容，与仍在上传的原正文无关，可以立刻写给上游；
    /// 原正文继续发送只是为了让 ICAP 侧请求体在协议上完整（必须有结束块）。
    ///
    /// 无论哪一路先完成，都会核对实际转交给上游的字节数是否等于
    /// `imap_message_size`：IMAP 的 APPEND 是按长度落库的，长度不符会导致
    /// 上游 mailbox 数据错位，因此必须直接判为错误。
    pub(super) async fn transfer<CR, UW>(
        &mut self,
        state: &mut ReqmodAdaptationRunState,
        mut clt_msg_transfer: &mut StreamCopy<'_, CR, IcapClientWriter>,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // 解析 ICAP 响应中封装的伪 HTTP 请求头（改写后邮件的头部分）
        let http_req =
            HttpAdaptedRequest::parse(self.icap_reader, self.http_header_size, true).await?;
        // 若响应头显式给出 Content-Length，则它必须等于原 literal 长度
        if let Some(len) = http_req.content_length
            && len != self.imap_message_size
        {
            return Err(ImapAdaptationError::MessageSizeNotMatch);
        }
        // TODO check request content type?

        // 改写后的邮件正文以 chunked 编码承载，先解码出裸字节
        let mut ups_body_reader = HttpBodyDecodeReader::new_chunked(self.icap_reader, 256);
        let mut ups_buf_writer = BufWriter::new(ups_writer);
        // IMAP literal 是长度自明的字节串，不需要 SMTP 式的点转义，直接原样搬运
        let mut ups_msg_transfer =
            StreamCopy::new(&mut ups_body_reader, &mut ups_buf_writer, &self.copy_config);

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                r = &mut clt_msg_transfer => {
                    return match r {
                        Ok(_) => {
                            // 原正文发满，补写 chunked 结束块后单线程收完响应正文
                            clt_msg_transfer
                                .writer()
                                .write_all_flush(b"\r\n0\r\n\r\n")
                                .await
                                .map_err(ImapAdaptationError::IcapServerWriteFailed)?;
                            match ups_msg_transfer.await {
                                Ok(copied) => {
                                    state.mark_ups_send_all();
                                    // 尝试吃掉 chunked 的 trailer，成功说明响应彻底读完
                                    if ups_body_reader.trailer(128).await.is_ok() {
                                        self.icap_read_finished = true;
                                    }
                                    if copied != self.imap_message_size {
                                        return Err(ImapAdaptationError::MessageSizeNotMatch);
                                    }
                                    Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                                }
                                Err(StreamCopyError::ReadFailed(e)) => Err(ImapAdaptationError::IcapServerReadFailed(e)),
                                Err(StreamCopyError::WriteFailed(e)) => Err(ImapAdaptationError::ImapUpstreamWriteFailed(e)),
                            }
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ImapAdaptationError::ImapClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ImapAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = &mut ups_msg_transfer => {
                    return match r {
                        Ok(copied) => {
                            state.mark_ups_send_all();
                            if ups_body_reader.trailer(128).await.is_ok() {
                                self.icap_read_finished = true;
                            }
                            if copied != self.imap_message_size {
                                return Err(ImapAdaptationError::MessageSizeNotMatch);
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(ImapAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(ImapAdaptationError::ImapUpstreamWriteFailed(e)),
                    };
                }
                _ = idle_interval.tick() => {
                    if clt_msg_transfer.is_idle() && ups_msg_transfer.is_idle() {
                        idle_count += 1;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 两路都空闲：依次判断卡在"读客户端 / 写 ICAP /
                            // 读 ICAP / 写上游"哪一个方向
                            return if clt_msg_transfer.is_idle() {
                                if clt_msg_transfer.no_cached_data() {
                                    Err(ImapAdaptationError::ImapClientReadIdle)
                                } else {
                                    Err(ImapAdaptationError::IcapServerWriteIdle)
                                }
                            } else if ups_msg_transfer.no_cached_data() {
                                Err(ImapAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(ImapAdaptationError::ImapUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        // 只要有一路在动，两路的空闲状态都重新计时
                        clt_msg_transfer.reset_active();
                        ups_msg_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(ImapAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
