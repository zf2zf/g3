/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 邮件正文审计中的两路并发收发。
//!
//! 因为不支持 preview（ICAP 不能只看不发就下结论前我们先灌完正文），
//! "向 ICAP 发送正文" 和 "从 ICAP 读响应" 必须并发推进，否则任一方写满
//! 对端缓冲区就会死锁。本文件用 `tokio::select!` 在两个 future 之间轮转：
//!
//! - `BidirectionalRecvIcapResponse`：发送阶段，一边把正文按 chunked 编码
//!   持续写入 ICAP（请求体对应封装的 `message/rfc822` 邮件），一边等待 ICAP
//!   响应头到达。谁先就绪就处理谁。
//! - `BidirectionalRecvHttpRequest`：改写阶段，ICAP 已经返回 200 且带有
//!   "新的伪 HTTP 请求"（改写后的邮件），此时剩余正文仍要发完，同时把响应
//!   的 chunked 正文解码回 SMTP 线格式（重新加点转义）写给上游。
//!
//! 两个结构都会配合 `idle_checker` 做空闲统计：长时间无数据往来时按配置
//! 超时或强制终止，避免半死的连接长期占用资源。

use std::sync::Arc;

use tokio::io::{AsyncBufRead, AsyncWrite, BufWriter};

use g3_http::server::HttpAdaptedRequest;
use g3_http::{HttpBodyDecodeReader, StreamToChunkedTransfer};
use g3_io_ext::{IdleCheck, LimitedBufReadExt, StreamCopyConfig, StreamCopyError};
use g3_smtp_proto::io::TextDataEncodeTransfer;

use super::SmtpAdaptationError;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::reqmod::response::ReqmodResponse;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient};

/// 发送侧：在继续上传邮件正文（chunked）的同时等待并解析 ICAP 响应。
pub(super) struct BidirectionalRecvIcapResponse<'a, I: IdleCheck> {
    pub(super) icap_client: &'a Arc<IcapServiceClient>,
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) idle_checker: &'a I,
}

impl<I: IdleCheck> BidirectionalRecvIcapResponse<'_, I> {
    /// 并发执行"发送 chunked 正文"与"接收 ICAP 响应"，返回解析后的响应。
    ///
    /// `msg_transfer` 是尚未启动的正文拷贝任务；对它 `await` 即驱动一次传输。
    /// `select!` 中三个分支的含义：
    /// - 正文发送完毕（通常是读到 SMTP 终止行 `\r\n.\r\n`）→ 转为纯接收响应
    /// - ICAP 读缓冲有数据 → 提前响应，剩下的正文后续在改写阶段继续补发
    /// - 空闲计时器到期 → 统计空闲次数，必要时超时退出
    pub(super) async fn transfer_and_recv<CR>(
        self,
        mut msg_transfer: &mut StreamToChunkedTransfer<'_, CR, BufWriter<&'_ mut IcapClientWriter>>,
    ) -> Result<ReqmodResponse, SmtpAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                // 优先保证发送推进
                biased;

                r = &mut msg_transfer => {
                    return match r {
                        Ok(_) => self.recv_icap_response().await,
                        Err(StreamCopyError::ReadFailed(e)) => Err(SmtpAdaptationError::SmtpClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(SmtpAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = self.icap_reader.fill_wait_data() => {
                    return match r {
                        // ICAP 在正文发完前就回了响应：先收下，
                        // 由调用方决定是继续补发剩余正文还是直接结束
                        Ok(true) => self.recv_icap_response().await,
                        Ok(false) => Err(SmtpAdaptationError::IcapServerConnectionClosed),
                        Err(e) => Err(SmtpAdaptationError::IcapServerReadFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if msg_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 按缓冲区里是否还有未写出的数据判断卡在哪个方向
                            return if msg_transfer.no_cached_data() {
                                Err(SmtpAdaptationError::SmtpClientReadIdle)
                            } else {
                                Err(SmtpAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        // 有数据流动，清零空闲计数
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

    /// 解析 ICAP 响应头，并把非"可继续处理"的状态码转成错误。
    ///
    /// - 204（未修改）与 206（无法处理）在这里都视为错误：SMTP 场景下调用方
    ///   已经发了完整正文，期望拿到 200 或直接放行，因此交由上层按错误回复。
    /// - 其余 2xx 视为正常，返回给上层按载荷类型分派。
    pub(super) async fn recv_icap_response(self) -> Result<ReqmodResponse, SmtpAdaptationError> {
        let rsp = ReqmodResponse::parse(
            self.icap_reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;

        match rsp.code {
            204 | 206 => Err(SmtpAdaptationError::IcapServerErrorResponse(
                rsp.code, rsp.reason,
            )),
            n if (200..300).contains(&n) => Ok(rsp),
            _ => Err(SmtpAdaptationError::IcapServerErrorResponse(
                rsp.code, rsp.reason,
            )),
        }
    }
}

/// 改写侧：一边补发剩余正文，一边接收 ICAP 返回的"改写后的邮件"。
pub(super) struct BidirectionalRecvHttpRequest<'a, I: IdleCheck> {
    pub(super) icap_reader: &'a mut IcapClientReader,
    pub(super) copy_config: StreamCopyConfig,
    pub(super) idle_checker: &'a I,
    /// ICAP 响应体中那段伪 HTTP 请求头的字节数，用于定位正文起点
    pub(super) http_header_size: usize,
    /// 输出参数：响应正文是否被干净读完（含 chunked 结束块），决定连接能否复用
    pub(super) icap_read_finished: bool,
}

impl<I: IdleCheck> BidirectionalRecvHttpRequest<'_, I> {
    /// 并发执行"补发剩余正文"与"接收改写后的邮件并写给上游"。
    ///
    /// 注意这里存在**时序上的互斥风险**：响应正文里的邮件是全新的内容，
    /// 与仍在上传的原正文无关，因此可以立刻写给上游；而原正文之所以还要继续发，
    /// 只是为了让 ICAP 侧的请求体在协议上完整（chunked 必须有结束块）。
    pub(super) async fn transfer<CR, UW>(
        &mut self,
        state: &mut ReqmodAdaptationRunState,
        mut clt_msg_transfer: &mut StreamToChunkedTransfer<
            '_,
            CR,
            BufWriter<&'_ mut IcapClientWriter>,
        >,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // 解析 ICAP 响应中封装的伪 HTTP 请求头（改写后的邮件的头部分）
        let _http_req =
            HttpAdaptedRequest::parse(self.icap_reader, self.http_header_size, true).await?;
        // TODO check request content type?

        // 响应正文以 chunked 编码承载，先解码出裸的邮件内容
        let mut ups_body_reader = HttpBodyDecodeReader::new_chunked(self.icap_reader, 256);
        let mut ups_buf_writer = BufWriter::new(ups_writer);
        // 再按 SMTP 线格式重新做点转义（行首的 "." 需要补一个 "."）后写入上游
        let mut ups_msg_transfer = TextDataEncodeTransfer::new(
            &mut ups_body_reader,
            &mut ups_buf_writer,
            self.copy_config,
        );

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                r = &mut clt_msg_transfer => {
                    return match r {
                        Ok(_) => {
                            // 原正文发完，转而单线程收完改写后的邮件
                            match ups_msg_transfer.await {
                                Ok(_) => {
                                    state.mark_ups_send_all();
                                    // 尝试吃掉 chunked 的 trailer，成功说明响应彻底读完
                                    if ups_body_reader.trailer(128).await.is_ok() {
                                        self.icap_read_finished = true;
                                    }
                                    Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                                }
                                Err(StreamCopyError::ReadFailed(e)) => Err(SmtpAdaptationError::IcapServerReadFailed(e)),
                                Err(StreamCopyError::WriteFailed(e)) => Err(SmtpAdaptationError::SmtpUpstreamWriteFailed(e)),
                            }
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(SmtpAdaptationError::SmtpClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(SmtpAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                r = &mut ups_msg_transfer => {
                    return match r {
                        Ok(_) => {
                            state.mark_ups_send_all();
                            if ups_body_reader.trailer(128).await.is_ok() {
                                self.icap_read_finished = true;
                            }
                            Ok(ReqmodAdaptationEndState::AdaptedTransferred)
                        }
                        Err(StreamCopyError::ReadFailed(e)) => Err(SmtpAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(SmtpAdaptationError::SmtpUpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if clt_msg_transfer.is_idle() && ups_msg_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            // 两路都空闲：依次判断是"读客户端卡住"、
                            // "写 ICAP 卡住"、"读 ICAP 卡住"还是"写上游卡住"
                            return if clt_msg_transfer.is_idle() {
                                if clt_msg_transfer.no_cached_data() {
                                    Err(SmtpAdaptationError::SmtpClientReadIdle)
                                } else {
                                    Err(SmtpAdaptationError::IcapServerWriteIdle)
                                }
                            } else if ups_msg_transfer.no_cached_data() {
                                Err(SmtpAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(SmtpAdaptationError::SmtpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        // 只要有一路在动，两路的空闲状态都重新计时
                        clt_msg_transfer.reset_active();
                        ups_msg_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(SmtpAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
