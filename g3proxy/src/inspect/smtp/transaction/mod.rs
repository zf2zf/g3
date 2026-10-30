/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 事务（transaction）阶段：一次 MAIL FROM 之后、到邮件数据传输完成为止。
//!
//! [`Transaction`] 处理 RCPT/DATA/BDAT/BURL/NOOP/RSET/QUIT 等命令的转发与响应中继，
//! 并在邮件正文到达代理时接入 ICAP reqmod 内容检测（放行原文、改写后转发或阻断）。
//! 本阶段是内容审计的核心：文本正文经 [`g3_smtp_proto::io::TextDataReader`] 还原点转义后
//! 交给适配器，二进制正文（BDAT）则按声明长度直接流式拷贝。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_dpi::SmtpInterceptionConfig;
use g3_icap_client::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use g3_icap_client::reqmod::smtp::SmtpMessageAdapter;
use g3_io_ext::{LimitedWriteExt, StreamCopy, StreamCopyError};
use g3_slog_types::LtUuid;
use g3_smtp_proto::command::{Command, MailParam, RecipientParam};
use g3_smtp_proto::io::TextDataReader;
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseParser};

use super::{CommandLineRecvExt, ResponseLineRecvExt, ResponseParseExt, SmtpRelayBuf};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;
use crate::serve::{ServerIdleChecker, ServerTaskError, ServerTaskResult};

// 记录一条事务级拦截日志，自动附带事务 id 与发件人地址等公共字段。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "SmtpTransaction",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "transaction_id" => $obj.transaction_id,
                "mail_from" => $obj.mail_from.reverse_path(),
            );
        }
    };
}

/// 一次邮件事务的状态机：从 MAIL 命令成功后开始，到正文传输完成（或 QUIT/RSET）结束。
pub(super) struct Transaction<'a, SC: ServerConfig> {
    config: &'a SmtpInterceptionConfig,
    ctx: &'a StreamInspectContext<SC>,
    transaction_id: usize,
    local_ip: IpAddr,
    allow_chunking: bool,         // 服务端宣告且配置允许 BDAT 分块传输
    allow_burl: bool,             // 服务端宣告且配置允许 BURL 按 URL 投递
    mail_from: MailParam,         // MAIL FROM 参数，ICAP 检测时作为信封发件人
    mail_to: Vec<RecipientParam>, // 已收集的 RCPT TO 收件人列表
    quit: bool,                   // 事务内收到 QUIT 的标志，上层据此结束整个会话
}

impl<'a, SC: ServerConfig> Transaction<'a, SC> {
    /// 创建事务对象；`from` 为已转发成功的 MAIL FROM 命令参数，收件人列表初始为空。
    pub(super) fn new(
        ctx: &'a StreamInspectContext<SC>,
        transaction_id: usize,
        local_ip: IpAddr,
        allow_chunking: bool,
        allow_burl: bool,
        from: MailParam,
    ) -> Self {
        Transaction {
            config: ctx.smtp_interception(),
            ctx,
            transaction_id,
            local_ip,
            allow_chunking,
            allow_burl,
            mail_from: from,
            mail_to: Vec::with_capacity(4),
            quit: false,
        }
    }

    /// 事务是否因客户端 QUIT 而结束；为 true 时上层应关闭会话而非开启下一事务。
    #[inline]
    pub(super) fn quit(&self) -> bool {
        self.quit
    }

    /// 对外入口：执行事务中继并在结束时记录拦截日志。
    pub(super) async fn relay<CR, CW, UR, UW>(
        &mut self,
        buf: &mut SmtpRelayBuf,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match self.do_relay(buf, clt_r, clt_w, ups_r, ups_w).await {
            Ok(_) => {
                intercept_log!(self, "finished");
                Ok(())
            }
            Err(e) => {
                intercept_log!(self, "{e}");
                Err(e)
            }
        }
    }

    /// 事务命令循环：按命令类型分发到对应的转发/传输逻辑。
    /// `in_chunking` 跟踪 BDAT 分段状态：一旦进入分块模式，RCPT/DATA 等文本命令均为时序错误。
    /// 正文传输完成（DATA 或最后一块 BDAT）后 `Ok(())` 返回，上层可开启下一事务。
    async fn do_relay<CR, CW, UR, UW>(
        &mut self,
        buf: &mut SmtpRelayBuf,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut in_chunking = false;
        loop {
            buf.cmd_recv_buf.consume_line();
            let (cmd, cmd_line) = buf
                .cmd_recv_buf
                .recv_cmd(self.config.command_wait_timeout, clt_r, clt_w)
                .await?;

            match cmd {
                Command::Recipient(p) => {
                    // 收件人命令只在正文传输前合法；分块模式中属于时序错误
                    if in_chunking {
                        self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                            .await?;
                        continue;
                    }
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.response_wait_timeout, buf, ups_r, clt_w)
                        .await?;
                    self.mail_to.push(p);
                }
                Command::Data => {
                    // 传统文本正文流程：DATA -> 354 -> 读正文 -> 源站最终响应，事务结束
                    if in_chunking {
                        self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                            .await?;
                        continue;
                    }
                    self.send_data_cmd(ups_w, clt_w, cmd_line).await?;
                    let rsp = self
                        .recv_relay_rsp(self.config.data_initiation_timeout, buf, ups_r, clt_w)
                        .await?;
                    // 源站未回 354（开始邮件输入）则客户端不会发正文，继续等下一条命令
                    if rsp != ReplyCode::START_MAIL_INPUT {
                        continue;
                    }
                    self.send_txt_data(clt_r, clt_w, ups_w).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.data_termination_timeout, buf, ups_r, clt_w)
                        .await?;
                    return Ok(());
                }
                Command::BinaryData(size) => {
                    // BDAT 中间块：传输声明长度后仍停留在分块模式，等待后续块
                    if !self.allow_chunking {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                        continue;
                    }
                    self.send_bdat_cmd(ups_w, clt_w, cmd_line, size).await?;
                    self.send_bin_data(buf, clt_r, ups_w, size).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.data_termination_timeout, buf, ups_r, clt_w)
                        .await?;
                    in_chunking = true;
                }
                Command::LastBinaryData(size) => {
                    // LAST-parameters BDAT：传输完最后一块后事务结束
                    if !self.allow_chunking {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                        continue;
                    }
                    self.send_bdat_cmd(ups_w, clt_w, cmd_line, size).await?;
                    self.send_bin_data(buf, clt_r, ups_w, size).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.data_termination_timeout, buf, ups_r, clt_w)
                        .await?;
                    return Ok(());
                }
                Command::DataByUrl(url) => {
                    // BURL 中间块：依赖 CHUNKING 与 BURL 双重许可，服务端异步取数据
                    if !self.allow_burl || !self.allow_chunking {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                        continue;
                    }
                    self.send_burl_cmd(ups_w, clt_w, cmd_line, url).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.data_termination_timeout, buf, ups_r, clt_w)
                        .await?;
                    in_chunking = true;
                }
                Command::LastDataByUrl(url) => {
                    // BURL 最后一块：受理后事务即结束（正文由服务端自行拉取）
                    if !self.allow_burl {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                        continue;
                    }
                    self.send_burl_cmd(ups_w, clt_w, cmd_line, url).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.data_termination_timeout, buf, ups_r, clt_w)
                        .await?;
                    return Ok(());
                }
                Command::NoOperation => {
                    // NOOP 保活命令：转发并确认 250，异常响应码视为协议错误
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let rsp = self
                        .recv_relay_rsp(self.config.response_wait_timeout, buf, ups_r, clt_w)
                        .await?;
                    if rsp != ReplyCode::OK {
                        return Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected NOOP reply code {rsp}"
                        )));
                    }
                }
                Command::Reset => {
                    // RSET：清空本次事务（收件人列表随之作废），返回上层重新等 MAIL
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let rsp = self
                        .recv_relay_rsp(self.config.response_wait_timeout, buf, ups_r, clt_w)
                        .await?;
                    return if rsp != ReplyCode::OK {
                        Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected RESET reply code {rsp}"
                        )))
                    } else {
                        Ok(())
                    };
                }
                Command::Quit => {
                    // QUIT：转发并中继响应后置位 quit 标志，通知上层结束会话
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let _ = self
                        .recv_relay_rsp(self.config.response_wait_timeout, buf, ups_r, clt_w)
                        .await?;
                    self.quit = true;
                    return Ok(());
                }
                // 其余命令（如再次 MAIL/EHLO）在事务中均属时序错误，本地回 503
                _ => {
                    self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                        .await?;
                }
            }
        }
    }

    /// 逐行读取源站响应并原样转发给客户端，直到完整响应结束，返回最终响应码。
    /// 421（SERVICE_NOT_AVAILABLE）视为源站即将下线，转换为 `UpstreamAppUnavailable` 错误终止任务。
    async fn recv_relay_rsp<CW, UR>(
        &mut self,
        recv_timeout: Duration,
        buf: &mut SmtpRelayBuf,
        ups_r: &mut UR,
        clt_w: &mut CW,
    ) -> ServerTaskResult<ReplyCode>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        let mut rsp = ResponseParser::default();
        loop {
            buf.rsp_recv_buf.consume_line();
            let line = buf
                .rsp_recv_buf
                .read_rsp_line_with_feedback(recv_timeout, ups_r, clt_w, self.local_ip)
                .await?;
            let _msg = rsp
                .feed_line_with_feedback(line, clt_w, self.local_ip)
                .await?;

            clt_w
                .write_all_flush(line)
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;

            if rsp.finished() {
                let code = rsp.code();
                return if code == ReplyCode::SERVICE_NOT_AVAILABLE {
                    Err(ServerTaskError::UpstreamAppUnavailable)
                } else {
                    Ok(code)
                };
            }
        }
    }

    /// 传输 DATA 命令后的文本邮件正文。
    /// 若配置了 ICAP reqmod 客户端，则把正文交给适配器做内容检测/改写；
    /// ICAP 不可用时：客户端允许旁路则退化为原始传输，否则报错。
    /// 无 ICAP 时用 [`TextDataReader`] 按 SMTP 点转义规则读取正文直到独占一行的 "."。
    async fn send_txt_data<CR, CW, UW>(
        &self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_w: &mut UW,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if let Some(client) = self.ctx.audit_handle.icap_reqmod_client() {
            match client
                .smtp_message_adaptor(
                    self.ctx.server_config.limited_copy_config(),
                    self.ctx.idle_checker(),
                )
                .await
            {
                Ok(adapter) => {
                    return self
                        .send_txt_data_with_adaptation(clt_r, clt_w, ups_w, adapter)
                        .await;
                }
                Err(e) => {
                    if !client.bypass() {
                        return Err(ServerTaskError::InternalAdapterError(e));
                    }
                    // ICAP 故障且策略允许旁路：落入下方原始传输
                }
            }
        }

        let mut reader = TextDataReader::new(clt_r);
        self.transfer_data(&mut reader, ups_w).await
    }

    /// 经 ICAP reqmod 适配器传输正文：适配器按信封（发件人/收件人）改写或放行邮件。
    /// 结束后按 [`ReqmodAdaptationEndState`] 分派：原文/改写后转发均成功；
    /// HTTP 错误响应表示 ICAP 阻断，向客户端回 554 后终止事务。
    async fn send_txt_data_with_adaptation<CR, CW, UW>(
        &self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_w: &mut UW,
        mut adapter: SmtpMessageAdapter<ServerIdleChecker>,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // 把客户端地址与用户名填入 ICAP 头，供检测服务做身份/来源维度的策略
        adapter.set_client_addr(self.ctx.task_notes.client_addr);
        if let Some(username) = self.ctx.raw_user_name() {
            adapter.set_client_username(username.clone());
        }

        let mut adaptation_state = ReqmodAdaptationRunState::new(Instant::now());
        match adapter
            .xfer_data(
                &mut adaptation_state,
                clt_r,
                ups_w,
                &self.mail_from,
                &self.mail_to,
            )
            .await
        {
            Ok(ReqmodAdaptationEndState::OriginalTransferred) => Ok(()),
            Ok(ReqmodAdaptationEndState::AdaptedTransferred) => Ok(()),
            Ok(ReqmodAdaptationEndState::HttpErrResponse(rsp, body)) => {
                // 读完并丢弃 HTTP 错误响应体，尽量回收连接后关闭
                if let Some(mut body) = body {
                    let mut body_reader = body.body_reader();
                    let mut sinker = tokio::io::sink();
                    let _ = tokio::io::copy(&mut body_reader, &mut sinker).await;
                    if body_reader.trailer(128).await.is_ok() {
                        body.save_connection().await;
                    }
                }
                let client_rsp = ResponseEncoder::message_blocked(
                    self.local_ip,
                    format!("ICAP Response {} {}", rsp.status, rsp.reason),
                );
                let _ = client_rsp.write(clt_w).await;
                Err(ServerTaskError::InternalAdapterError(anyhow!(
                    "blocked by icap server: {} - {}",
                    rsp.status,
                    rsp.reason
                )))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 传输 BDAT 声明的 `size` 字节二进制数据。
    /// 命令行缓冲里可能已预读到部分正文（命令与数据在同一 TCP 段到达），
    /// 先把这段缓存写往源站，剩余长度再用 `take` 精确拷贝。
    async fn send_bin_data<CR, UW>(
        &self,
        buf: &mut SmtpRelayBuf,
        clt_r: &mut CR,
        ups_w: &mut UW,
        size: usize,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut copy_size = size;
        let cache = buf.cmd_recv_buf.consume_left(size);
        if !cache.is_empty() {
            ups_w
                .write_all(cache)
                .await
                .map_err(ServerTaskError::UpstreamWriteFailed)?;
            copy_size -= cache.len();
            if copy_size == 0 {
                // 预读缓存已覆盖全部声明长度，无需再从 socket 读取
                ups_w
                    .flush()
                    .await
                    .map_err(ServerTaskError::UpstreamWriteFailed)?;
                return Ok(());
            }
        }

        let mut reader = clt_r.take(copy_size as u64);

        self.transfer_data(&mut reader, ups_w).await
    }

    /// 带空闲检测与限流的单向拷贝（客户端 -> 源站）。
    /// 空闲计数连续达到上限时，根据是否有未发送缓存判定超时方（客户端读空闲或源站写停滞）。
    async fn transfer_data<CR, UW>(&self, clt_r: &mut CR, ups_w: &mut UW) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut clt_to_ups =
            StreamCopy::new(clt_r, ups_w, &self.ctx.server_config.limited_copy_config());

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut clt_to_ups => {
                    return match r {
                        Ok(_) => {
                            // ups_w is already flushed
                            Ok(())
                        }
                        Err(StreamCopyError::ReadFailed(e)) => {
                            // 读侧失败前先把已缓存数据冲刷给源站，减少邮件损坏面
                            let _ = clt_to_ups.write_flush().await;
                            Err(ServerTaskError::ClientTcpReadFailed(e))
                        }
                        Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::UpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if clt_to_ups.is_idle() {
                        idle_count += n;
                        if idle_count >= self.ctx.max_idle_count {
                            // 无缓存数据 => 客户端不发数据；有缓存 => 源站不收数据
                            return if clt_to_ups.no_cached_data() {
                                Err(ServerTaskError::ClientAppTimeout("idle while reading BDAT data"))
                            } else {
                                Err(ServerTaskError::UpstreamAppTimeout("idle while sending BDAT data"))
                            };
                        }
                    } else {
                        idle_count = 0;
                        clt_to_ups.reset_active();
                    }

                    // 每个空闲周期复查用户封禁与服务退出，保证能快速中止长传输
                    if self.ctx.belongs_to_blocked_user() {
                        let _ = clt_to_ups.write_flush().await;
                        return Err(ServerTaskError::CanceledAsUserBlocked);
                    }

                    if self.ctx.server_force_quit() {
                        let _ = clt_to_ups.write_flush().await;
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }

    /// 转发 DATA 命令（当前与 [`send_cmd`] 相同，预留按命令类型差异化处理的钩子）。
    async fn send_data_cmd<UW, CW>(
        &self,
        ups_w: &mut UW,
        clt_w: &mut CW,
        cmd_line: &[u8],
    ) -> ServerTaskResult<()>
    where
        UW: AsyncWrite + Unpin,
        CW: AsyncWrite + Unpin,
    {
        self.send_cmd(ups_w, clt_w, cmd_line).await
    }

    /// 转发 BDAT 命令行（含长度参数），`_size` 仅用于接口一致性，实际按原行转发。
    async fn send_bdat_cmd<UW, CW>(
        &self,
        ups_w: &mut UW,
        clt_w: &mut CW,
        cmd_line: &[u8],
        _size: usize,
    ) -> ServerTaskResult<()>
    where
        UW: AsyncWrite + Unpin,
        CW: AsyncWrite + Unpin,
    {
        self.send_cmd(ups_w, clt_w, cmd_line).await
    }

    /// 转发 BURL 命令行（含 URL 参数），`_url` 仅用于接口一致性，实际按原行转发。
    async fn send_burl_cmd<UW, CW>(
        &self,
        ups_w: &mut UW,
        clt_w: &mut CW,
        cmd_line: &[u8],
        _url: String,
    ) -> ServerTaskResult<()>
    where
        UW: AsyncWrite + Unpin,
        CW: AsyncWrite + Unpin,
    {
        self.send_cmd(ups_w, clt_w, cmd_line).await
    }

    /// 把命令行原样写入源站并 flush；失败时先向客户端回 451 IO 错误再返回错误。
    async fn send_cmd<UW, CW>(
        &self,
        ups_w: &mut UW,
        clt_w: &mut CW,
        cmd_line: &[u8],
    ) -> ServerTaskResult<()>
    where
        UW: AsyncWrite + Unpin,
        CW: AsyncWrite + Unpin,
    {
        match ups_w.write_all_flush(cmd_line).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = ResponseEncoder::upstream_io_error(self.local_ip, &e)
                    .write(clt_w)
                    .await;
                Err(ServerTaskError::UpstreamWriteFailed(e))
            }
        }
    }

    /// 向客户端写入一条由 `rsp_encoder` 构造的本地错误响应。
    async fn send_error_to_client<W>(
        &self,
        clt_w: &mut W,
        rsp_encoder: ResponseEncoder,
    ) -> ServerTaskResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        rsp_encoder
            .write(clt_w)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)
    }
}
