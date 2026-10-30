/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 命令/响应的逐行分发与字面量（literal）数据转发。
//!
//! 被未认证与已认证两个中继循环共用：[`ImapInterceptObject::handle_rsp_line`]
//! 解析源站响应并决定下一步动作（含 mailbox_selected 状态维护与能力改写），
//! [`ImapInterceptObject::relay_client_literal`] / `relay_server_literal` 以
//! StreamCopy 大块搬运字面量数据并做空闲/封禁检查；APPEND 的邮件内容还会
//! 视配置交给 ICAP reqmod 做内容改写。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_icap_client::reqmod::imap::ImapMessageAdapter;
use g3_icap_client::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use g3_imap_proto::command::{Command, ParsedCommand};
use g3_imap_proto::response::{
    BadResponse, ByeResponse, CommandData, CommandResult, Response, ServerStatus, UntaggedResponse,
};
use g3_io_ext::{LimitedWriteExt, StreamCopy, StreamCopyError};

use super::{ImapInterceptObject, ImapRelayBuf};
use crate::config::server::ServerConfig;
use crate::serve::{ServerIdleChecker, ServerTaskError, ServerTaskResult};

/// 处理一条源站响应后的转发决策
pub(super) enum ResponseAction {
    /// 已转发完毕，继续主循环
    Loop,
    /// 收到 `* BYE`，连接即将由源站关闭
    Close,
    /// 响应含未传完的字面量，需从源站继续读 size 字节转发给客户端
    SendLiteral(u64),
    /// 收到 `+` 续传请求，需从客户端读 size 字节字面量数据转发给源站
    RecvClientLiteral(u64),
}

impl<SC> ImapInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 把客户端命令的续行喂给管线中挂起的命令继续解析，解析成功则原样转发源站；
    /// 解析失败视为客户端协议违例
    pub(super) async fn handle_cmd_continue_line<CW, UW>(
        &mut self,
        line: &[u8],
        cmd: &mut Command,
        clt_w: &mut CW,
        ups_w: &mut UW,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match cmd.parse_continue_line(line) {
            Ok(_) => {
                ups_w
                    .write_all_flush(line)
                    .await
                    .map_err(ServerTaskError::UpstreamWriteFailed)?;
                Ok(())
            }
            Err(e) => {
                let _ = ByeResponse::reply_client_protocol_error(clt_w).await;
                Err(ServerTaskError::ClientAppError(anyhow!(
                    "invalid IMAP command line: {e}"
                )))
            }
        }
    }

    /// 把客户端命令携带的 size 字节字面量数据中继给源站。APPEND 的邮件内容若
    /// 配置了 ICAP reqmod 则改走改写路径；其余情况先复用行缓冲中已预读的字节，
    /// 剩余部分用 StreamCopy 限长搬运，期间做空闲（transfer_max_idle_count）、
    /// 用户封禁与服务退出检查
    pub(super) async fn relay_client_literal<CR, CW, UW>(
        &mut self,
        literal_size: u64,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // 字面量必属于管线中挂起的命令，否则协议流已错乱
        let Some(cmd) = self.cmd_pipeline.ongoing_command() else {
            return Err(ServerTaskError::InternalServerError(
                "no ongoing IMAP command set while transferring literal data",
            ));
        };

        if cmd.parsed == ParsedCommand::Append
            && let Some(client) = self.ctx.audit_handle.icap_reqmod_client()
        {
            // 邮件正文交给 ICAP 服务器检测/改写后再写出源站
            match client
                .imap_message_adaptor(
                    self.ctx.server_config.limited_copy_config(),
                    self.ctx.idle_checker(),
                    literal_size,
                )
                .await
            {
                Ok(adapter) => {
                    return self
                        .relay_append_literal_with_adaptation(
                            literal_size,
                            clt_r,
                            clt_w,
                            ups_w,
                            relay_buf,
                            adapter,
                        )
                        .await;
                }
                Err(e) => {
                    // ICAP 不可用：配置了容错放行则退回普通中继，否则终止
                    if !client.bypass() {
                        return Err(ServerTaskError::InternalAdapterError(e));
                    }
                }
            }
        }

        // 客户端 pipelining 时字面量可能已部分躺在行缓冲里，先复用这些缓存字节
        relay_buf.cmd_recv_buf.consume_line();
        let cached = relay_buf
            .cmd_recv_buf
            .consume_left(literal_size.min(usize::MAX as u64) as usize);
        ups_w
            .write_all(cached)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        if literal_size > cached.len() as u64 {
            // take() 把读取限制在剩余字面量长度内，防止多读入下一条命令行
            let mut clt_r = clt_r.take(literal_size - cached.len() as u64);

            let mut idle_interval = self.ctx.idle_wheel.register();
            let mut idle_count = 0;
            let max_idle_count = self.ctx.imap_interception().transfer_max_idle_count;

            let mut clt_to_ups = StreamCopy::new(&mut clt_r, ups_w, &Default::default());

            loop {
                tokio::select! {
                    biased;
                    // 优先让拷贝任务推进，其次才检查空闲与策略

                    r = &mut clt_to_ups => {
                        return match r {
                            Ok(_) => {
                                // ups_w is already flushed
                                // （源站写端在 StreamCopy 结束时已冲刷，无需再 flush）
                                Ok(())
                            }
                            Err(StreamCopyError::ReadFailed(e)) => {
                                // 读侧出错也要把已缓存的字节冲给源站，保持数据完整
                                let _ = clt_to_ups.write_flush().await;
                                Err(ServerTaskError::ClientTcpReadFailed(e))
                            }
                            Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::UpstreamWriteFailed(e)),
                        };
                    }
                    n = idle_interval.tick() => {
                        if clt_to_ups.is_idle() {
                            idle_count += n;
                            if idle_count >= max_idle_count {
                                // 依缓存中是否还留有未写出数据，把责任归给客户端或源站
                                return if clt_to_ups.no_cached_data() {
                                    Err(ServerTaskError::ClientAppTimeout("idle while reading literal data"))
                                } else {
                                    Err(ServerTaskError::UpstreamAppTimeout("idle while sending literal data"))
                                };
                            }
                        } else {
                            idle_count = 0;
                            clt_to_ups.reset_active();
                        }

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
        ups_w
            .flush()
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)
    }

    /// APPEND 字面量经 ICAP reqmod 改写后转发：向 ICAP 请求注入客户端地址与
    /// 用户名供其做内容决策；ICAP 返回错误响应表示邮件被拒，此时向客户端回
    /// BAD + BYE blocked 并以适配错误终止任务
    pub(super) async fn relay_append_literal_with_adaptation<CR, CW, UW>(
        &mut self,
        literal_size: u64,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
        mut adapter: ImapMessageAdapter<ServerIdleChecker>,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        adapter.set_client_addr(self.ctx.task_notes.client_addr);
        if let Some(username) = self.ctx.raw_user_name() {
            adapter.set_client_username(username.clone());
        }

        relay_buf.cmd_recv_buf.consume_line();
        let cached = relay_buf
            .cmd_recv_buf
            .consume_left(literal_size.min(usize::MAX as u64) as usize);

        // 已缓存字节足够时走单次（one-shot）REQMOD 请求，否则从客户端继续流式
        // 读取剩余邮件内容逐段送 ICAP；两种情况都会把内容写到 ups_w
        let mut adaptation_state = ReqmodAdaptationRunState::new(Instant::now());
        match adapter
            .xfer_append(&mut adaptation_state, clt_r, cached, ups_w)
            .await
        {
            // 原文透传或改写后写出，两者对协议流程均无影响
            Ok(ReqmodAdaptationEndState::OriginalTransferred) => Ok(()),
            Ok(ReqmodAdaptationEndState::AdaptedTransferred) => Ok(()),
            Ok(ReqmodAdaptationEndState::HttpErrResponse(rsp, body)) => {
                // ICAP 拒绝该邮件：先把剩余响应体读完以便安全复用连接
                if let Some(mut body) = body {
                    let mut body_reader = body.body_reader();
                    let mut sinker = tokio::io::sink();
                    let _ = tokio::io::copy(&mut body_reader, &mut sinker).await;
                    if body_reader.trailer(128).await.is_ok() {
                        body.save_connection().await;
                    }
                }
                // 先回该命令的 BAD 结果，再补 BYE 终止整个会话
                if let Some(cmd) = self.cmd_pipeline.ongoing_command()
                    && BadResponse::reply_append_blocked(clt_w, &cmd.tag)
                        .await
                        .is_ok()
                {
                    let _ = ByeResponse::reply_blocked(clt_w).await;
                }
                Err(ServerTaskError::InternalAdapterError(anyhow!(
                    "blocked by icap server: {} - {}",
                    rsp.status,
                    rsp.reason
                )))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 把源站响应的续行喂给挂起的 untagged 响应继续解析（多行响应如 FETCH 的
    /// 邮件结构体），解析成功后原样转发客户端。注意错误被归因为客户端侧
    /// （沿用既有行为），实际是源站输出违反协议
    pub(super) async fn handle_rsp_continue_line<CW>(
        &mut self,
        line: &[u8],
        rsp: &mut UntaggedResponse,
        clt_w: &mut CW,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
    {
        rsp.parse_continue_line(line).map_err(|e| {
            ServerTaskError::ClientAppError(anyhow!("invalid IMAP command line: {e}"))
        })?;
        clt_w
            .write_all_flush(line)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        Ok(())
    }

    /// 把源站响应携带的 size 字节字面量数据（如 FETCH 回的信封正文）中继给
    /// 客户端。与 relay_client_literal 对称：先复用行缓冲中的缓存字节，剩余
    /// 部分 StreamCopy 限长搬运，并做空闲/封禁/退出检查
    pub(super) async fn relay_server_literal<CW, UR>(
        &mut self,
        literal_size: u64,
        clt_w: &mut CW,
        ups_r: &mut UR,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        relay_buf.rsp_recv_buf.consume_line();
        let cached = relay_buf
            .rsp_recv_buf
            .consume_left(literal_size.min(usize::MAX as u64) as usize);
        clt_w
            .write_all(cached)
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;
        if literal_size > cached.len() as u64 {
            // take() 把读取限制在剩余字面量长度内，防止多读入下一条响应行
            let mut ups_r = ups_r.take(literal_size - cached.len() as u64);

            let mut idle_interval = self.ctx.idle_wheel.register();
            let mut idle_count = 0;
            let max_idle_count = self.ctx.imap_interception().transfer_max_idle_count;

            let mut ups_to_clt = StreamCopy::new(&mut ups_r, clt_w, &Default::default());

            loop {
                tokio::select! {
                    biased;

                    r = &mut ups_to_clt => {
                        return match r {
                            Ok(_) => {
                                // clt_w is already flushed
                                Ok(())
                            }
                            Err(StreamCopyError::ReadFailed(e)) => {
                                let _ = ups_to_clt.write_flush().await;
                                Err(ServerTaskError::UpstreamReadFailed(e))
                            }
                            Err(StreamCopyError::WriteFailed(e)) => Err(ServerTaskError::ClientTcpWriteFailed(e)),
                        };
                    }
                    n = idle_interval.tick() => {
                        if ups_to_clt.is_idle() {
                            idle_count += n;
                            if idle_count >= max_idle_count {
                                return if ups_to_clt.no_cached_data() {
                                    Err(ServerTaskError::UpstreamAppTimeout("idle while reading literal data"))
                                } else {
                                    Err(ServerTaskError::ClientAppTimeout("idle while sending literal data"))
                                };
                            }
                        } else {
                            idle_count = 0;
                            ups_to_clt.reset_active();
                        }

                        if self.ctx.belongs_to_blocked_user() {
                            let _ = ups_to_clt.write_flush().await;
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                        if self.ctx.server_force_quit() {
                            let _ = ups_to_clt.write_flush().await;
                            return Err(ServerTaskError::CanceledAsServerQuit)
                        }
                    }
                }
            }
        }
        clt_w
            .flush()
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)
    }

    /// 未认证/已认证主循环共用的响应分发器：解析一行源站响应，改写或转发，
    /// 并返回下一步动作。带标签（tagged）结果需与管线中记录的命令配对，并据
    /// 命令类型维护 mailbox_selected 状态；`* CAPABILITY`/`* ENABLED` 走白名单
    /// 改写；`+` 续传请求区分 IDLE（直接放行）与非同步字面量（待收客户端数据）
    pub(super) async fn handle_rsp_line<CW>(
        &mut self,
        line: &[u8],
        clt_w: &mut CW,
    ) -> ServerTaskResult<ResponseAction>
    where
        CW: AsyncWrite + Unpin,
    {
        match Response::parse_line(line) {
            Ok(rsp) => {
                let mut action = ResponseAction::Loop;
                match rsp {
                    Response::CommandResult(r) => {
                        // tagged 结果必须能配对到之前记录的命令，否则源站标签错乱
                        let Some(cmd) = self.cmd_pipeline.remove(&r.tag) else {
                            let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                            return Err(ServerTaskError::UpstreamAppError(anyhow!(
                                "unexpected IMAP command result for tag {}",
                                r.tag
                            )));
                        };
                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        if r.result == CommandResult::Success {
                            // 用命令语义同步邮箱选择状态，供后续命令合法性检查
                            match cmd.parsed {
                                ParsedCommand::Select | ParsedCommand::Examine => {
                                    self.mailbox_selected = true;
                                }
                                ParsedCommand::Close | ParsedCommand::Unselect => {
                                    self.mailbox_selected = false;
                                }
                                _ => {}
                            }
                        }
                    }
                    Response::ServerStatus(ServerStatus::Close) => {
                        // * BYE：转发后通知主循环按源站关闭收尾
                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        action = ResponseAction::Close;
                    }
                    Response::ServerStatus(_s) => {
                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    }
                    Response::CommandData(d) => {
                        match d.command_data {
                            CommandData::Capability => {
                                self.write_capability_response(line, clt_w).await?;
                            }
                            CommandData::Enabled => {
                                self.write_enabled_response(line, clt_w).await?;
                            }
                            _ => {
                                clt_w
                                    .write_all_flush(line)
                                    .await
                                    .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                            }
                        }

                        if let Some(size) = d.literal_data {
                            // 响应带字面量（如 FETCH 的信封），挂起响应等待续传
                            self.cmd_pipeline.set_ongoing_response(d);
                            action = ResponseAction::SendLiteral(size);
                        }
                    }
                    Response::ContinuationRequest => {
                        // `+` 只应出现在有挂起命令等待续传时
                        let Some(cmd) = self.cmd_pipeline.ongoing_command() else {
                            let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                            return Err(ServerTaskError::UpstreamAppError(anyhow!(
                                "no ongoing IMAP command found when received continuation request"
                            )));
                        };

                        if cmd.parsed == ParsedCommand::Idle {
                            // IDLE 的 `+ ready`：放行后等 DONE，主循环继续观察
                            clt_w
                                .write_all_flush(line)
                                .await
                                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                            return Ok(ResponseAction::Loop);
                        }

                        // 同步字面量（LITERAL- 等）的 `+`：客户端接下来要发字面量数据
                        let Some(literal) = cmd.literal_arg else {
                            let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                            return Err(ServerTaskError::UpstreamAppError(anyhow!(
                                "unexpected IMAP continuation request"
                            )));
                        };

                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        action = ResponseAction::RecvClientLiteral(literal.size);
                    }
                }
                Ok(action)
            }
            Err(e) => {
                let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                Err(ServerTaskError::UpstreamAppError(anyhow!(
                    "invalid IMAP response line: {e}"
                )))
            }
        }
    }
}
