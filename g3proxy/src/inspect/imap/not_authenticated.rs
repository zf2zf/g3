/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 未认证（not authenticated）状态的命令/响应中继。
//!
//! 该状态下客户端只允许 CAPABILITY、NOOP、ID、STARTTLS、AUTHENTICATE、LOGIN、
//! LOGOUT 等少数命令，其余命令以本机 BAD 响应就地拒绝（不转发源站）。
//! [`ImapInterceptObject::relay_not_authenticated`] 是整个循环的入口，带
//! authenticate_timeout 总超时；成功认证后返回 [`InitiationStatus::Authenticated`]
//! 交由上层进入已认证状态。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_imap_proto::command::{Command, ParsedCommand};
use g3_imap_proto::response::{
    BadResponse, ByeResponse, CommandData, CommandResult, Response, ServerStatus,
};
use g3_io_ext::LimitedWriteExt;

use super::{
    Capability, CommandLineReceiveExt, ImapInterceptObject, ImapRelayBuf, ResponseAction,
    ResponseLineReceiveExt,
};
use crate::config::server::ServerConfig;
use crate::serve::{ServerTaskError, ServerTaskResult};

/// 处理一条客户端命令后的本地动作决策
enum ClientAction {
    /// 普通转发，继续主循环
    Loop,
    /// LOGOUT：进入登出收尾
    Logout,
    /// AUTHENTICATE：需要多轮挑战/应答，切换到专用等待循环
    Auth,
    /// STARTTLS：需要确认源站能力响应后升级 TLS
    StartTls,
    /// 命令带非同步字面量，先把 size 字节的字面量数据中继给源站
    SendLiteral(u64),
}

/// 未认证状态中继的结束原因，决定上层（mod.rs）的状态转移
pub(super) enum InitiationStatus {
    /// 源站关闭连接（收到 * BYE 或 EOF）
    ServerClose,
    /// 客户端发出 LOGOUT 正常登出
    ClientClose,
    /// STARTTLS 成功，流应移交给 TLS 检测对象
    StartTls,
    /// 认证成功，进入已认证状态
    Authenticated,
    /// 本机主动断开（超时/出错），携带待上报的错误
    LocalClose(ServerTaskError),
}

impl<SC> ImapInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 未认证状态中继入口：在 authenticate_timeout 内等待客户端完成认证，
    /// 超时则回 BYE blocked 并返回 LocalClose（防止长期停留在未认证探测）
    pub(super) async fn relay_not_authenticated<CR, CW, UR, UW>(
        &mut self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<InitiationStatus>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(
            self.ctx.imap_interception().authenticate_timeout,
            self.do_relay_not_authenticated(clt_r, clt_w, ups_r, ups_w, relay_buf),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => {
                let _ = ByeResponse::reply_blocked(clt_w).await;
                Ok(InitiationStatus::LocalClose(
                    ServerTaskError::ClientAppTimeout("timeout to enter IMAP authenticated state"),
                ))
            }
        }
    }

    /// 未认证状态主循环：双向 select 同时收客户端命令行与源站响应行。
    /// 命令侧先检查管线中是否有待续传的 literal 命令，有则把本行当作
    /// 命令续行解析；无则按新命令分发
    pub(super) async fn do_relay_not_authenticated<CR, CW, UR, UW>(
        &mut self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<InitiationStatus>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            relay_buf.cmd_recv_buf.consume_line();
            relay_buf.rsp_recv_buf.consume_line();
            tokio::select! {
                r = relay_buf.cmd_recv_buf.recv_cmd_line(clt_r) => {
                    let line = r?;
                    if let Some(mut cmd) = self.cmd_pipeline.take_ongoing_command() {
                        // 管线里挂着的命令还差续行/字面量数据，本行属于它的续传
                        self.handle_cmd_continue_line(line, &mut cmd, clt_w, ups_w).await?;
                        if let Some(literal) = cmd.literal_arg {
                            self.cmd_pipeline.set_ongoing_command(cmd);
                            if !literal.wait_continuation {
                                // 同步字面量（LITERAL+）：客户端已直接跟发数据，立即中继
                                self.relay_client_literal(literal.size, clt_r, clt_w, ups_w, relay_buf).await?;
                            }
                        } else {
                            self.cmd_pipeline.insert_completed(cmd);
                        }
                    } else {
                        match self.handle_not_authenticated_cmd_line(line, clt_w, ups_w).await? {
                            ClientAction::Auth => {
                                // 逐条转发源站响应直到 AUTHENTICATE 的 tagged 结果；
                                // 认证失败（返回 None）则回到主循环继续观察
                                if let Some(status) = self.wait_relay_authenticate_response(
                                    clt_r,
                                    clt_w,
                                    ups_r,
                                    ups_w,
                                    relay_buf,
                                ).await? {
                                    return Ok(status);
                                }
                            }
                            ClientAction::StartTls => {
                                if let Some(status) = self.wait_relay_starttls_response(
                                    clt_w,
                                    ups_r,
                                    relay_buf,
                                ).await? {
                                    return Ok(status);
                                }
                            }
                            ClientAction::Logout => {
                                return Ok(InitiationStatus::ClientClose);
                            }
                            ClientAction::SendLiteral(size) => {
                                self.relay_client_literal(size, clt_r, clt_w, ups_w, relay_buf).await?;
                            }
                            ClientAction::Loop => {}
                        }
                    }
                }
                r = relay_buf.rsp_recv_buf.recv_rsp_line(ups_r) => {
                    let line = r?;
                    // 源站响应统一交给 forward.rs 的 handle_rsp_line 处理（含能力改写）
                    match self.handle_rsp_line(line, clt_w).await? {
                        ResponseAction::Loop => {}
                        ResponseAction::Close => return Ok(InitiationStatus::ServerClose),
                        ResponseAction::SendLiteral(size) => {
                            self.relay_server_literal(size, clt_w, ups_r,  relay_buf).await?;
                        }
                        ResponseAction::RecvClientLiteral(size) => {
                             self.relay_client_literal(size, clt_r, clt_w, ups_w, relay_buf).await?;
                        }
                    }
                }
            }
        }
    }

    /// 解析并分类一条未认证状态的新命令：合法命令记入管线并原样转发源站；
    /// 该状态下非法的命令就地回 BAD（不转发）；解析失败视为客户端协议违例，
    /// 回 BYE 并终止任务
    async fn handle_not_authenticated_cmd_line<CW, UW>(
        &mut self,
        line: &[u8],
        clt_w: &mut CW,
        ups_w: &mut UW,
    ) -> ServerTaskResult<ClientAction>
    where
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        match Command::parse_line(line) {
            Ok(cmd) => {
                let mut action = ClientAction::Loop;
                match cmd.parsed {
                    ParsedCommand::Capability | ParsedCommand::NoOperation | ParsedCommand::Id => {
                        // 无续行数据的命令：记入管线等待配对响应后即可转发
                        self.cmd_pipeline.insert_completed(cmd);
                    }
                    ParsedCommand::Logout => {
                        self.cmd_pipeline.insert_completed(cmd);
                        action = ClientAction::Logout;
                    }
                    ParsedCommand::StartTls => {
                        if self.from_starttls {
                            // TLS 已经升级过，再次 STARTTLS 无意义，直接拒绝
                            BadResponse::reply_invalid_command(clt_w, cmd.tag.as_str())
                                .await
                                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                            return Ok(action);
                        } else {
                            self.cmd_pipeline.insert_completed(cmd);
                        }
                        // 成功与否要看源站的 tagged 响应，交由专用循环判断
                        action = ClientAction::StartTls;
                    }
                    ParsedCommand::Auth => {
                        self.cmd_pipeline.insert_completed(cmd);
                        action = ClientAction::Auth;
                    }
                    ParsedCommand::Login => {
                        // LOGIN 的口令参数可能是非同步字面量，需先中继数据
                        if let Some(literal) = cmd.literal_arg {
                            if !literal.wait_continuation {
                                action = ClientAction::SendLiteral(literal.size);
                            }
                            self.cmd_pipeline.set_ongoing_command(cmd);
                        } else {
                            self.cmd_pipeline.insert_completed(cmd);
                        }
                    }
                    _ => {
                        // 其余命令（SELECT/FETCH 等）在未认证状态下非法，就地回 BAD
                        BadResponse::reply_invalid_command(clt_w, cmd.tag.as_str())
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        return Ok(action);
                    }
                }

                // 通过检查的命令原样转发给源站
                ups_w
                    .write_all_flush(line)
                    .await
                    .map_err(ServerTaskError::UpstreamWriteFailed)?;
                Ok(action)
            }
            Err(e) => {
                // 命令行无法解析：客户端协议违例，无法继续逐行检测
                let _ = ByeResponse::reply_client_protocol_error(clt_w).await;
                Err(ServerTaskError::ClientAppError(anyhow!(
                    "invalid IMAP command line: {e}"
                )))
            }
        }
    }

    /// 转发并等待 STARTTLS 命令的 tagged 结果。返回 `Some` 表示状态结束
    /// （升级成功或源站关闭）；返回 `None` 表示 STARTTLS 失败（FAIL/NOOP 等），
    /// 连接仍在未认证状态，交回主循环继续
    async fn wait_relay_starttls_response<CW, UR>(
        &mut self,
        clt_w: &mut CW,
        ups_r: &mut UR,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<Option<InitiationStatus>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        loop {
            relay_buf.rsp_recv_buf.consume_line();
            let line = relay_buf.rsp_recv_buf.recv_rsp_line(ups_r).await?;
            let rsp = match Response::parse_line(line) {
                Ok(rsp) => rsp,
                Err(e) => {
                    let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                    return Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "invalid IMAP STARTTLS response line: {e}"
                    )));
                }
            };

            match rsp {
                Response::CommandResult(r) => {
                    // tagged 结果必须能配对到管线中记录的命令，否则源站协议违例
                    let Some(cmd) = self.cmd_pipeline.remove(&r.tag) else {
                        let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                        return Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected IMAP command result for tag {}",
                            r.tag
                        )));
                    };
                    if cmd.parsed != ParsedCommand::StartTls {
                        // 等待期间却收到其它命令的配对结果，说明源站标签错乱
                        let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                        return Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected IMAP command result for STARTTLS command"
                        )));
                    }

                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    return match r.result {
                        // OK 才能开始 TLS 握手；NO/BAD 则留在未认证状态继续中继
                        CommandResult::Success => Ok(Some(InitiationStatus::StartTls)),
                        CommandResult::Fail => Ok(None),
                        CommandResult::ProtocolError => Ok(None),
                    };
                }
                Response::ServerStatus(ServerStatus::Close) => {
                    // * BYE：源站登出，先把该行转发给客户端
                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    return Ok(Some(InitiationStatus::ServerClose));
                }
                Response::ServerStatus(_s) => {
                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                }
                Response::CommandData(d) => {
                    if d.command_data == CommandData::Capability {
                        // STARTTLS 成功后源站可能推新能力列表，需按白名单改写
                        self.write_capability_response(line, clt_w).await?;
                    } else {
                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    }
                }
                Response::ContinuationRequest => {
                    // STARTTLS 没有续传需求，`+` 响应属源站协议违例
                    let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                    return Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "unexpected IMAP continuation request response for STARTTLS command",
                    )));
                }
            }
        }
    }

    /// 转发并等待 AUTHENTICATE 的 tagged 结果；期间处理 SASL 挑战/应答的往返
    /// （`+` 挑战转给客户端，客户端应答转给源站）。返回 `Some` 表示状态结束；
    /// 返回 `None` 表示认证被拒（NO/BAD），回到主循环允许客户端重试
    async fn wait_relay_authenticate_response<CR, CW, UR, UW>(
        &mut self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<Option<InitiationStatus>>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            relay_buf.rsp_recv_buf.consume_line();
            let line = relay_buf.rsp_recv_buf.recv_rsp_line(ups_r).await?;
            let rsp = match Response::parse_line(line) {
                Ok(rsp) => rsp,
                Err(e) => {
                    let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                    return Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "invalid IMAP AUTHENTICATE response line: {e}"
                    )));
                }
            };

            match rsp {
                Response::CommandResult(r) => {
                    let Some(cmd) = self.cmd_pipeline.remove(&r.tag) else {
                        let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                        return Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected IMAP command result for tag {}",
                            r.tag
                        )));
                    };
                    if cmd.parsed != ParsedCommand::Auth {
                        let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                        return Err(ServerTaskError::UpstreamAppError(anyhow!(
                            "unexpected IMAP command result for command {}",
                            cmd
                        )));
                    }

                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    return match r.result {
                        // 认证成功：置位并通知上层切换到已认证状态
                        CommandResult::Success => {
                            self.authenticated = true;
                            Ok(Some(InitiationStatus::Authenticated))
                        }
                        CommandResult::Fail => Ok(None),
                        CommandResult::ProtocolError => Ok(None),
                    };
                }
                Response::ServerStatus(ServerStatus::Close) => {
                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    return Ok(Some(InitiationStatus::ServerClose));
                }
                Response::ServerStatus(_s) => {
                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                }
                Response::CommandData(d) => {
                    if d.command_data == CommandData::Capability {
                        self.write_capability_response(line, clt_w).await?;
                    } else {
                        clt_w
                            .write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    }
                }
                Response::ContinuationRequest => {
                    // `+ <挑战>`：转给客户端，再把客户端的应答原样转回源站
                    clt_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                    relay_buf.cmd_recv_buf.consume_line();
                    let line = relay_buf.cmd_recv_buf.recv_cmd_line(clt_r).await?;
                    // 客户端可以发送单独一行 "*" 取消本次认证，
                    // 但源站无论如何都必须补发最终的 tagged 响应
                    ups_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::UpstreamWriteFailed)?;
                }
            }
        }
    }

    /// 改写源站的 untagged `* CAPABILITY` 响应：只保留本机支持的能力并重建
    /// 该行发给客户端，同时用新解析出的能力集合覆盖 self.capability
    pub(super) async fn write_capability_response<CW>(
        &mut self,
        line: &[u8],
        clt_w: &mut CW,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
    {
        let orig = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end(),
            Err(e) => {
                let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                return Err(ServerTaskError::UpstreamAppError(anyhow!(
                    "invalid IMAP response line: {e}"
                )));
            }
        };

        let upper = orig.to_uppercase();
        // 在大写副本上做前缀匹配与切分：能力名本身大小写不敏感，统一后可直接查表
        let Some(list) = upper.strip_prefix("* CAPABILITY ") else {
            let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
            return Err(ServerTaskError::UpstreamAppError(anyhow!(
                "invalid IMAP CAPABILITY response line prefix"
            )));
        };

        // 收到新的能力列表即整体重建（覆盖旧值），未识别项被 check_supported 过滤掉
        let mut new_cap = Capability::default();

        let mut new_line = Vec::with_capacity(line.len());
        new_line.extend_from_slice(b"* CAPABILITY");
        for item in list.split(' ') {
            if let Some(cap) = new_cap.check_supported(item, false) {
                new_line.push(b' ');
                new_line.extend_from_slice(cap.as_bytes());
            }
        }
        self.capability = new_cap;

        new_line.extend_from_slice(b"\r\n");
        clt_w
            .write_all_flush(&new_line)
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)
    }
}
