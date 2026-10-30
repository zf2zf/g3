/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 命令转发阶段：会话建立（EHLO 协商）完成后的通用命令中继循环。
//!
//! [`Forward`] 逐条接收客户端命令、转发源站并中继响应，对时序敏感的命令
//! （MAIL/RCPT/DATA/BDAT 等）在事务之外收到时本地回 503 拒绝。
//! 当收到需要特殊处理的命令时，通过 [`ForwardNextAction`] 把控制权交回上层状态机：
//! 进入事务、升级 TLS、切透明中继（反向连接）或结束会话。

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use g3_dpi::SmtpInterceptionConfig;
use g3_io_ext::{LimitedWriteExt, LineRecvBuf};
use g3_smtp_proto::command::{Command, MailParam};
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseParser};

use super::{
    CommandLineRecvExt, InitializedExtensions, Initiation, ResponseLineRecvExt, ResponseParseExt,
    SmtpRelayBuf,
};
use crate::serve::{ServerTaskError, ServerTaskResult};

/// [`Forward`] 退出时告知上层下一步该进入哪个状态。
pub(super) enum ForwardNextAction {
    /// 客户端已 QUIT，关闭会话。
    Quit,
    /// STARTTLS 协商成功，切换到 TLS 拦截状态机。
    StartTls,
    /// ODMR 反向连接（ATRN 成功），无法内容拦截，转透明中继。
    ReverseConnection,
    /// 客户端重新 EHLO，用新的扩展能力集合刷新会话状态。
    SetExtensions(InitializedExtensions),
    /// MAIL FROM 被源站接受（250），携带发件人参数进入事务阶段。
    MailTransport(MailParam),
}

/// 命令转发状态机：处理事务边界之外的一切客户端命令。
pub(super) struct Forward<'a> {
    config: &'a SmtpInterceptionConfig,
    local_ip: IpAddr,
    allow_odmr: bool,     // 本会话是否允许 ATRN 反向连接
    allow_starttls: bool, // 本会话是否允许 STARTTLS 升级
    auth_end: bool,       // 是否已完成 AUTH 认证（ATRN 等命令的前置条件）
}

impl<'a> Forward<'a> {
    /// 每轮转发循环新建一个实例：扩展许可（odmr/starttls）随 EHLO 结果变化，
    /// 且 `auth_end` 等瞬态标志不应跨轮残留。
    pub(super) fn new(
        config: &'a SmtpInterceptionConfig,
        local_ip: IpAddr,
        allow_odmr: bool,
        allow_starttls: bool,
    ) -> Self {
        Forward {
            config,
            local_ip,
            allow_odmr,
            allow_starttls,
            auth_end: false,
        }
    }

    /// 命令转发主循环：返回 [`ForwardNextAction`] 表示需要上层切换状态；
    /// 普通命令（VRFY/RSET/NOOP 等）走默认分支直接转发并中继响应，循环继续。
    pub(super) async fn relay<CR, CW, UR, UW>(
        &mut self,
        buf: &mut SmtpRelayBuf,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
    ) -> ServerTaskResult<ForwardNextAction>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        loop {
            buf.cmd_recv_buf.consume_line();
            let (cmd, cmd_line) = buf
                .cmd_recv_buf
                .recv_cmd(self.config.command_wait_timeout, clt_r, clt_w)
                .await?;

            match cmd {
                // 这些命令只应在事务阶段出现，转发阶段收到即时序错误，本地回 503
                Command::Hello(_)
                | Command::Recipient(_)
                | Command::Data
                | Command::BinaryData(_)
                | Command::LastBinaryData(_)
                | Command::DataByUrl(_)
                | Command::LastDataByUrl(_) => {
                    self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                        .await?;
                }
                Command::Quit => {
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let _ = self.recv_relay_rsp(buf, ups_r, clt_w).await?;
                    return Ok(ForwardNextAction::Quit);
                }
                Command::StartTls => {
                    // 不允许时先回 502 拒绝本地，但仍把命令透传源站：
                    // 若源站也接受（250），由源站的拒绝逻辑处理后续
                    if !self.allow_starttls {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                    }
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let rsp = self.recv_relay_rsp(buf, ups_r, clt_w).await?;
                    // 源站回 250 表示已准备好 TLS 握手，交由上层切换状态机
                    if rsp == ReplyCode::SERVICE_READY {
                        return Ok(ForwardNextAction::StartTls);
                    }
                }
                Command::Auth => {
                    // AUTH 只在事务之外合法；auth_end 置位后再次 AUTH 属时序错误
                    if self.auth_end {
                        self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                            .await?;
                    }
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    self.recv_relay_auth(buf, clt_r, clt_w, ups_r, ups_w)
                        .await?;
                }
                Command::AuthenticatedTurn => {
                    // ATRN（ODMR 反向连接）：要求扩展被允许且已完成认证，两者缺一本地拒绝
                    if !self.allow_odmr {
                        self.send_error_to_client(clt_w, ResponseEncoder::COMMAND_NOT_IMPLEMENTED)
                            .await?;
                    }
                    if !self.auth_end {
                        self.send_error_to_client(clt_w, ResponseEncoder::AUTHENTICATION_REQUIRED)
                            .await?;
                    }
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    // a max 10min timeout according to RFC2645
                    // 源站可能等待较久（准备反向连接），响应 250 后转透明中继
                    let rsp = self.recv_relay_rsp(buf, ups_r, clt_w).await?;
                    if rsp == ReplyCode::OK {
                        return Ok(ForwardNextAction::ReverseConnection);
                    }
                }
                Command::ExtendHello(_host) => {
                    // 会话中途重新 EHLO：复用 Initiation 的响应过滤逻辑刷新扩展能力
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let mut initialization = Initiation::new(self.config, self.local_ip, true);
                    if initialization
                        .recv_relay_check_rsp(&mut buf.rsp_recv_buf, ups_r, clt_w)
                        .await?
                        .is_some()
                    {
                        let (_, extensions) = initialization.into_parts();
                        return Ok(ForwardNextAction::SetExtensions(extensions));
                    }
                }
                Command::Mail(param) => {
                    // MAIL FROM 被源站接受后进入事务阶段处理 RCPT/DATA
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    let rsp = self.recv_relay_rsp(buf, ups_r, clt_w).await?;
                    if rsp == ReplyCode::OK {
                        return Ok(ForwardNextAction::MailTransport(param));
                    }
                }
                // 其余命令（HELP/RSET/NOOP/VRFY 等）无状态影响，直接透传
                _ => {
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                    self.recv_relay_rsp(buf, ups_r, clt_w).await?;
                }
            }
        }
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

    /// 逐行读取源站响应并原样转发给客户端，直到完整响应结束，返回最终响应码。
    /// 421（SERVICE_NOT_AVAILABLE）表示源站即将下线，转换为 `UpstreamAppUnavailable` 错误。
    async fn recv_relay_rsp<CW, UR>(
        &mut self,
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
                .read_rsp_line_with_feedback(
                    self.config.response_wait_timeout,
                    ups_r,
                    clt_w,
                    self.local_ip,
                )
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

    /// AUTH 命令的多轮挑战/应答中继：源站每回 334（AUTH_CONTINUE）就转发客户端的下一条
    /// base64 应答行，直到出现 235（认证成功，置位 `auth_end`）或最终失败响应。
    /// 凭据内容不做解析，仅透传。
    async fn recv_relay_auth<CR, CW, UR, UW>(
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
        loop {
            let rsp = self.recv_relay_rsp(buf, ups_r, clt_w).await?;
            match rsp {
                ReplyCode::AUTHENTICATION_SUCCESSFUL => {
                    // 认证成功：允许后续依赖认证的命令（如 ATRN）
                    self.auth_end = true;
                    return Ok(());
                }
                ReplyCode::AUTH_CONTINUE => {}
                // 其它响应码表示认证已终结（成功例外）或失败，直接返回
                _ => return Ok(()),
            }

            // 334 挑战：把客户端的应答行（base64 数据，非 SMTP 命令）透传给源站
            let mut recv_buf = LineRecvBuf::<{ Command::MAX_CONTINUE_LINE_SIZE }>::default();
            match recv_buf
                .read_line_with_timeout(clt_r, self.config.command_wait_timeout)
                .await
            {
                Ok(line) => {
                    ups_w
                        .write_all_flush(line)
                        .await
                        .map_err(ServerTaskError::UpstreamWriteFailed)?;
                    recv_buf.consume_line();
                }
                Err(e) => {
                    let e = LineRecvBuf::<{ Command::MAX_CONTINUE_LINE_SIZE }>::handle_line_error(
                        e, clt_w,
                    )
                    .await;
                    return Err(e);
                }
            }
        }
    }
}
