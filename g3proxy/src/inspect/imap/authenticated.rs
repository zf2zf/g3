/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 已认证（authenticated）状态的命令/响应中继。
//!
//! 认证通过后客户端可执行邮箱类命令（SELECT/FETCH/SEARCH/APPEND/IDLE 等）。
//! 本文件在 [`ImapInterceptObject`] 上实现：主循环 [`relay_authenticated`]
//! 风格的双向 select、空闲计数与封禁/强制退出检查、IDLE 挂起子循环
//! （[`Self::relay_until_idle_done`]）、ENABLE 命令的能力过滤改写，
//! 以及 LOGIN/STARTTLS 等已认证状态下非法命令的就地 BAD 拒绝。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_imap_proto::command::{Command, ParsedCommand};
use g3_imap_proto::response::{BadResponse, ByeResponse};
use g3_io_ext::{IdleInterval, LimitedWriteExt};

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
    /// IDLE：进入空闲挂起子循环
    Idle,
    /// 命令带非同步字面量，先把 size 字节的字面量数据中继给源站
    SendLiteral(u64),
}

/// 已认证状态中继的结束原因，决定上层（mod.rs）的收尾方式
pub(super) enum CloseReason {
    /// 源站关闭连接（* BYE 或 EOF）
    Server,
    /// 客户端发出 LOGOUT 正常登出
    Client,
    /// 本机主动断开（空闲超时/用户被封禁/服务退出/出错），携带待上报的错误
    Local(ServerTaskError),
}

impl<SC> ImapInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 已认证状态主循环：双向 select 中继命令与响应，并周期检查空闲、封禁、退出。
    /// 空闲计数达到 forward_max_idle_count 时回 BYE 并以 CloseReason::Local 结束；
    /// IDLE 期间同样受该空闲限制
    pub(super) async fn relay_authenticated<CR, CW, UR, UW>(
        &mut self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
    ) -> ServerTaskResult<CloseReason>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;
        let max_idle_count = self.ctx.imap_interception().forward_max_idle_count;

        // 本空闲周期内是否有任一方向的流量；无流量才累加空闲计数
        let mut active = false;

        loop {
            relay_buf.cmd_recv_buf.consume_line();
            relay_buf.rsp_recv_buf.consume_line();

            tokio::select! {
                r = relay_buf.cmd_recv_buf.recv_cmd_line(clt_r) => {
                    let line = r?;
                    active = true;
                    if let Some(mut cmd) = self.cmd_pipeline.take_ongoing_command() {
                        self.handle_cmd_continue_line(line, &mut cmd, clt_w, ups_w).await?;
                        if let Some(literal) = cmd.literal_arg {
                            self.cmd_pipeline.set_ongoing_command(cmd);
                            if !literal.wait_continuation {
                                self.relay_client_literal(literal.size, clt_r, clt_w, ups_w, relay_buf).await?;
                            }
                        } else {
                            self.cmd_pipeline.insert_completed(cmd);
                        }
                    } else {
                        match self.handle_authenticated_cmd_line(line, clt_w, ups_w).await? {
                            ClientAction::Logout => {
                                return Ok(CloseReason::Client);
                            }
                            ClientAction::Idle => {
                                if let Some(status) = self.relay_until_idle_done(
                                    clt_r,
                                    clt_w,
                                    ups_r,
                                    ups_w,
                                    relay_buf,
                                    &mut idle_interval,
                                ).await? {
                                    return Ok(status);
                                }
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
                    active = true;
                    if let Some(mut rsp) = self.cmd_pipeline.take_ongoing_response() {
                        // 源站响应含未传完的 literal 数据，本行属于该响应的续行
                        self.handle_rsp_continue_line(line, &mut rsp, clt_w).await?;
                        if let Some(size) = rsp.literal_data {
                            self.cmd_pipeline.set_ongoing_response(rsp);
                            self.relay_server_literal(size, clt_w, ups_r, relay_buf).await?;
                        }
                    } else {
                        match self.handle_rsp_line(line, clt_w).await? {
                            ResponseAction::Loop => {}
                            ResponseAction::Close => return Ok(CloseReason::Server),
                            ResponseAction::SendLiteral(size) => {
                                self.relay_server_literal(size, clt_w, ups_r,  relay_buf).await?;
                            }
                            ResponseAction::RecvClientLiteral(size) => {
                                 self.relay_client_literal(size, clt_r, clt_w, ups_w, relay_buf).await?;
                            }
                        }
                    }
                }
                 n = idle_interval.tick() => {
                    if !active {
                        // n 为本次 tick 跨过的空闲周期数；连续空闲超限则主动踢掉连接
                        idle_count += n;
                        if idle_count >= max_idle_count {
                            let _ = ByeResponse::reply_idle_logout(clt_w).await;
                            return Ok(CloseReason::Local(ServerTaskError::Idle(idle_interval.period(), idle_count)));
                        }
                    } else {
                        idle_count = 0;
                    }

                    // 空闲检查点同时也是策略检查点：用户被封禁/服务强制退出时终止会话
                    if self.ctx.belongs_to_blocked_user() {
                        let _ = ByeResponse::reply_blocked(clt_w).await;
                        return Ok(CloseReason::Local(ServerTaskError::CanceledAsUserBlocked));
                    }

                    if self.ctx.server_force_quit() {
                        let _ = ByeResponse::reply_server_quit(clt_w).await;
                        return Ok(CloseReason::Local(ServerTaskError::CanceledAsServerQuit));
                    }
                }
            }
        }
    }

    /// 解析并分类一条已认证状态的新命令。未选邮箱时拒绝依赖邮箱状态的命令
    /// （FETCH/SEARCH 等）；LOGIN/AUTHENTICATE/STARTTLS 在此状态一律 BAD；
    /// 其余合法命令记入管线并转发源站
    async fn handle_authenticated_cmd_line<CW, UW>(
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
                        self.cmd_pipeline.insert_completed(cmd);
                    }
                    ParsedCommand::Logout => {
                        self.cmd_pipeline.insert_completed(cmd);
                        action = ClientAction::Logout;
                    }
                    ParsedCommand::StartTls | ParsedCommand::Auth | ParsedCommand::Login => {
                        // 认证/加密协商类命令只属于未认证状态，就地 BAD
                        BadResponse::reply_invalid_command(clt_w, cmd.tag.as_str())
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        return Ok(action);
                    }
                    ParsedCommand::Enable => {
                        // ENABLE 的能力列表需按白名单过滤改写，在子过程内完成转发
                        self.handle_enable_command(line, cmd, clt_w, ups_w).await?;
                        return Ok(action);
                    }
                    ParsedCommand::Select
                    | ParsedCommand::Examine
                    | ParsedCommand::Namespace
                    | ParsedCommand::Create
                    | ParsedCommand::Delete
                    | ParsedCommand::Rename
                    | ParsedCommand::Subscribe
                    | ParsedCommand::Unsubscribe
                    | ParsedCommand::List
                    | ParsedCommand::Lsub
                    | ParsedCommand::Status
                    | ParsedCommand::Append
                    | ParsedCommand::Language
                    | ParsedCommand::Comparator
                    | ParsedCommand::GetQuota
                    | ParsedCommand::GetQuotaRoot
                    | ParsedCommand::SetQuota
                    | ParsedCommand::SetAcl
                    | ParsedCommand::GetAcl
                    | ParsedCommand::DeleteAcl
                    | ParsedCommand::ListRights
                    | ParsedCommand::MyRights
                    | ParsedCommand::Conversions
                    | ParsedCommand::Convert
                    | ParsedCommand::GetMetadata
                    | ParsedCommand::SetMetadata
                    | ParsedCommand::Notify
                    | ParsedCommand::ResetKey
                    | ParsedCommand::UrlFetch
                    | ParsedCommand::GenUrlAuth => {
                        // 不依赖已选邮箱的命令；参数若含非同步字面量需先中继数据
                        if let Some(literal) = cmd.literal_arg {
                            if !literal.wait_continuation {
                                action = ClientAction::SendLiteral(literal.size);
                            }
                            self.cmd_pipeline.set_ongoing_command(cmd);
                        } else {
                            self.cmd_pipeline.insert_completed(cmd);
                        }
                    }
                    ParsedCommand::Idle => {
                        // IDLE 以 DONE 结束而非普通命令行，挂起命令并进入空闲子循环
                        self.cmd_pipeline.set_ongoing_command(cmd);
                        action = ClientAction::Idle;
                    }
                    ParsedCommand::Close
                    | ParsedCommand::Unselect
                    | ParsedCommand::Expunge
                    | ParsedCommand::Search
                    | ParsedCommand::Fetch
                    | ParsedCommand::Store
                    | ParsedCommand::Copy
                    | ParsedCommand::Move
                    | ParsedCommand::Uid
                    | ParsedCommand::CancelUpdate
                    | ParsedCommand::Sort
                    | ParsedCommand::Thread
                    | ParsedCommand::Esearch => {
                        // 依赖已选邮箱的命令：未 SELECT 时拒绝（mailbox_selected
                        // 由 forward.rs 在 SELECT/CLOSE 成功时维护）
                        if !self.mailbox_selected {
                            BadResponse::reply_invalid_command(clt_w, cmd.tag.as_str())
                                .await
                                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                            return Ok(action);
                        }
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
                        // 未知或本代理不放行的命令：就地 BAD，不暴露给源站
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

    /// 改写并重发 ENABLE 命令：仅保留本机支持的能力项。过滤后仍有能力项才转发
    /// 源站并记入管线；全部被过滤掉时直接回客户端 `<tag> OK no enabled`，
    /// 不打扰源站
    async fn handle_enable_command<CW, UW>(
        &mut self,
        line: &[u8],
        cmd: Command,
        clt_w: &mut CW,
        ups_w: &mut UW,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let orig = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end(),
            Err(e) => {
                let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
                return Err(ServerTaskError::ClientAppError(anyhow!(
                    "invalid IMAP command line: {e}"
                )));
            }
        };

        let mut items = orig.split_ascii_whitespace();
        // 解析已成功，首两词必为 tag 与命令名
        let tag = items.next().unwrap();
        let name = items.next().unwrap();

        let mut new_line = Vec::with_capacity(line.len());
        new_line.extend_from_slice(tag.as_bytes());
        new_line.push(b' ');
        new_line.extend_from_slice(name.as_bytes());

        // 用临时 Capability 过滤 ENABLE 请求里的能力名，不认识的整体丢弃
        let mut all_cap = Capability::default();
        let mut enable_cap_count = 0;
        for item in items {
            if let Some(cap) = all_cap.check_supported(item, false) {
                new_line.push(b' ');
                new_line.extend_from_slice(cap.as_bytes());
                enable_cap_count += 1;
            }
        }

        if enable_cap_count > 0 {
            new_line.extend_from_slice(b"\r\n");

            ups_w
                .write_all_flush(&new_line)
                .await
                .map_err(ServerTaskError::UpstreamWriteFailed)?;
            self.cmd_pipeline.insert_completed(cmd);
        } else {
            // 没有任何被支持的能力：本地伪造成功响应，客户端不会察觉差异
            let rsp = format!("{tag} OK no enabled\r\n");
            clt_w
                .write_all_flush(rsp.as_bytes())
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        }

        Ok(())
    }

    /// 改写源站的 untagged `* ENABLED ...` 响应：只转发本机支持的能力项；
    /// 全部被过滤掉时整行丢弃不发（与 ENABLE 请求侧的过滤保持一致，
    /// 避免客户端误以为启用了代理不支持的扩展）。from_enable=true 使
    /// IMAP4rev2 等仅在 ENABLED 中确认的能力也能通过过滤
    pub(super) async fn write_enabled_response<CW>(
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

        let mut items = orig.split_ascii_whitespace();
        let tag = items.next().unwrap();
        let name = items.next().unwrap();

        let mut new_line = Vec::with_capacity(line.len());
        new_line.extend_from_slice(tag.as_bytes());
        new_line.push(b' ');
        new_line.extend_from_slice(name.as_bytes());

        let mut all_cap = Capability::default();
        let mut enable_cap_count = 0;
        for item in items {
            if let Some(cap) = all_cap.check_supported(item, true) {
                new_line.push(b' ');
                new_line.extend_from_slice(cap.as_bytes());
                enable_cap_count += 1;
            }
        }

        if enable_cap_count > 0 {
            new_line.extend_from_slice(b"\r\n");

            clt_w
                .write_all_flush(&new_line)
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        }

        Ok(())
    }

    /// IDLE 挂起子循环：等待客户端发 DONE 结束空闲。期间源站推送的 untagged
    /// 通知照常中继。返回 `None` 表示 DONE 已转发、可回到主循环；返回
    /// `Some(CloseReason)` 表示连接就此终止（空闲超限/封禁/退出/源站关闭），
    /// 终止时先替客户端补发 DONE，尽量让源站正常收尾
    async fn relay_until_idle_done<CR, CW, UR, UW>(
        &mut self,
        clt_r: &mut CR,
        clt_w: &mut CW,
        ups_r: &mut UR,
        ups_w: &mut UW,
        relay_buf: &mut ImapRelayBuf,
        idle_interval: &mut IdleInterval,
    ) -> ServerTaskResult<Option<CloseReason>>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        const DONE_MSG: &[u8] = b"DONE\r\n";

        let mut idle_count = 0;
        let max_idle_count = self.ctx.imap_interception().forward_max_idle_count;

        // 进入 IDLE 时视为刚有活动，避免立刻计入空闲
        let mut active = true;

        loop {
            relay_buf.cmd_recv_buf.consume_line();
            relay_buf.rsp_recv_buf.consume_line();

            tokio::select! {
                r = relay_buf.cmd_recv_buf.recv_cmd_line(clt_r) => {
                    let line = r?;
                    return if line == DONE_MSG {
                        // DONE 转发给源站后 IDLE 正常结束
                        ups_w.write_all_flush(line)
                            .await
                            .map_err(ServerTaskError::UpstreamWriteFailed)?;
                        Ok(None)
                    } else {
                        // IDLE 期间除 DONE 外不得发送任何内容
                        let _ = ByeResponse::reply_client_protocol_error(clt_w).await;
                        Err(ServerTaskError::ClientAppError(anyhow!(
                            "invalid IMAP IDLE ending line"
                        )))
                    };
                }
                r = relay_buf.rsp_recv_buf.recv_rsp_line(ups_r) => {
                    let line = r?;
                    active = true;
                    if let Some(mut rsp) = self.cmd_pipeline.take_ongoing_response() {
                        // 源站响应含未传完的 literal 数据，本行属于该响应的续行
                        self.handle_rsp_continue_line(line, &mut rsp, clt_w).await?;
                        if let Some(size) = rsp.literal_data {
                            self.relay_server_literal(size, clt_w, ups_r, relay_buf).await?;
                        }
                    } else {
                        match self.handle_rsp_line(line, clt_w).await? {
                            ResponseAction::Loop => {}
                            ResponseAction::Close => return Ok(Some(CloseReason::Server)),
                            ResponseAction::SendLiteral(size) => {
                                self.relay_server_literal(size, clt_w, ups_r,  relay_buf).await?;
                            }
                            ResponseAction::RecvClientLiteral(size) => {
                                 self.relay_client_literal(size, clt_r, clt_w, ups_w, relay_buf).await?;
                            }
                        }
                    }
                }
                n = idle_interval.tick() => {
                    if !active {
                        // 空闲超限：客户端不再活动，本地结束会话
                        idle_count += n;
                        if idle_count >= max_idle_count {
                            // 补发 DONE 替客户端结束 IDLE，尽量让源站正常收尾
                            let _ = ByeResponse::reply_idle_logout(clt_w).await;
                            let _ = ups_w.write_all_flush(DONE_MSG).await;
                            return Ok(Some(CloseReason::Local(ServerTaskError::Idle(idle_interval.period(), idle_count))));
                        }
                    } else {
                        idle_count = 0;
                    }

                    // 同主循环：空闲检查点兼做封禁/强制退出策略检查点
                    if self.ctx.belongs_to_blocked_user() {
                        let _ = ByeResponse::reply_blocked(clt_w).await;
                        let _ = ups_w.write_all_flush(DONE_MSG).await;
                        return Ok(Some(CloseReason::Local(ServerTaskError::CanceledAsUserBlocked)));
                    }

                    if self.ctx.server_force_quit() {
                        let _ = ByeResponse::reply_server_quit(clt_w).await;
                        let _ = ups_w.write_all_flush(DONE_MSG).await;
                        return Ok(Some(CloseReason::Local(ServerTaskError::CanceledAsServerQuit)));
                    }
                }
            }
        }
    }
}
