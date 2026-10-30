/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 登出（LOGOUT）收尾流程。
//!
//! 两个方向各一套：客户端发了 LOGOUT 时，本机继续把源站的 tagged 结果与
//! `* BYE` 转发完再结束（[`ImapInterceptObject::handle_client_logout`]，带
//! logout_wait_timeout 超时）；本机要主动断开时，替客户端向源站补发一条
//! 伪造标签 `XXXX LOGOUT` 并等源站回完，礼貌释放上游连接
//! （[`ImapInterceptObject::start_server_logout`]）。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_imap_proto::command::ParsedCommand;
use g3_imap_proto::response::{Response, ServerStatus};
use g3_io_ext::{LimitedWriteExt, LineRecvVec};

use super::{ImapInterceptObject, ResponseLineReceiveExt};
use crate::config::server::ServerConfig;
use crate::serve::{ServerTaskError, ServerTaskResult};

impl<SC> ImapInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 等待客户端的 LOGOUT 在源站侧完成配对：转发响应直到收到 LOGOUT 命令的
    /// tagged 结果。整体受 logout_wait_timeout 约束，超时按源站应用超时上报
    pub(super) async fn handle_client_logout<CW, UR>(
        &mut self,
        clt_w: &mut CW,
        ups_r: &mut UR,
        rsp_recv_buf: &mut LineRecvVec,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        self.client_logout = true;

        tokio::time::timeout(
            self.ctx.imap_interception().logout_wait_timeout,
            self.wait_client_logout(clt_w, ups_r, rsp_recv_buf),
        )
        .await
        .map_err(|_| ServerTaskError::UpstreamAppTimeout("timeout to wait IMAP LOGOUT response"))?
    }

    /// 逐行转发源站响应，直到出现 LOGOUT 命令对应的 tagged 结果为止；
    /// 期间收到 `* BYE` 只置位 server_bye 标记，仍要等到 tagged 结果才算收完
    async fn wait_client_logout<CW, UR>(
        &mut self,
        clt_w: &mut CW,
        ups_r: &mut UR,
        rsp_recv_buf: &mut LineRecvVec,
    ) -> ServerTaskResult<()>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        loop {
            rsp_recv_buf.consume_line();
            let line = rsp_recv_buf.recv_rsp_line(ups_r).await?;
            clt_w
                .write_all_flush(line)
                .await
                .map_err(ServerTaskError::ClientTcpWriteFailed)?;
            match Response::parse_line(line) {
                Ok(Response::CommandResult(r)) => {
                    // 结果可能属于 LOGOUT 之前尚未回完的其它命令，配对不到就继续
                    let Some(cmd) = self.cmd_pipeline.remove(&r.tag) else {
                        continue;
                    };
                    if cmd.parsed == ParsedCommand::Logout {
                        return Ok(());
                    }
                }
                Ok(Response::ServerStatus(ServerStatus::Close)) => {
                    self.server_bye = true;
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "invalid IMAP response line: {e}"
                    )));
                }
            }
        }
    }

    /// 本机主动断开时向源站补发 LOGOUT：用不与真实客户端标签冲突的伪造
    /// 标签 `XXXX`，尽力等待源站回完（超时/失败均忽略，纯 best-effort）
    pub(super) async fn start_server_logout<UR, UW>(
        &mut self,
        ups_r: &mut UR,
        ups_w: &mut UW,
        rsp_recv_buf: &mut LineRecvVec,
    ) where
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let _ = ups_w.write_all_flush(b"XXXX LOGOUT\r\n").await;
        let _ = tokio::time::timeout(
            self.ctx.imap_interception().logout_wait_timeout,
            self.wait_server_logout(ups_r, rsp_recv_buf),
        )
        .await;
    }

    /// 等待伪造标签 `XXXX` 的 LOGOUT 结果；期间顺带清理其它命令的残留配对，
    /// 任何读取/解析异常都直接放弃（调用方不关心收尾细节）
    async fn wait_server_logout<UR>(&mut self, ups_r: &mut UR, rsp_recv_buf: &mut LineRecvVec)
    where
        UR: AsyncRead + Unpin,
    {
        loop {
            rsp_recv_buf.consume_line();
            let Ok(line) = rsp_recv_buf.recv_rsp_line(ups_r).await else {
                return;
            };
            match Response::parse_line(line) {
                Ok(Response::CommandResult(r)) => {
                    if r.tag.as_bytes() == b"XXXX" {
                        return;
                    }
                    // 非本标签的结果：属于之前未完成命令，出队避免管线堆积
                    self.cmd_pipeline.remove(&r.tag);
                }
                Ok(Response::ServerStatus(ServerStatus::Close)) => {}
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }
}
