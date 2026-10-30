/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 会话结束阶段：QUIT 命令/响应的优雅收尾。
//!
//! 当一侧已确定不再通信（源站回 421、或代理阻断了会话）时，用这两个状态机做礼貌收尾：
//! [`EndQuitServer`] 主动向源站发 QUIT 并等待 221 响应；
//! [`EndWaitClient`] 代替源站继续接收客户端命令，直到收到 QUIT 后回 221 并关闭。
//! 二者都带总超时，防止对端不配合时任务悬挂。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_io_ext::{LimitedWriteExt, LineRecvBuf, RecvLineError};
use g3_smtp_proto::command::Command;
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseParser};

use crate::serve::{ServerTaskError, ServerTaskResult};

/// 向源站发起 QUIT 并等待其 221 响应的结束状态机（无状态，纯工具方法）。
pub(super) struct EndQuitServer {}

impl EndQuitServer {
    /// 主动对源站执行优雅关闭：发送 QUIT，并在 `timeout` 内等待完整的 221 响应。
    /// 超时或对端响应非法均返回错误；调用方通常已不再使用这条连接。
    pub(super) async fn run_to_end<R, W>(
        ups_r: R,
        mut ups_w: W,
        timeout: Duration,
    ) -> ServerTaskResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        ups_w
            .write_all_flush(b"QUIT\r\n")
            .await
            .map_err(ServerTaskError::UpstreamWriteFailed)?;

        tokio::time::timeout(timeout, EndQuitServer::wait_quit_reply(ups_r))
            .await
            .map_err(|_| {
                ServerTaskError::UpstreamAppTimeout("timeout to wait SMTP QUIT response")
            })?
    }

    /// 循环读取源站对 QUIT 的响应行，校验响应码必须为 221（SERVICE_CLOSING），
    /// 多行响应全部读完后正常退出。
    async fn wait_quit_reply<R>(mut ups_r: R) -> ServerTaskResult<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut recv_buf = LineRecvBuf::<{ ResponseParser::MAX_LINE_SIZE }>::default();

        let mut rsp = ResponseParser::default();
        loop {
            let line = recv_buf.read_line(&mut ups_r).await.map_err(|e| match e {
                RecvLineError::IoError(e) => ServerTaskError::UpstreamReadFailed(e),
                RecvLineError::IoClosed => ServerTaskError::ClosedByUpstream,
                RecvLineError::Timeout => {
                    ServerTaskError::UpstreamAppTimeout("timeout to get upstream response")
                }
                RecvLineError::LineTooLong => {
                    ServerTaskError::UpstreamAppError(anyhow!("SMTP response line too long"))
                }
            })?;

            rsp.feed_line(line).map_err(|e| {
                ServerTaskError::UpstreamAppError(anyhow!("invalid SMTP QUIT response line: {e}"))
            })?;
            // QUIT 只接受 221；其它响应码说明源站状态机与代理预期不一致
            if rsp.code() != ReplyCode::SERVICE_CLOSING {
                return Err(ServerTaskError::UpstreamAppError(anyhow!(
                    "invalid SMTP QUIT response code: {}",
                    rsp.code()
                )));
            }
            if rsp.finished() {
                break;
            }

            recv_buf.consume_line();
        }

        Ok(())
    }
}

/// 代替已断开的源站接收客户端命令、直到其发出 QUIT 的结束状态机。
/// 用于阻断/源站 421 等场景：客户端仍以为会话有效，需要陪它走完 QUIT 流程。
pub(super) struct EndWaitClient {
    local_ip: IpAddr, // 生成 221 关闭响应时使用的地址前缀
}

impl EndWaitClient {
    pub(super) fn new(local_ip: IpAddr) -> Self {
        EndWaitClient { local_ip }
    }

    /// 在 `timeout` 总时限内等待客户端发出 QUIT；超时则按客户端协议错误终止。
    pub(super) async fn run_to_end<R, W>(
        self,
        clt_r: R,
        clt_w: W,
        timeout: Duration,
    ) -> ServerTaskResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        tokio::time::timeout(timeout, self.wait_quit_command(clt_r, clt_w))
            .await
            .map_err(|_| {
                ServerTaskError::ClientAppError(anyhow!("timeout to wait SMTP QUIT command"))
            })?
    }

    /// 命令接收循环：QUIT 以外的命令一律回 503（会话已在收尾，不再受理业务命令），
    /// 收到 QUIT 后回 221 并关闭客户端写端。
    async fn wait_quit_command<R, W>(self, mut clt_r: R, mut clt_w: W) -> ServerTaskResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut recv_buf = LineRecvBuf::<{ Command::MAX_LINE_SIZE }>::default();
        loop {
            let line = match recv_buf.read_line(&mut clt_r).await {
                Ok(line) => line,
                Err(e) => {
                    // 行过长时先回 500 告知客户端，再终止等待
                    let e = match e {
                        RecvLineError::IoError(e) => ServerTaskError::ClientTcpReadFailed(e),
                        RecvLineError::IoClosed => ServerTaskError::ClosedByClient,
                        RecvLineError::Timeout => {
                            ServerTaskError::ClientAppTimeout("timeout to wait client command")
                        }
                        RecvLineError::LineTooLong => {
                            let _ = ResponseEncoder::COMMAND_LINE_TOO_LONG
                                .write(&mut clt_w)
                                .await;
                            ServerTaskError::ClientAppError(anyhow!("SMTP command line too long"))
                        }
                    };
                    return Err(e);
                }
            };

            // 解析失败时把协议错误映射为响应回给客户端后终止
            let cmd = match Command::parse_line(line) {
                Ok(cmd) => {
                    recv_buf.consume_line();
                    cmd
                }
                Err(e) => {
                    let _ = ResponseEncoder::from(&e).write(&mut clt_w).await;
                    return Err(ServerTaskError::ClientAppError(anyhow!(
                        "invalid SMTP command line: {e}"
                    )));
                }
            };
            if cmd == Command::Quit {
                // 代理本地扮演源站完成收尾：回 221 后关闭
                ResponseEncoder::local_service_closing(self.local_ip)
                    .write(&mut clt_w)
                    .await
                    .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                break;
            } else {
                ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS
                    .write(&mut clt_w)
                    .await
                    .map_err(ServerTaskError::ClientTcpWriteFailed)?;
            }
        }

        let _ = clt_w.shutdown().await;
        Ok(())
    }
}
