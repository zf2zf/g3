/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 拦截各阶段共用的行读写扩展 trait。
//!
//! 把"读取一行 + 失败时先向对端回一条本地生成的错误响应"这一模式抽象为三个扩展：
//! [`ResponseLineRecvExt`]（读源站响应行）、[`ResponseParseExt`]（喂入并解析响应行）、
//! [`CommandLineRecvExt`]（读并解析客户端命令行）。
//! 保证协议出错时客户端能收到符合 SMTP 语义的 4xx/5xx 响应而非被静默断开。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_io_ext::{LineRecvBuf, RecvLineError};
use g3_smtp_proto::command::Command;
use g3_smtp_proto::response::{ResponseEncoder, ResponseParser};

use crate::serve::{ServerTaskError, ServerTaskResult};

/// 带"反馈"的响应行读取：从源站读一行响应，任何失败都先映射成一条本地 4xx/5xx 响应写给客户端。
pub(super) trait ResponseLineRecvExt {
    async fn read_rsp_line_with_feedback<'a, R, W>(
        &'a mut self,
        recv_timeout: Duration,
        ups_r: &mut R,
        clt_w: &mut W,
        local_ip: IpAddr,
    ) -> ServerTaskResult<&'a [u8]>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin;
}

impl<const MAX_LINE_SIZE: usize> ResponseLineRecvExt for LineRecvBuf<MAX_LINE_SIZE> {
    /// 四种失败各对应一条语义不同的响应：IO 错误(451)、对端关闭(451)、超时(421)、行过长(551)。
    /// 写响应本身失败会被忽略（连接大概率已断），错误仍原样向上返回。
    async fn read_rsp_line_with_feedback<'a, R, W>(
        &'a mut self,
        recv_timeout: Duration,
        ups_r: &mut R,
        clt_w: &mut W,
        local_ip: IpAddr,
    ) -> ServerTaskResult<&'a [u8]>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match self.read_line_with_timeout(ups_r, recv_timeout).await {
            Ok(line) => Ok(line),
            Err(e) => match e {
                RecvLineError::IoError(e) => {
                    let _ = ResponseEncoder::upstream_io_error(local_ip, &e)
                        .write(clt_w)
                        .await;
                    Err(ServerTaskError::UpstreamReadFailed(e))
                }
                RecvLineError::IoClosed => {
                    let _ = ResponseEncoder::upstream_io_closed(local_ip)
                        .write(clt_w)
                        .await;
                    Err(ServerTaskError::ClosedByUpstream)
                }
                RecvLineError::Timeout => {
                    let _ = ResponseEncoder::local_service_not_available(local_ip)
                        .write(clt_w)
                        .await;
                    Err(ServerTaskError::UpstreamAppTimeout(
                        "timeout to get upstream response",
                    ))
                }
                RecvLineError::LineTooLong => {
                    let _ = ResponseEncoder::upstream_line_too_long(local_ip)
                        .write(clt_w)
                        .await;
                    Err(ServerTaskError::UpstreamAppError(anyhow!(
                        "SMTP response line too long"
                    )))
                }
            },
        }
    }
}

/// 带"反馈"的响应行解析：把已转发的响应行喂给 [`ResponseParser`]，解析失败时先向客户端回 501。
/// 注意行本身已转发给客户端，这里只负责语义校验与错误反馈。
pub(super) trait ResponseParseExt {
    async fn feed_line_with_feedback<'a, W>(
        &mut self,
        line: &'a [u8],
        clt_w: &mut W,
        local_ip: IpAddr,
    ) -> ServerTaskResult<&'a [u8]>
    where
        W: AsyncWrite + Unpin;
}

impl ResponseParseExt for ResponseParser {
    /// 返回该行的消息文本部分（去掉响应码前缀），供上层继续解析扩展关键字等。
    async fn feed_line_with_feedback<'a, W>(
        &mut self,
        line: &'a [u8],
        clt_w: &mut W,
        local_ip: IpAddr,
    ) -> ServerTaskResult<&'a [u8]>
    where
        W: AsyncWrite + Unpin,
    {
        match self.feed_line(line) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                let _ = ResponseEncoder::upstream_response_error(local_ip, &e)
                    .write(clt_w)
                    .await;
                Err(ServerTaskError::UpstreamAppError(anyhow!(
                    "invalid SMTP QUIT response line: {e}"
                )))
            }
        }
    }
}

/// 客户端命令行的接收与解析扩展：读一行并解析为 [`Command`]，出错时向客户端回相应错误响应。
pub(super) trait CommandLineRecvExt {
    /// 返回 (解析出的命令, 原始行字节)。原始行用于把命令原样转发到源站，
    /// 避免重新序列化导致与客户端发送内容不一致（如大小写、参数空格）。
    async fn recv_cmd<CR, CW>(
        &mut self,
        recv_timeout: Duration,
        clt_r: &mut CR,
        clt_w: &mut CW,
    ) -> ServerTaskResult<(Command, &[u8])>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin;

    /// 把行读取错误转换为任务错误；行过长时先向客户端回 500 命令过长。
    async fn handle_line_error<CW>(e: RecvLineError, clt_w: &mut CW) -> ServerTaskError
    where
        CW: AsyncWrite + Unpin,
    {
        match e {
            RecvLineError::IoError(e) => ServerTaskError::ClientTcpReadFailed(e),
            RecvLineError::IoClosed => ServerTaskError::ClosedByClient,
            RecvLineError::Timeout => {
                ServerTaskError::ClientAppTimeout("timeout to wait client command")
            }
            RecvLineError::LineTooLong => {
                let _ = ResponseEncoder::COMMAND_LINE_TOO_LONG.write(clt_w).await;
                ServerTaskError::ClientAppError(anyhow!("SMTP command line too long"))
            }
        }
    }
}

impl<const MAX_LINE_SIZE: usize> CommandLineRecvExt for LineRecvBuf<MAX_LINE_SIZE> {
    /// 解析失败时按 [`g3_smtp_proto`] 的错误类型生成对应 5xx 响应回给客户端后终止会话。
    async fn recv_cmd<CR, CW>(
        &mut self,
        recv_timeout: Duration,
        clt_r: &mut CR,
        clt_w: &mut CW,
    ) -> ServerTaskResult<(Command, &[u8])>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        match self.read_line_with_timeout(clt_r, recv_timeout).await {
            Ok(line) => match Command::parse_line(line) {
                Ok(cmd) => Ok((cmd, line)),
                Err(e) => {
                    let _ = ResponseEncoder::from(&e).write(clt_w).await;
                    Err(ServerTaskError::ClientAppError(anyhow!(
                        "invalid SMTP command line: {e}"
                    )))
                }
            },
            Err(e) => {
                let e = Self::handle_line_error(e, clt_w).await;
                Err(e)
            }
        }
    }
}
