/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! 行接收的薄适配层：把 [`LineRecvVec`] 通用的 `RecvLineError` 按方向翻译成
//! 语义准确的 [`ServerTaskError`]（客户端侧超时/断开 vs 源站侧超时/断开），
//! 供 imap 各中继循环统一以 `?` 传播错误。

use tokio::io::AsyncRead;

use g3_io_ext::{LineRecvVec, RecvLineError};

use crate::serve::{ServerTaskError, ServerTaskResult};

/// 从客户端读一行 IMAP 命令，失败时归因为客户端侧错误
pub(super) trait CommandLineReceiveExt {
    /// 读到以 CRLF 结尾的完整命令行并返回其字节切片；行内容保留在内部缓冲，
    /// 供字面量数据复用，需调用方在合适时机 consume_line 释放
    async fn recv_cmd_line<'a, CR>(&'a mut self, clt_r: &mut CR) -> ServerTaskResult<&'a [u8]>
    where
        CR: AsyncRead + Unpin;
}

impl CommandLineReceiveExt for LineRecvVec {
    async fn recv_cmd_line<'a, CR>(&'a mut self, clt_r: &mut CR) -> ServerTaskResult<&'a [u8]>
    where
        CR: AsyncRead + Unpin,
    {
        match self.read_line(clt_r).await {
            Ok(line) => Ok(line),
            Err(RecvLineError::Timeout) => Err(ServerTaskError::ClientAppTimeout(
                "timeout to read IMAP command",
            )),
            Err(RecvLineError::IoError(e)) => Err(ServerTaskError::ClientTcpReadFailed(e)),
            Err(RecvLineError::IoClosed) => Err(ServerTaskError::ClosedByClient),
            Err(RecvLineError::LineTooLong) => Err(ServerTaskError::InvalidClientProtocol(
                "too long IMAP command line",
            )),
        }
    }
}

/// 从源站读一行 IMAP 响应，失败时归因为源站侧错误
pub(super) trait ResponseLineReceiveExt {
    /// 读到以 CRLF 结尾的完整响应行并返回其字节切片；语义同 recv_cmd_line
    async fn recv_rsp_line<'a, UR>(&'a mut self, ups_r: &mut UR) -> ServerTaskResult<&'a [u8]>
    where
        UR: AsyncRead + Unpin;
}

impl ResponseLineReceiveExt for LineRecvVec {
    async fn recv_rsp_line<'a, UR>(&'a mut self, ups_r: &mut UR) -> ServerTaskResult<&'a [u8]>
    where
        UR: AsyncRead + Unpin,
    {
        match self.read_line(ups_r).await {
            Ok(line) => Ok(line),
            Err(RecvLineError::Timeout) => Err(ServerTaskError::UpstreamAppTimeout(
                "timeout to read IMAP response",
            )),
            Err(RecvLineError::IoError(e)) => Err(ServerTaskError::UpstreamReadFailed(e)),
            Err(RecvLineError::IoClosed) => Err(ServerTaskError::ClosedByUpstream),
            Err(RecvLineError::LineTooLong) => Err(ServerTaskError::InvalidUpstreamProtocol(
                "too long IMAP response line",
            )),
        }
    }
}
