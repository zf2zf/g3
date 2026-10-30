/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 服务端问候（greeting）处理。
//!
//! 连接建立后源站发出的第一条 untagged 响应（`* OK` / `* PREAUTH` / `* BYE`）。
//! [`Greeting`] 负责：在 greeting_timeout 内读取该行、解析其状态含义、按本机
//! 能力白名单改写行内 `[CAPABILITY ...]` 代码后再转发给客户端，并据此决定
//! 后续进入未认证还是已认证状态。

use std::io;
use std::str::{self, Utf8Error};
use std::time::Duration;

use anyhow::anyhow;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_imap_proto::response::{ByeResponse, Response, ResponseLineError, ServerStatus};
use g3_io_ext::{LimitedWriteExt, LineRecvVec, RecvLineError};

use super::Capability;
use crate::serve::ServerTaskError;

/// 问候阶段的处理结果与状态
#[derive(Default)]
pub(super) struct Greeting {
    /// 源站以 `* BYE` 问候，服务不可用/直接关闭
    close_service: bool,
    /// 源站以 `* PREAUTH` 问候，客户端已预认证（跳过 LOGIN 阶段）
    pre_authenticated: bool,
    /// 已写给客户端的问候字节数；为 0 表示出错时可安全补发 BYE
    total_to_write: usize,
    /// 从问候行 `[CAPABILITY ...]` 代码中解析出的能力集合
    capability: Capability,
}

impl Greeting {
    /// 问候是否表示源站直接关闭服务（此时不应再进入任何中继阶段）
    #[inline]
    pub(super) fn close_service(&self) -> bool {
        self.close_service
    }

    /// 问候是否表示预认证状态（应直接进入已认证中继）
    #[inline]
    pub(super) fn pre_authenticated(&self) -> bool {
        self.pre_authenticated
    }

    /// 交出解析到的能力集合，供上层改写后续 CAPABILITY 响应
    #[inline]
    pub(super) fn into_capability(self) -> Capability {
        self.capability
    }

    /// 读取并转发一条问候响应行。三种 ServerStatus 的语义：
    /// - `* BYE`：置 close_service；
    /// - `* OK`：普通未认证问候；
    /// - `* PREAUTH`：置 pre_authenticated。
    /// 其它响应类型视为协议违例
    pub(super) async fn relay<UR, CW>(
        &mut self,
        ups_r: &mut UR,
        clt_w: &mut CW,
        rsp_recv_buf: &mut LineRecvVec,
        rsp_recv_timeout: Duration,
    ) -> Result<(), GreetingError>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        let line = rsp_recv_buf
            .read_line_with_timeout(ups_r, rsp_recv_timeout)
            .await?;

        let rsp = Response::parse_line(line)?;
        match rsp {
            Response::ServerStatus(ServerStatus::Close) => {
                // `* BYE` 问候：原样转发后结束，不再进入中继阶段
                self.write_greeting_line(clt_w, line).await?;
                rsp_recv_buf.consume_line();
                self.close_service = true;
                Ok(())
            }
            Response::ServerStatus(ServerStatus::Information) => {
                // `* OK`：可能带 [CAPABILITY ...] 代码，改写为白名单后再转发
                match self.rewrite_capability(line)? {
                    Some(new_line) => {
                        self.write_greeting_line(clt_w, &new_line).await?;
                    }
                    None => {
                        self.write_greeting_line(clt_w, line).await?;
                    }
                }
                rsp_recv_buf.consume_line();
                Ok(())
            }
            Response::ServerStatus(ServerStatus::Authenticated) => {
                // `* PREAUTH`：同样改写能力，但源站已认为客户端通过认证
                match self.rewrite_capability(line)? {
                    Some(new_line) => {
                        self.write_greeting_line(clt_w, &new_line).await?;
                    }
                    None => {
                        self.write_greeting_line(clt_w, line).await?;
                    }
                }
                rsp_recv_buf.consume_line();
                self.pre_authenticated = true;
                Ok(())
            }
            _ => {
                // 问候只允许上面三种 ServerStatus，其余均违反 RFC 3501
                rsp_recv_buf.consume_line();
                Err(GreetingError::InvalidResponseType)
            }
        }
    }

    /// 若问候行含 `[CAPABILITY ...]` 代码，把能力列表过滤为本机支持的子集并
    /// 重建该行（同时记录解析结果到 self.capability）。
    /// 返回 `None` 表示该行不含 CAPABILITY 代码、无需改写
    fn rewrite_capability(&mut self, line: &[u8]) -> Result<Option<Vec<u8>>, GreetingError> {
        // 定位响应代码的 '[' 与 ']'，缺失或顺序颠倒则视为无代码、原样转发
        let Some(a) = memchr::memchr(b'[', line) else {
            return Ok(None);
        };
        let Some(b) = memchr::memchr(b']', line) else {
            return Ok(None);
        };

        if a >= b {
            return Ok(None);
        }

        let s = str::from_utf8(&line[a + 1..b])?;
        let mut items = s.trim_end().split_ascii_whitespace();
        let Some(code) = items.next() else {
            return Ok(None);
        };
        if code != "CAPABILITY" {
            // 其它响应代码（如 ALERT）不触碰
            return Ok(None);
        }

        let mut new_line = Vec::with_capacity(line.len());
        new_line.extend_from_slice(&line[..=a]);
        new_line.extend_from_slice(b"CAPABILITY");

        // 逐项过滤：check_supported 同时把本机认识的能力记入 self.capability
        for item in items {
            if let Some(cap) = self.capability.check_supported(item, false) {
                new_line.push(b' ');
                new_line.extend_from_slice(cap.as_bytes());
            }
        }

        new_line.extend_from_slice(&line[b..]);
        Ok(Some(new_line))
    }

    /// 把问候行发给客户端并记录已写字节数（供 reply_no_service 判断是否还能
    /// 补发 BYE：已经写出半个问候后再插 BYE 会破坏协议流）
    async fn write_greeting_line<CW>(
        &mut self,
        clt_w: &mut CW,
        line: &[u8],
    ) -> Result<(), GreetingError>
    where
        CW: AsyncWrite + Unpin,
    {
        self.total_to_write = line.len();
        clt_w
            .write_all_flush(line)
            .await
            .map_err(GreetingError::ClientWriteFailed)?;
        Ok(())
    }

    /// 问候失败后的兜底：仅当一个字节都还没写给客户端时，按错误类别回复一条
    /// `* BYE` 说明原因；写客户端自身失败则无从回复，直接跳过
    pub(super) async fn reply_no_service<CW>(self, e: &GreetingError, clt_w: &mut CW)
    where
        CW: AsyncWrite + Unpin,
    {
        if self.total_to_write > 0 {
            return;
        }
        match e {
            GreetingError::Timeout => {
                let _ = ByeResponse::reply_upstream_timeout(clt_w).await;
            }
            GreetingError::InvalidResponseLine(_)
            | GreetingError::TooLongResponseLine
            | GreetingError::InvalidResponseType
            | GreetingError::InvalidUtf8Line(_) => {
                let _ = ByeResponse::reply_upstream_protocol_error(clt_w).await;
            }
            GreetingError::ClientWriteFailed(_) => {}
            GreetingError::UpstreamReadFailed(_) | GreetingError::UpstreamClosed => {
                let _ = ByeResponse::reply_upstream_io_error(clt_w).await;
            }
        }
    }
}

/// 问候阶段可能出现的错误，映射到任务级错误的规则见下方 From 实现
#[derive(Debug, Error)]
pub(super) enum GreetingError {
    /// 在 greeting_timeout 内未收到源站问候行
    #[error("greeting timeout")]
    Timeout,
    /// 问候行语法不符合 IMAP 响应格式
    #[error("invalid greeting response line: {0}")]
    InvalidResponseLine(#[from] ResponseLineError),
    /// 问候行超过配置的 response_line_max_size
    #[error("response line too long")]
    TooLongResponseLine,
    /// 问候行语法有效但不是合法的问候类型（非 * OK/* PREAUTH/* BYE）
    #[error("invalid greeting response type")]
    InvalidResponseType,
    /// 向客户端写问候/ BYE 失败
    #[error("write to client failed: {0:?}")]
    ClientWriteFailed(io::Error),
    /// 从源站读退出错（连接层错误）
    #[error("read from upstream failed: {0:?}")]
    UpstreamReadFailed(io::Error),
    /// 源站在发出问候前关闭了连接
    #[error("upstream closed connection")]
    UpstreamClosed,
    /// 问候行中的响应代码不是合法 UTF-8
    #[error("invalid utf-8 line: {0}")]
    InvalidUtf8Line(#[from] Utf8Error),
}

// 把 g3_io_ext 的行接收错误翻译为问候阶段错误
impl From<RecvLineError> for GreetingError {
    fn from(value: RecvLineError) -> Self {
        match value {
            RecvLineError::IoError(e) => GreetingError::UpstreamReadFailed(e),
            RecvLineError::IoClosed => GreetingError::UpstreamClosed,
            RecvLineError::Timeout => GreetingError::Timeout,
            RecvLineError::LineTooLong => GreetingError::TooLongResponseLine,
        }
    }
}

// 把问候阶段错误归并为服务器任务的通用错误（源站问题归因于源站）
impl From<GreetingError> for ServerTaskError {
    fn from(value: GreetingError) -> Self {
        match value {
            GreetingError::Timeout => ServerTaskError::UpstreamAppTimeout("imap greeting timeout"),
            GreetingError::InvalidResponseLine(e) => {
                ServerTaskError::UpstreamAppError(anyhow!("invalid greeting response line: {e}"))
            }
            GreetingError::TooLongResponseLine => {
                ServerTaskError::UpstreamAppError(anyhow!("response line too long"))
            }
            GreetingError::InvalidResponseType => {
                ServerTaskError::UpstreamAppError(anyhow!("invalid imap greeting response type"))
            }
            GreetingError::InvalidUtf8Line(e) => {
                ServerTaskError::UpstreamAppError(anyhow!("invalid IMAP utf-8 greeting line: {e}"))
            }
            GreetingError::ClientWriteFailed(e) => ServerTaskError::ClientTcpWriteFailed(e),
            GreetingError::UpstreamReadFailed(e) => ServerTaskError::UpstreamReadFailed(e),
            GreetingError::UpstreamClosed => ServerTaskError::ClosedByUpstream,
        }
    }
}
