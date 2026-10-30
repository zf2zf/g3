/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 问候（greeting）阶段：会话建立时源站主动向客户端发送的第一条响应。
//!
//! [`Greeting`] 逐行读取并中继源站的 220（SERVICE_READY）或 421（NO_SERVICE）响应，
//! 同时从 220 响应文本中解析出源站主机名，供上层记录审计日志。
//! 本阶段在整条检测流水线中位于最前，其后衔接 [`super::initiation`] 发起阶段。

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::anyhow;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};

use g3_io_ext::{LimitedWriteExt, LineRecvBuf, OnceBufReader, RecvLineError};
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseLineError, ResponseParser};
use g3_types::net::Host;

use crate::serve::ServerTaskError;

/// 问候阶段处理器：解析源站 greeting 响应并原样转发给客户端。
pub(super) struct Greeting {
    /// 代理本地 IP，用于生成 4xx/5xx 响应时的地址前缀。
    local_ip: IpAddr,
    /// 从 220 响应中解析出的源站主机名。
    upstream_host: Host,
    /// 多行响应解析器，跟踪响应码与结束标志。
    rsp: ResponseParser,
    /// 已转发给客户端的字节数；非零时不再补发错误响应。
    total_to_write: usize,
}

impl Greeting {
    pub(super) fn new(local_ip: IpAddr) -> Self {
        Greeting {
            local_ip,
            upstream_host: Host::empty(),
            rsp: ResponseParser::default(),
            total_to_write: 0,
        }
    }

    /// 拆出问候结果：响应码（220 或 421）与解析到的源站主机名。
    pub(super) fn into_parts(self) -> (ReplyCode, Host) {
        (self.rsp.code(), self.upstream_host)
    }

    /// 核心读取循环：逐行读源站响应、转发到客户端，直到响应结束。
    /// 成功时返回还原后的源站读端（ [`OnceBufReader`] 剥掉预读缓冲）。
    async fn do_relay<UR, CW>(
        &mut self,
        mut ups_r: OnceBufReader<UR>,
        clt_w: &mut CW,
    ) -> Result<UR, GreetingError>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        let mut recv_buf = LineRecvBuf::<{ ResponseParser::MAX_LINE_SIZE }>::default();

        loop {
            recv_buf.consume_line();
            let line = recv_buf.read_line(&mut ups_r).await?;

            // feed_line 边喂入边判定响应是否完整（多行响应的最后一行）
            let msg = self.rsp.feed_line(line)?;
            self.total_to_write += line.len();
            clt_w
                .write_all_flush(line)
                .await
                .map_err(GreetingError::ClientWriteFailed)?;

            match self.rsp.code() {
                ReplyCode::SERVICE_READY => {
                    // 220 响应：首次出现时从消息文本提取空格前的主机名字段
                    if self.upstream_host.is_empty() {
                        let host_d = match memchr::memchr(b' ', msg) {
                            Some(d) => &msg[..d],
                            None => msg,
                        };
                        if host_d.is_empty() {
                            return Err(GreetingError::NoHostField);
                        }
                        self.upstream_host = Host::parse_smtp_host_address(host_d)
                            .ok_or(GreetingError::UnsupportedHostFormat)?;
                    }
                    if self.rsp.finished() {
                        return Ok(ups_r.into_inner());
                    }
                }
                ReplyCode::NO_SERVICE => {
                    // 421：源站拒绝服务，无主机名可解析，响应读完即返回
                    if self.rsp.finished() {
                        return Ok(ups_r.into_inner());
                    }
                }
                // 其它响应码在问候阶段均为协议违规
                c => return Err(GreetingError::UnexpectedReplyCode(c)),
            }
        }
    }

    /// 带总超时 [`timeout`] 的对外入口：超时则先 flush 已缓冲内容再报 [`GreetingError::Timeout`]。
    pub(super) async fn relay<UR, CW>(
        &mut self,
        ups_r: OnceBufReader<UR>,
        clt_w: &mut CW,
        timeout: Duration,
    ) -> Result<UR, GreetingError>
    where
        UR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
    {
        // 用 BufWriter 聚合响应行减少小包写；客户端写失败时不 flush（避免半条脏数据）
        let mut buf_writer = BufWriter::with_capacity(1024, clt_w);
        match tokio::time::timeout(timeout, self.do_relay(ups_r, &mut buf_writer)).await {
            Ok(Ok(ups_r)) => {
                let _ = buf_writer.flush().await;
                Ok(ups_r)
            }
            Ok(Err(e)) => {
                if let GreetingError::ClientWriteFailed(e) = e {
                    Err(GreetingError::ClientWriteFailed(e))
                } else {
                    let _ = buf_writer.flush().await;
                    Err(e)
                }
            }
            Err(_) => {
                let _ = buf_writer.flush().await;
                Err(GreetingError::Timeout)
            }
        }
    }

    /// 问候失败时向客户端补发一条 421 "service not ready"，附带失败原因。
    /// 若已向客户端转发过任何字节（`total_to_write > 0`），为避免协议状态混乱而跳过。
    pub(super) async fn reply_no_service<CW>(self, e: &GreetingError, clt_w: &mut CW)
    where
        CW: AsyncWrite + Unpin,
    {
        if self.total_to_write > 0 {
            return;
        }
        let reason = match e {
            GreetingError::Timeout => "read timeout",
            GreetingError::InvalidResponseLine(_) => "invalid response",
            GreetingError::UnexpectedReplyCode(_) => "unexpected reply code",
            GreetingError::UpstreamReadFailed(_) => "read failed",
            GreetingError::UpstreamClosed => "connection closed",
            _ => return,
        };
        let rsp = ResponseEncoder::upstream_service_not_ready(self.local_ip, reason);
        let _ = clt_w.write_all_flush(rsp.as_bytes()).await;
        let _ = clt_w.shutdown().await;
    }
}

/// 问候阶段可能出现的协议/IO 错误。
#[derive(Debug, Error)]
pub(super) enum GreetingError {
    /// 读取问候响应超时。
    #[error("greeting timeout")]
    Timeout,
    /// 响应行格式非法。
    #[error("invalid greeting response line: {0}")]
    InvalidResponseLine(#[from] ResponseLineError),
    /// 响应行超长。
    #[error("response line too long")]
    TooLongResponseLine,
    /// 问候阶段出现了不该出现的响应码。
    #[error("unexpected reply code {0} in greeting stage")]
    UnexpectedReplyCode(ReplyCode),
    /// 220 响应缺少主机名字段。
    #[error("no host field in greeting message")]
    NoHostField,
    /// 主机名字段格式不被支持。
    #[error("unsupported host format")]
    UnsupportedHostFormat,
    /// 向客户端写数据失败。
    #[error("write to client failed: {0:?}")]
    ClientWriteFailed(io::Error),
    /// 从源站读数据失败。
    #[error("read from upstream failed: {0:?}")]
    UpstreamReadFailed(io::Error),
    /// 源站关闭了连接。
    #[error("upstream closed connection")]
    UpstreamClosed,
}

// 将底层行读取错误映射为问候阶段语义错误。
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

// 将问候阶段错误归一化为服务端任务错误，供上层统一处理。
impl From<GreetingError> for ServerTaskError {
    fn from(value: GreetingError) -> Self {
        match value {
            GreetingError::Timeout => ServerTaskError::UpstreamAppTimeout("smtp greeting timeout"),
            GreetingError::InvalidResponseLine(e) => {
                ServerTaskError::UpstreamAppError(anyhow!("invalid greeting response line: {e}"))
            }
            GreetingError::TooLongResponseLine => {
                ServerTaskError::UpstreamAppError(anyhow!("response line too long"))
            }
            GreetingError::UnexpectedReplyCode(c) => ServerTaskError::UpstreamAppError(anyhow!(
                "unknown reply code {c} in greeting stage",
            )),
            GreetingError::NoHostField => {
                ServerTaskError::UpstreamAppError(anyhow!("no host found in smtp greeting message"))
            }
            GreetingError::UnsupportedHostFormat => ServerTaskError::UpstreamAppError(anyhow!(
                "unsupported host in smtp greeting message"
            )),
            GreetingError::ClientWriteFailed(e) => ServerTaskError::ClientTcpWriteFailed(e),
            GreetingError::UpstreamReadFailed(e) => ServerTaskError::UpstreamReadFailed(e),
            GreetingError::UpstreamClosed => ServerTaskError::ClosedByUpstream,
        }
    }
}
