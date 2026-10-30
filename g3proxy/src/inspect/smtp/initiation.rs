/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 发起阶段（EHLO/HELO 握手）。
//!
//! [`Initiation`] 中继客户端发出的第一个 EHLO/HELO 命令，解析源站返回的扩展能力列表
//! （[`InitializedExtensions`]），并提取客户端自报主机名。
//! 白名单机制：只有代理愿意透传的扩展关键字才会转发给客户端，未识别的扩展行会被丢弃，
//! 防止客户端使用代理无法拦截的 SMTP 扩展。本阶段位于问候（greeting）之后、
//! 命令转发（forward）之前。

use std::net::IpAddr;
use std::str;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_dpi::SmtpInterceptionConfig;
use g3_io_ext::{LimitedWriteExt, LineRecvBuf};
use g3_smtp_proto::command::Command;
use g3_smtp_proto::response::{ReplyCode, ResponseEncoder, ResponseParser};
use g3_types::net::Host;

use super::{CommandLineRecvExt, ResponseLineRecvExt, ResponseParseExt};
use crate::serve::{ServerTaskError, ServerTaskResult};

/// EHLO 响应中解析出的服务端扩展能力集合，各字段表示服务器是否宣告过该扩展。
#[derive(Default)]
pub(super) struct InitializedExtensions {
    odmr: bool,     // 按需邮件中继 ATRN（RFC2645）
    starttls: bool, // STARTTLS 升级（RFC3207）
    chunking: bool, // BDAT 分块传输（RFC3030）
    burl: bool,     // 按 URL 投递数据 BURL（RFC4468）
}

impl InitializedExtensions {
    /// 是否允许使用 ODMR（ATRN 反向连接）：服务器宣告过且配置开关打开。
    pub(super) fn allow_odmr(&self, config: &SmtpInterceptionConfig) -> bool {
        self.odmr && config.allow_on_demand_mail_relay
    }

    /// 是否允许 STARTTLS：服务器宣告过且会话尚未完成 TLS 升级（避免重复升级）。
    pub(super) fn allow_starttls(&self, from_starttls: bool) -> bool {
        self.starttls && !from_starttls
    }

    /// 是否允许 BDAT 分块传输：服务器宣告过且配置允许。
    pub(super) fn allow_chunking(&self, config: &SmtpInterceptionConfig) -> bool {
        self.chunking && config.allow_data_chunking
    }

    /// 是否允许 BURL 按 URL 投递：服务器宣告过且配置允许。
    pub(super) fn allow_burl(&self, config: &SmtpInterceptionConfig) -> bool {
        self.burl && config.allow_burl_data
    }
}

/// 发起阶段状态机：记录客户端自报主机名与服务端扩展能力白名单过滤结果。
pub(super) struct Initiation<'a> {
    config: &'a SmtpInterceptionConfig,
    local_ip: IpAddr,
    from_starttls: bool,
    client_host: Host,
    server_ext: InitializedExtensions,
}

impl<'a> Initiation<'a> {
    /// `from_starttls` 为真表示 TLS 升级后重新发起 EHLO（此时不应再允许 STARTTLS 扩展）。
    pub(super) fn new(
        config: &'a SmtpInterceptionConfig,
        local_ip: IpAddr,
        from_starttls: bool,
    ) -> Self {
        Initiation {
            config,
            local_ip,
            from_starttls,
            client_host: Host::empty(),
            server_ext: InitializedExtensions::default(),
        }
    }

    /// 拆出协商结果：(客户端主机名, 服务端扩展能力集合)。
    pub(super) fn into_parts(self) -> (Host, InitializedExtensions) {
        (self.client_host, self.server_ext)
    }

    /// 驱动 EHLO/HELO 交换：循环接收客户端命令（非 EHLO/HELO 一律回 503 拒绝），
    /// 转发到源站并中继/过滤其响应；收到 250 完整响应后结束。
    pub(super) async fn relay<CR, CW, UR, UW>(
        &mut self,
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
        let mut cmd_recv_buf = LineRecvBuf::<{ Command::MAX_LINE_SIZE }>::default();
        let mut rsp_recv_buf = LineRecvBuf::<{ ResponseParser::MAX_LINE_SIZE }>::default();

        loop {
            cmd_recv_buf.consume_line();
            let (cmd, cmd_line) = cmd_recv_buf
                .recv_cmd(self.config.command_wait_timeout, clt_r, clt_w)
                .await?;

            match cmd {
                // 仅接受 EHLO/HELO，并记录客户端自报的主机名
                Command::ExtendHello(host) => {
                    self.client_host = host;
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                }
                Command::Hello(host) => {
                    self.client_host = host;
                    self.send_cmd(ups_w, clt_w, cmd_line).await?;
                }
                // 其它命令在发起阶段属于时序错误，本地直接回 503
                _ => {
                    self.send_error_to_client(clt_w, ResponseEncoder::BAD_SEQUENCE_OF_COMMANDS)
                        .await?;
                }
            }

            // 收到 250 完整响应（Some）即协商完成；4xx/5xx 则回到循环等下一条命令
            if self
                .recv_relay_check_rsp(&mut rsp_recv_buf, ups_r, clt_w)
                .await?
                .is_some()
            {
                return Ok(());
            }
        }
    }

    /// 把命令行原样转发到源站；写失败时先向客户端回 451 IO 错误再返回错误。
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

    /// 逐行读取并中继源站对 EHLO/HELO 的响应，同时对 250 的扩展行做白名单过滤。
    /// 返回 `Some(())` 表示协商成功完成（250 最后一行），`None` 表示以其它响应码结束。
    pub(super) async fn recv_relay_check_rsp<CW, UR>(
        &mut self,
        rsp_recv_buf: &mut LineRecvBuf<{ ResponseParser::MAX_LINE_SIZE }>,
        ups_r: &mut UR,
        clt_w: &mut CW,
    ) -> ServerTaskResult<Option<()>>
    where
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
    {
        let mut rsp = ResponseParser::default();
        loop {
            rsp_recv_buf.consume_line();
            let line = rsp_recv_buf
                .read_rsp_line_with_feedback(
                    self.config.response_wait_timeout,
                    ups_r,
                    clt_w,
                    self.local_ip,
                )
                .await?;
            let msg = rsp
                .feed_line_with_feedback(line, clt_w, self.local_ip)
                .await?;

            match rsp.code() {
                ReplyCode::OK => {
                    // 250 首行（问候语本身）总是转发；后续扩展行只有白名单内的才转发，
                    // 未识别的扩展行被丢弃，客户端因此不会使用代理无法拦截的扩展
                    if rsp.is_first_line() || self.allow_extension(msg) {
                        clt_w
                            .write_all(line)
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                    }

                    if rsp.finished() {
                        clt_w
                            .flush()
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        return Ok(Some(()));
                    }
                }
                ReplyCode::SERVICE_NOT_AVAILABLE => {
                    // 421：源站服务不可用，转发后终止整个任务
                    clt_w
                        .write_all(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                    if rsp.finished() {
                        let _ = clt_w.flush().await;
                        return Err(ServerTaskError::UpstreamAppUnavailable);
                    }
                }
                _ => {
                    // 其它响应码原样转发；响应结束后返回 None 让上层重新等待命令
                    clt_w
                        .write_all(line)
                        .await
                        .map_err(ServerTaskError::ClientTcpWriteFailed)?;

                    if rsp.finished() {
                        clt_w
                            .flush()
                            .await
                            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// EHLO 扩展关键字白名单：判断该扩展行是否应转发给客户端，并顺带记录服务器已宣告的能力。
    /// `msg` 带参数时（含空格）走"带参扩展"分支；关键字大小写不敏感。
    /// 返回 false 表示该行被过滤，客户端不可见。
    fn allow_extension(&mut self, msg: &[u8]) -> bool {
        if let Some(p) = memchr::memchr(b' ', msg) {
            let Ok(keyword) = str::from_utf8(&msg[..p]) else {
                return false;
            };

            match keyword.to_uppercase().as_str() {
                // Message Size Declaration, RFC1870, TODO use this max message limit ?
                // 消息大小声明：仅转发参数信息，代理不额外记录上限
                "SIZE" => true,
                // Deliver By, RFC2852, add a MAIL BY param key
                "DELIVERBY" => true,
                // No Soliciting, RFC3865, add a MAIL param key
                "NO-SOLICITING" => true,
                // Authentication, RFC4954, add AUTH command
                "AUTH" => true,
                // BURL, RFC4468, add BURL command
                "BURL" => {
                    self.server_ext.burl = true;
                    self.config.allow_burl_data
                }
                // Future Message Release, RFC4865, add MAIL param keys
                "FUTURERELEASE" => true,
                // Priority Message Handling, RFC6710, add a MAIL param key
                "MT-PRIORITY" => true,
                // LIMITS, RFC9422
                "LIMITS" => true,
                _ => false,
            }
        } else {
            let Ok(keyword) = str::from_utf8(msg) else {
                return false;
            };

            match keyword.to_uppercase().as_str() {
                // Expand the mailing list, RFC5321, add EXPN command
                "EXPN" => true,
                // Supply helpful information, RFC5321, add HELP command
                "HELP" => true,
                // 8bit-MIMEtransport, RFC6152, add a MAIL BODY param value
                "8BITMIME" => true,
                // Message Size Declaration, RFC1870
                "SIZE" => true,
                // Verbose
                "VERB" => true,
                // One message transaction only
                "ONEX" => true,
                // CHUNKING, RFC3030, add BDAT command
                // 分块传输：记录服务器能力，是否放行还取决于配置开关
                "CHUNKING" => {
                    self.server_ext.chunking = true;
                    self.config.allow_data_chunking
                }
                // BINARYMIME, RFC3030, add a MAIL BODY param value, require CHUNKING
                // 二进制 MIME：依赖 CHUNKING，配置不允许分块时整行过滤掉
                "BINARYMIME" => self.config.allow_data_chunking,
                // Deliver By, RFC2852, add a MAIL BY param key
                "DELIVERBY" => true,
                // Pipelining, RFC2920
                "PIPELINING" => true,
                // Delivery Status Notification, RFC3461, add param keys to RCPT and MAIL
                "DSN" => true,
                // Remote Queue Processing Declaration, RFC1985, add ETRN command
                "ETRN" => true,
                // Enhanced-Status-Codes, RFC2034, add status code preface to response
                // 增强状态码：故意不透传（返回 false），避免响应文本超出解析预期
                "ENHANCEDSTATUSCODES" => false,
                // STARTTLS, RFC3207, add STARTTLS command
                // TLS 升级：记录能力；若本会话已由 STARTTLS 升级而来则不再透传
                "STARTTLS" => {
                    self.server_ext.starttls = true;
                    !self.from_starttls
                }
                // No Soliciting, RFC3865, add a MAIL param key
                "NO-SOLICITING" => true,
                // Message Tracking, RFC3885, add a MAIL MTRK param key
                "MTRK" => true,
                // BURL, RFC4468, add BURL command, no param means AUTH is required
                // 按 URL 投递：记录能力，是否放行取决于配置开关
                "BURL" => {
                    self.server_ext.burl = true;
                    self.config.allow_burl_data
                }
                // Content-Conversion-Permission, RFC4141, add a MAIL param key
                "CONPERM" => true,
                // Content-Negotiation, RFC4141, add a RCPT param key
                "CONNEG" => true,
                // Internationalized Email, RFC6531, add MAIL/VRFY/EXPN param key
                "SMTPUTF8" => true,
                // Priority Message Handling, RFC6710, add a MAIL param key
                "MT-PRIORITY" => true,
                // Require Recipient Valid Since, RFC7293, add a RCPT param key
                "RRVS" => true,
                // Require TLS, RFC8689, add a MAIL param key
                "REQUIRETLS" => true,
                // LIMITS, RFC9422
                "LIMITS" => true,
                // On-Demand Mail Relay, RFC2645, change the protocol
                // 按需邮件中继：记录能力；ATRN 会建立反向连接，届时转透明中继
                "ATRN" => {
                    self.server_ext.odmr = true;
                    self.config.allow_on_demand_mail_relay
                }
                _ => false,
            }
        }
    }
}
