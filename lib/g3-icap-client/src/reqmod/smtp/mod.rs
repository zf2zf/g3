/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 邮件正文的 ICAP REQMOD（请求修改）适配器 —— 请求头拼装部分。
//!
//! 本模块工作在 SMTP 协议的 DATA 阶段：把一封邮件伪装成一个 HTTP PUT 请求，
//! 封装进 ICAP 请求的 encap-request 部分交给 ICAP 服务器扫描，再根据响应决定
//! "原样转发"、"转发被改写后的邮件"还是"用 ICAP 返回的 HTTP 错误响应回复客户端"。
//!
//! 封装出的伪 HTTP 报文格式（由 [`build_http_header`] 拼装请求头，正文由
//! 子模块 `data` 以 chunked 分块传输编码流式追加）：
//! ```text
//! PUT / HTTP/1.1\r\n
//! Content-Type: message/rfc822\r\n
//! X-SMTP-From: <reverse_path>\r\n     // MAIL FROM 的反向路径，固定一条
//! X-SMTP-To: <forward_path>\r\n       // RCPT TO 的正向路径，每个收件人一条
//! X-SMTP-To: <forward_path>\r\n       // （可重复）
//! \r\n
//! <邮件正文（已去掉点转义），以 chunked 编码写入 ICAP req-body>
//! ```
//!
//! ICAP 自身的扩展头（不属于上面的伪 HTTP 报文）由 `push_extended_headers`
//! 追加，内容为 `X-Transformed-From: SMTP`、`X-Client-IP` / `X-Client-Port`
//! （来自 `set_client_addr`）以及 `X-Client-Username` / `X-Authenticated-User`
//! （来自 `set_client_username`）。
//!
//! 真正的双向收发流程在子模块 `data` 中实现；SMTP 场景暂不支持 preview 机制。
//!
//! [`build_http_header`]: SmtpMessageAdapter::build_http_header

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use arcstr::ArcStr;
use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_io_ext::{IdleCheck, StreamCopyConfig};
use g3_smtp_proto::command::{MailParam, RecipientParam};

use super::IcapReqmodClient;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::{IcapClientConnection, IcapServiceClient};

// 当 ICAP 返回一个替代性的 HTTP 错误响应（用于直接回复 SMTP 客户端）时，
// 其解析方式与 h1 适配器完全一致，因此直接复用 h1 的响应类型。
pub use crate::reqmod::h1::HttpAdapterErrorResponse;

// 适配过程中的各类错误
mod error;
pub use error::SmtpAdaptationError;

// DATA 阶段邮件正文的收发流程（构建 ICAP 请求、双向传输、按响应类型分派处理）
mod data;

impl IcapReqmodClient {
    /// 创建一个用于审计 SMTP 邮件正文的 REQMOD 适配器。
    ///
    /// 会从连接池中取出一条已建立的 ICAP 连接（内部先做 OPTIONS/连接复用），
    /// `copy_config` 控制正文拷贝时的缓冲区大小与 yield 粒度，
    /// `idle_checker` 用于在传输长时间无进展时超时退出或强制终止。
    ///
    /// 注意：本接口不返回 ICAP 的 OPTIONS 结果，SMTP 场景暂不基于 OPTIONS
    /// 做决策（例如是否支持 preview）。
    pub async fn smtp_message_adaptor<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> anyhow::Result<SmtpMessageAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, _icap_options) = icap_client.fetch_connection().await?;
        Ok(SmtpMessageAdapter {
            icap_client,
            icap_connection,
            copy_config,
            idle_checker,
            client_addr: None,
            client_username: None,
        })
    }
}

/// SMTP 邮件正文审计适配器的状态集合。
///
/// 采用"消耗自身（`self`）"的构建方式：调用方先设置好客户端信息，再调用
/// `xfer_data` 一次性完成整封邮件的传输，之后适配器即被消费。
pub struct SmtpMessageAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    copy_config: StreamCopyConfig,
    // TODO add SMTP config
    idle_checker: I,
    // 客户端地址，用于生成 ICAP 的 X-Client-IP / X-Client-Port 扩展头
    client_addr: Option<SocketAddr>,
    // 客户端用户名，用于生成 X-Client-Username / X-Authenticated-User 扩展头
    client_username: Option<ArcStr>,
}

impl<I: IdleCheck> SmtpMessageAdapter<I> {
    /// 记录 SMTP 客户端（发起 MAIL FROM 的一侧）的地址。
    ///
    /// 设置后会以 `X-Client-IP` / `X-Client-Port` 扩展头告知 ICAP 服务器。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 记录 SMTP 客户端的用户名（通常是已认证的用户名）。
    ///
    /// 设置后会以 `X-Client-Username` / `X-Authenticated-User` 扩展头告知 ICAP 服务器。
    pub fn set_client_username(&mut self, user: ArcStr) {
        self.client_username = Some(user);
    }

    /// 拼装封装用的伪 HTTP 请求头（作为 ICAP encap-request 的 req-hdr 部分）。
    ///
    /// 生成结果形如：
    /// ```text
    /// PUT / HTTP/1.1\r\n
    /// Content-Type: message/rfc822\r\n
    /// X-SMTP-From: <alice@example.com>\r\n
    /// X-SMTP-To: <bob@example.com>\r\n
    /// \r\n
    /// ```
    /// 使用 `PUT` 是因为 ICAP REQMOD 语义上等价于"修改这个请求"，方法与路径
    /// 本身对邮件审计并无意义；收件人可能有多个，因此输出多条 `X-SMTP-To`。
    ///
    /// 返回值的长度会作为 `Encapsulated: req-hdr=0, req-body=<len>` 中的偏移量
    /// 使用（见 `data` 子模块），所以此处头部与后续正文之间不能有多余字节。
    /// 末尾的空行 `\r\n` 就是 HTTP 头与正文的分隔行，已包含在返回长度内。
    pub fn build_http_header(&self, mail_from: &MailParam, mail_to: &[RecipientParam]) -> Vec<u8> {
        let mut header = Vec::with_capacity(128);
        header.extend_from_slice(b"PUT / HTTP/1.1\r\n");
        // 邮件正文本身就是 RFC822 报文，因此内容类型固定为 message/rfc822
        header.extend_from_slice(b"Content-Type: message/rfc822\r\n");
        let _ = write!(&mut header, "X-SMTP-From: {}\r\n", mail_from.reverse_path());
        // 每个 RCPT TO 生成一条独立的 X-SMTP-To 头
        for to in mail_to {
            let _ = write!(&mut header, "X-SMTP-To: {}\r\n", to.forward_path());
        }
        header.extend_from_slice(b"\r\n");
        header
    }

    /// 追加 ICAP 协议的扩展头（写在 ICAP 请求头上，而非封装的 HTTP 头里）。
    ///
    /// `X-Transformed-From: SMTP` 告诉 ICAP 服务器原始协议是 SMTP，
    /// 其余客户端地址/用户名头为可选，只有调用方设置过才会输出。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"X-Transformed-From: SMTP\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(user) = &self.client_username {
            crate::serialize::add_client_username(data, user);
        }
    }

    /// 传输并审计一封 SMTP 邮件正文的入口。
    ///
    /// - `state`：本次适配的运行态（客户端是否读完、是否已向上游发全等）
    /// - `clt_r`：SMTP 客户端方向的读取半区，即 DATA 命令之后收到的邮件正文
    /// - `ups_w`：SMTP 上游方向的写入半区，审计通过的（可能被改写的）邮件写回这里
    /// - `mail_from` / `mail_to`：MAIL FROM 与全部 RCPT TO 参数，用于拼装伪 HTTP 头
    pub async fn xfer_data<CR, UW>(
        self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: &mut UW,
        mail_from: &MailParam,
        mail_to: &[RecipientParam],
    ) -> Result<ReqmodAdaptationEndState, SmtpAdaptationError>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        // TODO support preview?
        self.xfer_data_without_preview(state, clt_r, ups_w, mail_from, mail_to)
            .await
    }
}
