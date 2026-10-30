/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP APPEND 命令的 ICAP REQMOD（请求修改）适配器 —— 请求头拼装部分。
//!
//! 本模块工作在 IMAP 的 APPEND 命令上：客户端用 `APPEND mailbox flags (LIMIT n) {<literal_size>}`
//! 后跟一段 **literal**（即一整封 `message/rfc822` 邮件）。适配器把这段 literal
//! 伪装成 HTTP PUT 请求封装进 ICAP 的 encap-request，交给 ICAP 服务器审计，
//! 再按响应决定"原样写入上游"、"写入被改写后的邮件"或"返回替代的 HTTP 错误响应"。
//!
//! 封装出的伪 HTTP 报文格式（请求头由 `build_http_header()` 拼装，正文由
//! 子模块 `append` 写入）：
//! ```text
//! PUT / HTTP/1.1\r\n
//! Content-Type: message/rfc822\r\n
//! Content-Length: <literal_size>\r\n   // IMAP literal 的字节数，作为正文长度
//! \r\n
//! <literal 邮件内容，作为 ICAP req-body 以 chunked 编码传输>
//! ```
//! 与 SMTP 场景的差别：IMAP literal 长度已知（`Content-Length`），且**没有**
//! `X-SMTP-From` / `X-SMTP-To` 这类信封头（APPEND 命令本身不带发件人/收件人信封，
//! 只有邮箱名与 flags）。
//!
//! ICAP 自身的扩展头由 `push_extended_headers()` 追加：
//! `X-Transformed-From: IMAP`、`X-Client-IP` / `X-Client-Port`
//! （来自 `set_client_addr`）、`X-Client-Username` / `X-Authenticated-User`
//! （来自 `set_client_username`）。
//!
//! 子模块 `append` 实现了两种传输路径：literal 已完整缓存在内存时一次性上报
//! （`xfer_append_once`，可拿到 204 快速放行），长度不足时走流式续传。
//! IMAP 场景同样暂不支持 preview。

use std::net::SocketAddr;
use std::sync::Arc;

use arcstr::ArcStr;
use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite};

use g3_io_ext::{IdleCheck, StreamCopyConfig};

use super::IcapReqmodClient;
use crate::reqmod::mail::{ReqmodAdaptationEndState, ReqmodAdaptationRunState};
use crate::{IcapClientConnection, IcapServiceClient, IcapServiceOptions};

// 替代用 HTTP 错误响应的解析类型与 h1 适配器共用
pub use crate::reqmod::h1::HttpAdapterErrorResponse;

// 适配过程中的各类错误
mod error;
pub use error::ImapAdaptationError;

// APPEND literal 的收发流程
mod append;

impl IcapReqmodClient {
    /// 创建一个用于审计 IMAP APPEND literal 的 REQMOD 适配器。
    ///
    /// `literal_size` 是 IMAP `{<n>}` 中声明的字节数，必须准确：它既是伪 HTTP
    /// 请求的 `Content-Length`，也是后续 chunked 编码的块长与响应长度校验基准。
    ///
    /// 与 SMTP 不同，这里会把 ICAP 服务的 OPTIONS 结果（`icap_options`）一并保存，
    /// 因为完整缓存的 literal 走"一次性上报"路径时，需要根据服务端是否允许 204
    /// 来决定能否带上 `Allow: 204` 扩展头。
    pub async fn imap_message_adaptor<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
        literal_size: u64,
    ) -> anyhow::Result<ImapMessageAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(ImapMessageAdapter {
            icap_client,
            icap_connection,
            icap_options,
            copy_config,
            idle_checker,
            client_addr: None,
            client_username: None,
            literal_size,
        })
    }
}

/// IMAP APPEND literal 审计适配器的状态集合。
///
/// 与 SMTP 适配器一样采用"消耗自身"的调用方式：设置完客户端信息后调用
/// `xfer_append` 完成整段 literal 的传输与审计。
pub struct ImapMessageAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    icap_connection: IcapClientConnection,
    // OPTIONS 结果：用于判断服务端是否支持 204（Allow: 204）
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    idle_checker: I,
    // 客户端地址，用于生成 ICAP 的 X-Client-IP / X-Client-Port 扩展头
    client_addr: Option<SocketAddr>,
    // 客户端用户名，用于生成 X-Client-Username / X-Authenticated-User 扩展头
    client_username: Option<ArcStr>,
    // IMAP literal 的字节数，即待审计邮件的精确长度
    literal_size: u64,
}

impl<I: IdleCheck> ImapMessageAdapter<I> {
    /// 记录 IMAP 客户端的地址，设置后以 X-Client-IP / X-Client-Port 扩展头告知 ICAP。
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /// 记录 IMAP 客户端的登录用户名，设置后以 X-Client-Username /
    /// X-Authenticated-User 扩展头告知 ICAP。
    pub fn set_client_username(&mut self, user: ArcStr) {
        self.client_username = Some(user);
    }

    /// 拼装封装用的伪 HTTP 请求头（作为 ICAP encap-request 的 req-hdr 部分）。
    ///
    /// 生成结果形如：
    /// ```text
    /// PUT / HTTP/1.1\r\n
    /// Content-Type: message/rfc822\r\n
    /// Content-Length: 16384\r\n
    /// \r\n
    /// ```
    /// `Content-Length` 直接取 IMAP 的 literal 长度：literal 是一个长度自明的
    /// 字节串（不像 SMTP 那样靠 `\r\n.\r\n` 终止行表示结束），所以这里能给出
    /// 精确值，供 ICAP 服务器与后续响应校验使用。
    ///
    /// 返回值的长度会作为 `Encapsulated: req-hdr=0, req-body=<len>` 的偏移量，
    /// 末尾空行是 HTTP 头与正文的分隔行，已计入长度。
    pub fn build_http_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(128);
        header.extend_from_slice(b"PUT / HTTP/1.1\r\n");
        // literal 就是一封 RFC822 邮件，内容类型固定
        header.extend_from_slice(b"Content-Type: message/rfc822\r\n");

        // 用 itoa 把 u64 长度直接格式化进头部，避免额外分配
        let mut len_buf = itoa::Buffer::new();
        let len_s = len_buf.format(self.literal_size);

        header.extend_from_slice(b"Content-Length: ");
        header.extend_from_slice(len_s.as_bytes());
        header.extend_from_slice(b"\r\n");

        header.extend_from_slice(b"\r\n");
        header
    }

    /// 追加 ICAP 协议的扩展头（写在 ICAP 请求头上，而非封装的 HTTP 头里）。
    ///
    /// `X-Transformed-From: IMAP` 告知 ICAP 服务器原始协议是 IMAP；
    /// 地址与用户名头仅在调用方设置过才输出。
    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"X-Transformed-From: IMAP\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        if let Some(user) = &self.client_username {
            crate::serialize::add_client_username(data, user);
        }
    }

    /// 传输并审计 IMAP APPEND 的 literal 邮件。
    ///
    /// - `clt_r`：客户端方向剩余可读的 literal 数据（尚未缓存的部分从这里继续读）
    /// - `cached`：协议解析层已经缓存在内存中的 literal 前缀
    /// - `ups_w`：上游方向写入半区，审计通过的邮件写入这里
    ///
    /// 分支依据是"缓存是否已覆盖整段 literal"：
    /// - `literal_size > cached.len()`：还差 `literal_size - cached.len()` 字节，
    ///   需要继续从客户端边读边发（流式续传）
    /// - 否则：literal 已完整在手，一次性上报，可走 204 快速放行
    pub async fn xfer_append<CR, UW>(
        self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        cached: &[u8],
        ups_w: &mut UW,
    ) -> Result<ReqmodAdaptationEndState, ImapAdaptationError>
    where
        CR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        if self.literal_size > cached.len() as u64 {
            // TODO support preview?

            // 还需从客户端读取的剩余字节数 = literal 总长 - 已缓存长度
            let read_size = self.literal_size - cached.len() as u64;
            self.xfer_append_without_preview(state, clt_r, cached, read_size, ups_w)
                .await
        } else {
            self.xfer_append_once(state, cached, ups_w).await
        }
    }
}
