/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! SMTP / ODMR 服务端 greeting 识别。
//!
//! 与 TLS、HTTP 这类「客户端先发言」的协议相反，SMTP 建连后由服务端立刻发一行回复：
//! 服务就绪是 `220 <domain> <string>` + CRLF，服务不可用则可能直接以 `554 ...` 结束。
//! 识别依据就是这一行，分派表把 [`MaybeProtocol::Odmr`] 也交给本函数——
//! ODMR 是 SMTP 的受限子集，greeting 形态一致，无法（也无需）在此区分。
//!
//! ```text
//!  offset:  0     1     2     3     4                        n-2    n-1
//!        +-----+-----+-----+-----+------------------------+------+------+
//!        | '2' | '2' | '0' | ' ' | <domain> <string>...   | '\r' | '\n' |
//!        +-----+-----+-----+-----+------------------------+------+------+
//!         \____ 三位数码 ____/     \____ 回复文本：首个空格前是 host ____/
//! ```
//!
//! 判定难点有两处：
//!
//! 1. **数码与其他文本协议重叠**。FTP 的 greeting 同样以 `220 ` 开头，NNTP 也是 `2xx`
//!    开头。真正的区分点是正文结构：SMTP 的 `220 ` 之后必须紧跟一个合法 host address
//!    （域名、`[IPv4]` 或 `Ipv6:...`，由 `Host::parse_smtp_host_address` 校验），
//!    而 FTP 的 banner 是任意文本；NNTP 在本 crate 的探测器里只接受 `200` / `201`，
//!    所以确定为 `22x` 就能把 NNTP / NNSP 整体排除。
//! 2. **行长未知**。`data` 是累积的服务端首包，可能只含半行。在见到 `\n` 之前只能
//!    不断返回 `NeedMoreData(1)` 小步推进；同时用 `REPLY_LINE_MAX_SIZE` 兜底——
//!    超过该长度仍没有换行的数据不可能是 SMTP 回复行，直接排除以免无限等待。

use g3_types::net::Host;

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

/// 回复行的最大可接受长度：超过它仍未见到 `\n` 就判定不是 SMTP。
///
/// 本模块内硬编码，不像 IMAP / NATS 那样走 `ProtocolInspectionSizeLimit` 配置。
const REPLY_LINE_MAX_SIZE: usize = 512;

impl ProtocolInspectState {
    /// 从服务端 greeting 识别 SMTP，入口先按首字节分派到 `220` 与 `554` 两种形态。
    ///
    /// 返回 `Ok(Some(Protocol::Smtp))` 表示已确认；`Ok(None)` 表示不是 SMTP（多数分支
    /// 已顺带 `exclude_current`）；`Err(NeedMoreData)` 表示首行还没读全。
    pub(crate) fn check_smtp_server_greeting(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least XYZ <address>\r\n
        // 3 位数码 + 分隔符 + 至少 1 字节正文 + CRLF = 7，不足则连结构都无法校验
        const MINIMUM_DATA_LEN: usize = 7;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        match data[0] {
            b'2' => {
                // 0x32
                self.smtp_exclude_by_byte0();

                // 必须是 22x：'2' 之后第二位不是 '2' 就不是 SMTP greeting
                if data[1] != b'2' {
                    self.exclude_current();
                    return Ok(None);
                }
                // NNTP 的 greeting 码只有 200 / 201（见 nntp.rs 的判定），
                // 确定为 22x 后两个候选都不可能出现
                self.exclude_other(MaybeProtocol::Nntp);
                self.exclude_other(MaybeProtocol::Nnsp);

                if data[2] == b'0' {
                    // may be FTP
                    // 220 与 FTP greeting 完全重叠，交给下钻函数按正文结构裁决
                    return self.check_smtp_after_code(data);
                }
            }
            b'5' => {
                // 0x35
                self.smtp_exclude_by_byte0();
                // FTP 探测器只认 120 / 220 / 421 三种首码，5xx 与它互斥
                self.exclude_other(MaybeProtocol::Ftp);
                // 5xx 同样不在 NNTP / NNSP 的合法 greeting 取值内
                self.exclude_other(MaybeProtocol::Nntp);
                self.exclude_other(MaybeProtocol::Nnsp);

                // 只有 554（服务不可用）才会作为 greeting 出现，其余 5xx 视为不匹配
                if &data[0..3] == b"554" {
                    return self.check_smtp_after_code(data);
                }
            }
            _ => {}
        }

        // 首字节既不是 '2' 也不是 '5'（或数码组合不被 SMTP 使用）：当前候选出局
        self.exclude_current();
        Ok(None)
    }

    /// 首字节是 ASCII 数字（`2` / `5`）时可一并剔除的候选。
    ///
    /// 这些协议的服务端 greeting 首字符固定不同：SSH 是 `'S'`、POP3 是 `'+'`、
    /// IMAP 是 `'*'`、NATS 是 `'I'`、BitTorrent 是 `0x13`，都不可能是数字。
    fn smtp_exclude_by_byte0(&mut self) {
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);
    }

    /// 数码之后的定论：校验分隔符并把回复正文的开头解析成 SMTP host address。
    ///
    /// 调用前提是 `data[0..3]` 已是 `220` 或 `554`。
    fn check_smtp_after_code(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // data[3] 是数码与正文的分隔符：空格表示首行（末行），
        // '-' 表示多行回复的中间行；其他字符不符合任何 SMTP 回复语法
        if !matches!(data[3], b' ' | b'-') {
            self.exclude_current();
            return Ok(None);
        }

        let left = &data[4..];
        if let Some(p) = memchr::memchr(b'\n', left) {
            if p < 1 {
                // at lease "<addr>\n"
                // 正文为空（`\n` 就在第一个字节），没有 host address 可用
                self.exclude_current();
                return Ok(None);
            }
            // 换行前必须是回车：本 crate 按 CRLF 行结束判定，裸 LF 直接排除
            if left[p - 1] != b'\r' {
                self.exclude_current();
                return Ok(None);
            }

            // 取到首个空格为止作为 host address；正文里没有空格就整段（去掉 \r）当作 host
            let end_host = memchr::memchr(b' ', left).unwrap_or(p - 1);
            if Host::parse_smtp_host_address(&left[..end_host]).is_some() {
                Ok(Some(Protocol::Smtp))
            } else {
                // 首行结构合法但正文开头不像 host address：判定这不是 SMTP greeting。
                // 注意此时首行已经读完整（上面已找到 '\n' 与 '\r'），所以没有可等待的
                // 新数据；与其余分支不同，这里不调用 exclude_current，因此候选不会被
                // 记入排除集合，只是本轮不下结论。（描述现状，未作修改）
                Ok(None)
            }
        } else if left.len() > REPLY_LINE_MAX_SIZE {
            // 首行超长仍无换行，不可能是 SMTP greeting
            self.exclude_current();
            Ok(None)
        } else {
            // 行还没读全：每次只要 1 个新字节，直到出现 `\n` 或超过长度上限
            Err(ProtocolInspectError::NeedMoreData(1))
        }
    }
}
