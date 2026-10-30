/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! IMAP4rev1 服务端 greeting 识别。
//!
//! IMAP 建连后服务端先发一条 **untagged 响应**：以 `*` 加一个空格开头，
//! 再接状态关键字。本探测器接受三种关键字：
//!
//! - `* OK <文本>`：等待客户端发 LOGIN（最短，`* OK` + CRLF 共 6 字节即可定论）
//! - `* PREAUTH`：连接已是预认证状态（例如由外层 TLS 客户端证书完成），不必再走 LOGIN
//! - `* BYE`：服务端主动告别、关闭连接
//!
//! ```text
//!  offset:  0     1     2 ...          n-2    n-1
//!        +-----+-----+--------------+------+------+
//!        | '*' | ' ' | 状态关键字文本 | '\r' | '\n' |
//!        +-----+-----+--------------+------+------+
//!                       ^-- 'O'(OK) / 'P'(PREAUTH) / 'B'(BYE)
//! ```
//!
//! 首字节 `'*'`（0x2A）在「服务端先发言」的文本协议里是独占的：POP3 用 `'+'`、
//! SMTP / FTP / NNTP 用数字、NATS 用 `'I'`、SSH 用 `'S'`、BitTorrent 用 `0x13`，
//! 所以确认 `*` 之后可以一次性把这些候选全部剔除。
//!
//! 难点在长度：三个关键字的完整拼写长度不同（`PREAUTH` 要 7 个字母，
//! `OK` / `BYE` 只需再看两三个字节），且关键字之后还可能跟着很长的状态文本；
//! 因此在没读到 `\n` 之前只能返回 `NeedMoreData` 逐步推进，
//! 并用可配置的 `size_limit.imap_server_greeting_msg` 作为行长上限，
//! 防止把随机数据当成永不结束的一行。`NO` / `BAD` 等其他 untagged 响应不在接受之列。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};
use crate::ProtocolInspectionSizeLimit;

impl ProtocolInspectState {
    /// 从服务端 greeting 识别 IMAP：校验 `* ` 前缀、三种状态关键字、行尾 CRLF。
    ///
    /// `size_limit` 只用于首行尚未见 `\n` 时的长度兜底。
    pub(crate) fn check_imap_server_greeting(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least * OK <M>\r\n
        // 6 字节是最短的 `* OK` + CRLF，也是访问 data[3] / data[4] 的安全前提
        const MINIMUM_DATA_LEN: usize = 6;
        // at least * PREAUTH\r\n
        // `* `(2) + `PREAUTH`(7) + CRLF(2)，短于此则连关键字都还没收全
        const PREAUTH_MIN_DATA_LEN: usize = 11;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // untagged 响应的引导符必须是 '*'
        if data[0] != b'*' {
            // 0x2A
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 首字节为 '*' 与其他文本协议的 greeting 首字符集合互斥，一并排除
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Nntp);
        self.exclude_other(MaybeProtocol::Nnsp);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);

        // '*' 之后必须紧跟一个空格，这是 IMAP untagged 响应与 POP3 风格 `+OK` 的差异点
        if data[1] != b' ' {
            self.exclude_current();
            return Ok(None);
        }

        // 按关键字首字母分支：三条路径校验深度不同，取决于该关键字有多长
        match data[2] {
            b'O' => {
                // "OK"
                // 两个字母，只需再看 data[3]；后面的文本不做校验
                if data[3] != b'K' {
                    self.exclude_current();
                    return Ok(None);
                }
            }
            b'P' => {
                // "PREAUTH"
                // 7 个字母的关键字：数据不够长时必须补数据，而不是判为不匹配
                if data_len < PREAUTH_MIN_DATA_LEN {
                    return Err(ProtocolInspectError::NeedMoreData(
                        PREAUTH_MIN_DATA_LEN - data_len,
                    ));
                }
                if !data[2..].starts_with(b"PREAUTH") {
                    self.exclude_current();
                    return Ok(None);
                }
            }
            b'B' => {
                // "BYE"
                // 校验到 data[4]，MINIMUM_DATA_LEN = 6 已保证该下标可用
                if data[3] != b'Y' || data[4] != b'E' {
                    self.exclude_current();
                    return Ok(None);
                }
            }
            _ => {
                // 首字母既不是 O/P/B：不是本探测器接受的 greeting 关键字
                self.exclude_current();
                return Ok(None);
            }
        }

        // 关键字已匹配，剩下确认整行结束。`data` 是累积的服务端首包，
        // 而 greeting 只占一行，所以缓冲末尾不是 '\n' 就说明首行还没读全
        if data[data_len - 1] != b'\n' {
            // 以跳过 `* OK` 之后的长度作为行长依据，超过可配置上限就不再等待
            let left = &data[4..];
            return if left.len() > size_limit.imap_server_greeting_msg {
                self.exclude_current();
                Ok(None)
            } else {
                // 每次只要 1 个新字节，直到出现 '\n' 或触发上面的长度上限
                Err(ProtocolInspectError::NeedMoreData(1))
            };
        }
        if data[data_len - 2] != b'\r' {
            // 裸 LF 结尾不是 IMAP 的 CRLF 行结束
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Imap))
    }
}
