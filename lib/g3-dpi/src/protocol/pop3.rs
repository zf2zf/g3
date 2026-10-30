/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! POP3 服务端 greeting 识别。
//!
//! POP3（服务端先发言）建连后立刻发送单行状态响应，正常形态是 `+OK <文本>` + CRLF。
//! 五个文本协议里只有 POP3 以 ASCII `'+'`（0x2B）开头——SMTP / FTP / NNTP 是数字，
//! IMAP 是 `'*'`，NATS 是 `'I'`——因此首字节本身就是极强的证据：
//! 一旦确认，可以把其他所有「服务端先发言」的候选整体排除。
//!
//! ```text
//!  offset:  0     1     2     3                        n-2    n-1
//!        +-----+-----+-----+------------------------+------+------+
//!        | '+' | 'O' | 'K' | <文本，可为空>            | '\r' | '\n' |
//!        +-----+-----+-----+------------------------+------+------+
//! ```
//!
//! 判定只覆盖 `+OK` 前缀与行尾 CRLF，正文不参与校验，所以这段数据不区分
//! `+OK` 之后跟的是欢迎语还是命令回显——识别阶段够用，因为 greeting 总是首行。
//! 行长不可预知，故未见 `\n` 时返回 `NeedMoreData(1)` 逐字节推进，
//! 并用 `MAXIMUM_DATA_LEN` 设上限，避免随机流量把探测拖成无限等待。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从服务端 greeting 识别 POP3：校验 `+OK` 前缀与首行行尾。
    ///
    /// `Ok(Some(..))` 已确认；`Ok(None)` 明确不是（已排除当前候选）；
    /// `Err(NeedMoreData)` 表示首行还没读完。
    pub(crate) fn check_pop3_server_greeting(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least +OK <M>\r\n
        // 5 字节是能同时读到 "+OK" 与末尾 CRLF 两个校验点的最小前提
        const MINIMUM_DATA_LEN: usize = 5;
        // greeting 是单行；缓冲超过此长度仍未结束就不可能是 POP3 响应
        const MAXIMUM_DATA_LEN: usize = 512;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }
        if data_len > MAXIMUM_DATA_LEN {
            self.exclude_current();
            return Ok(None);
        }

        // 首字节必须是 '+'：其他文本协议的 greeting 首字符都不可能是它
        if data[0] != b'+' {
            // 0x2B
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 走到这里已确定首字节是 '+'，与下列协议 greeting 的首字符集合互斥
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);
        self.exclude_other(MaybeProtocol::Nntp);
        self.exclude_other(MaybeProtocol::Nnsp);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);

        if &data[1..3] != b"OK" {
            // '-ERR' 等其他状态码不是就绪 greeting，不足以定论为 POP3
            self.exclude_current();
            return Ok(None);
        }

        // 以下两行按「缓冲末尾恰好是行尾」判断首行是否读全：
        // `data` 是累积的服务端首包，而 greeting 只有一行，所以没读到 '\n' 就是数据不足
        if data[data_len - 1] != b'\n' {
            return Err(ProtocolInspectError::NeedMoreData(1));
        }
        if data[data_len - 2] != b'\r' {
            // 裸 LF 结尾不是 POP3 的 CRLF 行结束
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Pop3))
    }
}
