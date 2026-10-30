/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! NATS 服务端 INFO 消息识别。
//!
//! NATS 是控制行（control line）式文本协议，服务端接受连接后立刻推送一行
//! `INFO <JSON>` + CRLF，内容是服务器自身的能力描述（版本、监听地址等）。
//! 本探测器只认这一条命令，判据是三件套：字面前缀 `INFO {`、行尾 CRLF、行长上限。
//!
//! ```text
//!  offset:  0     1     2     3     4     5     6                n-2    n-1
//!        +-----+-----+-----+-----+-----+-----+-----+-----------+------+------+
//!        | 'I' | 'N' | 'F' | 'O' | ' ' | '{' |   JSON 对象内容    | '\r' | '\n' |
//!        +-----+-----+-----+-----+-----+-----+-----+-----------+------+------+
//!         \_____ "INFO {" 字面匹配 _____/  \__ 内容不做 JSON 解析 __/
//! ```
//!
//! 为什么这些特征足够：在「服务端先发言」的候选集合里，只有 NATS 以 `'I'` 开头
//! （FTP / SMTP / NNTP 是数字，POP3 是 `'+'`，IMAP 是 `'*'`，SSH 是 `'S'`，
//! BitTorrent 是 `0x13`）；再叠加 `INFO {` 这段字面量——命令名之后紧跟空格和
//! JSON 的起始花括号——几乎不会出现在其他协议的 greeting 文本里，
//! 因此不需要解析 JSON 就能定论。
//!
//! 难点是行长：INFO 里的 JSON 字段数量取决于服务器配置（开启 JetStream、leaf node
//! 等会让它明显变长），一条消息很可能跨多次读。故未见 `\n` 时返回 `NeedMoreData(1)`
//! 增量等待，并用可配置的 `size_limit.nats_server_info_line`（默认 1024）封顶。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};
use crate::ProtocolInspectionSizeLimit;

impl ProtocolInspectState {
    /// 从服务端首包识别 NATS：校验 `INFO {` 前缀与行尾 CRLF。
    ///
    /// `size_limit` 用于首行未见 `\n` 时的长度兜底。JSON 内容不被解析，
    /// 也就不校验结尾的 `}`。
    pub(crate) fn check_nats_server_info_msg(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least INFO {<M>}\r\n
        // `INFO {`(6) 之外还要留出内容与 CRLF，取 10 作为访问末尾两字节的安全下限
        const MINIMUM_DATA_LEN: usize = 10;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // 先做单字节快筛：'I' 与其余 greeting 类协议的首字符互斥，无需比较整串前缀
        if data[0] != b'I' {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Nntp);
        self.exclude_other(MaybeProtocol::Nnsp);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::BitTorrent);

        // 命令名 + 空格 + JSON 起始花括号：把裸文本恰好以 INFO 开头的情况挡掉
        if !data.starts_with(b"INFO {") {
            self.exclude_current();
            return Ok(None);
        }

        // `data` 是累积的服务端首包，而 INFO 消息以 CRLF 结束，
        // 故缓冲末尾不是 '\n' 就说明这条消息还没读全
        if data[data_len - 1] != b'\n' {
            // 以整个缓冲长度为依据对比上限：JSON 可能较长，允许继续等，
            // 但超过配置值就不再当作 NATS
            return if data_len > size_limit.nats_server_info_line {
                self.exclude_current();
                Ok(None)
            } else {
                Err(ProtocolInspectError::NeedMoreData(1))
            };
        }
        if data[data_len - 2] != b'\r' {
            // 裸 LF 结尾不符合 NATS 控制行的 CRLF 约定
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Nats))
    }
}
