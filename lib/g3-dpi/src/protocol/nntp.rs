/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! NNTP / NNSP 服务端 greeting 识别。
//!
//! NNTP 是「服务端先发言」的文本协议：连接建立后服务端立刻发一行 `2xx` 状态码，
//! 只有两种值代表就绪——`200`（允许发帖）与 `201`（只读、不允许发帖），
//! 后面跟 `<server info>` 文本和 CRLF。NNTPFEED 转发通道（[`MaybeProtocol::Nnsp`] 候选）
//! 复用同一套语法，分派表把两者合并到本函数；由于首包完全同形，
//! 载荷层面无法区分，确认后统一返回 [`Protocol::Nntp`]
//! （[`Protocol::Nnsp`] 只能由 TLS ALPN 这类外部强证据给出）。
//!
//! ```text
//!  offset:  0     1     2     3                     n-2    n-1
//!        +-----+-----+-----+-----+---------------+------+------+
//!        | '2' | '0' | '0' | ' ' | <server info>   | '\r' | '\n' |
//!        +-----+-----+-----+-----+---------------+------+------+
//!         \____ 状态码 ____/       \__ 正文不做校验 __/
//!                     ^-- 只接受 '0' 或 '1'
//! ```
//!
//! 区分度靠状态码的**逐位**组合：`20x` 与 SMTP 的 `220`、FTP 的 `220` / `120` / `421`
//! 在第二位就分道扬镳，所以确认 `20` 之后可以把 SMTP / ODMR / FTP 整体排除；
//! 反过来这些协议也排除了本候选。
//!
//! 与 POP3 一样，greeting 是单行且长度不可预知（`<server info>` 常含服务器名与版本），
//! 未见 `\n` 时返回 `NeedMoreData(1)` 逐字节推进，超过 `MAXIMUM_DATA_LEN` 则直接排除。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从服务端 greeting 识别 NNTP：校验 `20` + `0`/`1` 状态码与行尾 CRLF。
    ///
    /// 正文 `<server info>` 不做任何校验；候选 `Nntp` 与 `Nnsp` 共用本函数。
    pub(crate) fn check_nntp_server_greeting(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least 20X <M>\r\n
        // 5 是可读的完整最短形态："20x" 三位状态码 + 分隔符 + 行尾 '\n'。
        // 既要保证 data[0..3] 的三位状态码齐全，也要保证末尾的 [len-1] 与 [len-2]
        // 两个下标可访问，否则无法判断这一行是否已经读完。
        const MINIMUM_DATA_LEN: usize = 5;
        // greeting 单行；缓冲超过此长度仍未结束则判定不是 NNTP（本模块内硬编码）
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

        // 状态码首位必须是 '2'（2xx 表示连接期的服务就绪）
        if data[0] != b'2' {
            // 0x32
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 首字符是数字，与这些协议 greeting 的固定首字符互斥
        self.exclude_other(MaybeProtocol::Ssh);
        // 注意：这里连本候选自身（以及同形的 Nnsp）也标记为排除。
        // 一次性判定不受影响（下面直接返回结论），但若本轮走到 NeedMoreData 分支，
        // 下一轮分派表会因 excluded 命中而不再重试 NNTP——即当前实现要求
        // greeting 在首轮就被读全才能定论。（仅描述现状，未作修改）
        self.exclude_other(MaybeProtocol::Nntp);
        self.exclude_other(MaybeProtocol::Nnsp);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);

        // 第二位必须是 '0'：NNTP 的连接期就绪码只有 200 / 201
        if data[1] != b'0' {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 确认是 20x 后，SMTP（只认 220 / 554）与 FTP（只认 120 / 220 / 421）
        // 的探测器都不可能命中，一并剔除
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);

        // 第三位取 '0'（允许发帖）或 '1'（只读）；其他 2xx 不作为 greeting
        if !matches!(data[2], b'0' | b'1') {
            self.exclude_current();
            return Ok(None);
        }

        // 与前两个文件同理：`data` 是累积的服务端首包，greeting 只有一行，
        // 所以缓冲末尾不是 '\n' 就说明首行还没读全
        if data[data_len - 1] != b'\n' {
            return Err(ProtocolInspectError::NeedMoreData(1));
        }
        if data[data_len - 2] != b'\r' {
            // 裸 LF 结尾不是 NNTP 的 CRLF 行结束
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Nntp))
    }
}
