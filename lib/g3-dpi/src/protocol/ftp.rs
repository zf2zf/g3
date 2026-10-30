/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP 控制连接的服务端 greeting 识别。
//!
//! FTP 是服务端先发言的文本协议：连接建立后服务器立刻回送一行
//! `xyz <文本>\n` 形式的状态码响应（RFC 959）。识别依据就是这个三位数字状态码，
//! 常见取值：
//! - `120 ` 服务即将就绪
//! - `220 ` 服务就绪（新的连接）——也是最典型的 greeting
//! - `421 ` 服务不可用、关闭控制连接
//!
//! 难点在于 FTP 与 SMTP / ODMR 共用状态码语义：SMTP 的 greeting 同样是 `220 `，
//! 因此本探测器只在候选已被上层（端口表 / 猜测表）指向 FTP 时才下结论，
//! 对与 SMTP 重叠的 `220` 分支不抢先排除 SMTP，交由其他候选并行判定。
//! 数字开头（`1`/`2`/`4`）与 SSH(`S`)、NATS(`I`)、BitTorrent(`0x13`) 等首字节互斥，
//! 可据此快速排除。greeting 文本长度不固定，用 `size_limit.ftp_server_greeting_msg` 设上限。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};
use crate::ProtocolInspectionSizeLimit;

impl ProtocolInspectState {
    /// 从服务端首包识别 FTP greeting：按状态码首数字分派，命中已知码后
    /// 交给 `check_ftp_after_code` 确认整行结构。
    pub(crate) fn check_ftp_server_greeting(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least XYZ <M>\n
        // 最短形态 "xyz a\n"：3 位状态码 + 空格 + 至少 1 字符 + 换行
        const MINIMUM_DATA_LEN: usize = 6;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // 只看状态码首数字：'1'/'2'/'4' 各自对应一组 FTP 码，其余首字符直接落空排除
        match data[0] {
            b'1' => {
                // 0x31
                self.ftp_exclude_by_byte0();
                // '1' 开头的码（120）不属于 SMTP/ODMR/NFTP 的 greeting 取值，可安全排除
                self.exclude_other(MaybeProtocol::Smtp);
                self.exclude_other(MaybeProtocol::Odmr);
                self.exclude_other(MaybeProtocol::Nntp);
                self.exclude_other(MaybeProtocol::Nnsp);

                if &data[0..3] == b"120" {
                    return self.check_ftp_after_code(data, size_limit);
                }
            }
            b'2' => {
                // 0x32
                self.ftp_exclude_by_byte0();

                if data[1] != b'2' {
                    // 状态码必须以 "22" 开头（220/221/226/230...），第二位非 '2' 即否定
                    self.exclude_current();
                    return Ok(None);
                }
                // 注意：不排除 Smtp/Odmr——"220 " 与 SMTP greeting 完全重叠
                // 而 NNTP 的 greeting 固定为 "200"/"201"，第二位是 '0' 而非 '2'，
                // 走到这里已确认 data[1] == '2'，故可安全排除 NNTP/NNSP
                self.exclude_other(MaybeProtocol::Nntp);
                self.exclude_other(MaybeProtocol::Nnsp);

                if data[2] == b'0' {
                    // may be SMTP
                    // "220" 既是 FTP 也是 SMTP 的就绪码，此处仍按 FTP 结构继续校验
                    return self.check_ftp_after_code(data, size_limit);
                }
            }
            b'4' => {
                // 0x34
                self.ftp_exclude_by_byte0();
                self.exclude_other(MaybeProtocol::Smtp);
                self.exclude_other(MaybeProtocol::Odmr);
                self.exclude_other(MaybeProtocol::Nntp);
                self.exclude_other(MaybeProtocol::Nnsp);

                if &data[0..3] == b"421" {
                    return self.check_ftp_after_code(data, size_limit);
                }
            }
            _ => {}
        }

        self.exclude_current();
        Ok(None)
    }

    /// 确认状态码首数字后，排除所有 greeting 不以数字 `1`/`2`/`4` 开头的候选：
    /// SSH（`S`）、POP3（`+`）、IMAP（`*`）、NATS（`I`）、BitTorrent（`0x13`）。
    /// 这里不排除 SMTP/ODMR/NNTP，因为它们的首状态码数字与此重叠。
    fn ftp_exclude_by_byte0(&mut self) {
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);
    }

    /// 状态码三位数字之后的结构校验。
    ///
    /// `data[3]` 必须是空格（单行响应）或 `-`（多行响应的分隔符）；随后在剩余字节
    /// 中查找行尾 `\n`：找到即确认为 [`Protocol::FtpControl`]；找不到时，若已超出
    /// `size_limit.ftp_server_greeting_msg` 判定非法，否则要求继续读数据。
    fn check_ftp_after_code(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // 状态码后紧跟空格（单行）或 '-'（多行首行）
        if !matches!(data[3], b' ' | b'-') {
            self.exclude_current();
            return Ok(None);
        }

        let left = &data[4..];
        match memchr::memchr(b'\n', left) {
            Some(_) => Ok(Some(Protocol::FtpControl)),
            None => {
                // 未见行尾换行：文本超过上限长度即否定，否则再读一点
                if left.len() > size_limit.ftp_server_greeting_msg {
                    self.exclude_current();
                    Ok(None)
                } else {
                    Err(ProtocolInspectError::NeedMoreData(1))
                }
            }
        }
    }
}
