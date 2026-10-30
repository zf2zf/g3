/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! SSH 版本协商字符串识别。
//!
//! SSH 连接建立后双方各自发送一行版本协商串，形如：
//!
//! ```text
//! SSH-<major>.<minor>-<software version>\r\n
//! ```
//!
//! 判定依据只有这个 ASCII 前缀 `SSH-` 与其后的版本号，无需解析任何二进制报文。
//! 版本号决定返回 [`Protocol::Ssh`] 还是 [`Protocol::SshLegacy`]：
//! - `2.0` -> 现代 SSH（`Protocol::Ssh`）。主版本 2 只认 `2.0`，`2.1` 等一律不认。
//! - `1.99` -> 协议 2.0 的兼容标识，按 `Protocol::Ssh` 处理。
//! - 其余全部 `1.x`（`1.0`~`1.8`，以及 `1.90`~`1.98`）-> 旧版 `Protocol::SshLegacy`。
//!
//! 难点：版本行以 `\n` 结尾但长度不固定（软件版本段可变），所以要在末尾寻找换行；
//! 换行未出现前只能不断要求补数据。首个字节 `'S'`(0x53) 与 HTTP 的 `SEARCH`/`SOURCE`、
//! RTSP 的 `SETUP` 重叠，故只在与本方候选冲突时才排除。
//!
//! 客户端方向与服务端方向逻辑一致，仅区别在于：服务端方向 `data[0..4]` 直接是 `SSH-`，
//! 而客户端方向首字节必须先为 `'S'` 才继续（并借此排除更多以其他字节开头的协议）。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从客户端首包识别 SSH 版本协商串。
    ///
    /// 首字节必须为 `'S'`(0x53)，随后校验 `SSH-` 与版本号，最后确认行尾换行。
    /// 确认 `SSH-` 后即排除所有非 `S` 开头的协议（TLS/MQTT/…），
    /// 并额外排除 HTTP 与 RTSP（它们的候选方法串不会与 `SSH-x.y-` 完全一致）。
    pub(crate) fn check_ssh_client_protocol_version_exchange(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least SSH-<x>.<y>-<z>\r\n
        // 最短合法版本串 "SSH-x.y-z\r\n" 的长度
        const MINIMUM_DATA_LEN: usize = 11;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        if data[0] != b'S' {
            // 0x53
            // 首字节不是 'S' 就绝不可能是 SSH，直接排除当前候选
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 已确定以 'S' 开头：下列协议的首字节取值域均不含 'S'，一次性剔除
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        if &data[1..4] != b"SH-" {
            // 'S' 之后必须是 "SH-"，拼起来即 "SSH-"
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 确认了 "SSH-" 前缀：HTTP 请求行与 RTSP 请求行都不以此开头，排除二者
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Rtsp);

        // check ssh version
        // data[4..6] 为主版本+点号（"1." 或 "2."），data[6] 为次版本号首字符。
        // offset 指向版本串中主/次版本号之后应出现的 '-' 分隔符位置：
        // 常规为 7（"SSH-x.y"），但当次版本为 "1.99" 时版本段多占一字节，offset 顺延到 8。
        let mut offset = 7;
        let protocol = match &data[4..6] {
            b"1." => match data[6] {
                b'9' => {
                    if data[7] == b'9' {
                        // "SSH-1.99-"：兼容标识，按协议 2.0 处理，'-' 落在 offset=8
                        offset = 8;
                        Protocol::Ssh
                    } else {
                        // "1.9x"（x≠9）视为旧版
                        Protocol::SshLegacy
                    }
                }
                b'0'..=b'8' => Protocol::SshLegacy,
                _ => {
                    self.exclude_current();
                    return Ok(None);
                }
            },
            b"2." => {
                if data[6] != b'0' {
                    // 主版本 2 目前只定义 "2.0"，其余（如 2.1）不作为已知 SSH
                    self.exclude_current();
                    return Ok(None);
                }
                Protocol::Ssh
            }
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        // 版本号段之后必须紧跟 '-'，再接软件版本串
        if data[offset] != b'-' {
            self.exclude_current();
            return Ok(None);
        }

        // check trailing
        // 版本行必须以 '\n' 结尾；未到行尾且长度仍小于单行上限(255)时，要求继续读
        if data[data_len - 1] != b'\n' {
            return if data_len < 255 {
                Err(ProtocolInspectError::NeedMoreData(1))
            } else {
                self.exclude_current();
                Ok(None)
            };
        }
        if data[7] != b'9' {
            // no '\r' for SSH-1.99-
            // 常规版本行以 "\r\n" 结尾需校验 '\r'；
            // 而 "SSH-1.99-" 形态（data[7]=='9'）按约定不要求 '\r'，跳过该检查
            if data[data_len - 2] != b'\r' {
                self.exclude_current();
                return Ok(None);
            }
        }

        Ok(Some(protocol))
    }

    /// 从服务端 greeting 识别 SSH 版本协商串。
    ///
    /// 与客户端方向的算法完全相同，区别只在入口：服务端首包直接从 `data[0..4]`
    /// 比对 `SSH-`（无需先判 'S' 首字节），并据此排除以其他字节开头的一批文本协议
    /// （FTP/SMTP/POP3 等 greeting 均以数字或别的字母开头）。
    pub(crate) fn check_ssh_server_protocol_version_exchange(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least SSH-<x>.<y>-<z>\r\n or SSH-1.99-<z>\n
        const MINIMUM_DATA_LEN: usize = 11;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        if &data[0..4] != b"SSH-" {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 确认 "SSH-" 前缀后，排除所有服务端 greeting 不以 "SSH-" 开头的候选
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Nntp);
        self.exclude_other(MaybeProtocol::Nnsp);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::BitTorrent);

        // check ssh version
        // 与客户端方向同样的版本判定：offset 指向版本号后的 '-'，"1.99" 时顺延到 8
        let mut offset = 7;
        let protocol = match &data[4..6] {
            b"1." => match data[6] {
                b'9' => {
                    if data[7] == b'9' {
                        offset = 8;
                        Protocol::Ssh
                    } else {
                        Protocol::SshLegacy
                    }
                }
                b'0'..=b'8' => Protocol::SshLegacy,
                _ => {
                    self.exclude_current();
                    return Ok(None);
                }
            },
            b"2." => {
                if data[6] != b'0' {
                    self.exclude_current();
                    return Ok(None);
                }
                Protocol::Ssh
            }
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        // 版本号段之后必须紧跟 '-'
        if data[offset] != b'-' {
            self.exclude_current();
            return Ok(None);
        }

        // check trailing
        // 行尾 '\n' 未到且未超长时要求补数据；非 "1.99" 形态还需校验 '\r'
        if data[data_len - 1] != b'\n' {
            return if data_len < 255 {
                Err(ProtocolInspectError::NeedMoreData(1))
            } else {
                self.exclude_current();
                Ok(None)
            };
        }
        if data[7] != b'9' {
            // no '\r' for SSH-1.99-
            if data[data_len - 2] != b'\r' {
                self.exclude_current();
                return Ok(None);
            }
        }

        Ok(Some(protocol))
    }
}
