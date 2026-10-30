/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! STOMP CONNECT 帧识别。
//!
//! STOMP 是纯文本协议，帧以命令行开头，与 HTTP 请求行长得非常像，
//! 因此本文件的重点全在“与 HTTP 抢候选”：
//!
//! ```text
//! CONNECT\n\n\0                          <- 1.0/1.1 风格，命令后紧跟空行与结束符
//! CONNECT\r\n\r\n\0                      <- 同上，CRLF 换行
//! STOMP\naccept-version:1.2\nhost:x\n\0  <- 1.2 引入的 STOMP 命令，必须带头部
//! ```
//!
//! 判定分两条路，按首字节 `C` / `S` 分流：
//! - `CONNECT` 分支：HTTP 也有 `CONNECT` 方法（用于隧道），二者前 7 字节完全相同。
//!   区分点在第 8 个字节——HTTP 的 `CONNECT` 后面必须是空格 + 请求 URI，
//!   而 STOMP 的命令行到此结束（`\n` 或 `\r\n`）。所以这条路上
//!   **先不排除 Http**，等换行符确认后再把它剔除。
//! - `STOMP` 分支：HTTP / RTSP 都没有名为 STOMP 的方法，一旦整行命令核对成功
//!   就立即排除它们。
//!
//! 与 SSH 的歧义也落在 `S` 分支上：`SSH-2.0-...` 同样以 `S` 开头，
//! 一旦第 2..5 字节不是 `TOMP`，本探测器就用 `exclude_current` 放弃 STOMP 候选。
//! 需要注意的是本分支在核对 `TOMP` **之前**就已把 Ssh 标记为不可能，
//! 详见 `check_stomp_stomp_method` 内的说明。
//!
//! 这里只看到“命令行 + 换行”就下结论，帧尾的 `\0` 与各头部内容并不校验
//! （见函数内 TODO），因为能凑出 `CONNECT\n\n` / `STOMP\n<头部>` 的随机数据极少。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 客户端方向 STOMP 入口：按首字节把候选帧分流到 CONNECT 或 STOMP 命令。
    ///
    /// 返回 [`Protocol::Stomp`] 的两条路径分别见
    /// [`ProtocolInspectState::check_stomp_connect_method`] 与
    /// [`ProtocolInspectState::check_stomp_stomp_method`]。
    pub(crate) fn check_stomp_client_connect_request(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 最短合法帧的长度，对应下面两种形态里较紧凑的一种。
        // at least "CONNECT\n\n\0" or "STOMP\naccept-version:1.2\nhost:<xxx>\n\0"
        const MINIMUM_DATA_LEN: usize = 10;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // 只在首字节层面粗分流，真正的判定在子函数里做——
        // 这样两个分支各自决定“什么时候可以放心排除 Http”。
        match data[0] {
            // 0x43
            b'C' => self.check_stomp_connect_method(data),
            // 0x53
            b'S' => self.check_stomp_stomp_method(data),
            _ => {
                self.exclude_current();
                Ok(None)
            }
        }
    }

    /// 检查 1.0/1.1 风格的 `CONNECT` 命令帧。
    ///
    /// `data` 已保证长度不小于 10。offset 7 处必须是换行，这既是 STOMP 的
    /// 命令行结束标志，也是与 HTTP `CONNECT` 方法的分水岭。
    fn check_stomp_connect_method(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 命令行之后至少还要容纳“空行 + 帧结束符”两个字节。
        // at least "CONNECT\n\n\0"
        const MINIMUM_LEN_AFTER_METHOD: usize = 2;

        // exclude impossible protocols
        // 首字节 'C' 与这批协议的首字节集合互斥：TLS 记录是 0x16、MQTT 是 0x10、
        // SMPP 恒为 0、RTMP 是 0x03、BitTorrent 是 0x13、LDAP 是 BER SEQUENCE 0x30；
        // SSH 以 "SSH-" 开头，RTSP 在本 crate 的探测器里只认 'S' 开头的方法。
        // 列表里独缺 Http，因为 HTTP 请求方法恰好也有 CONNECT。
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // data[0] 已是 'C'，这里核对剩下的 "ONNECT" 六个字节
        if &data[1..7] != b"ONNECT" {
            self.exclude_current();
            return Ok(None);
        }

        // 命令名之后的第一个字节决定成败：
        // ' '（HTTP 的 CONNECT 后跟 URI）会落到 `_` 分支被排除掉
        let offset: usize = match data[7] {
            b'\r' => {
                // CRLF 才算合法行尾；单独一个 \r 不是 STOMP 换行。
                // 能走到这里说明命令行就是 "CONNECT" 加换行，不是 HTTP 请求行。
                self.exclude_other(MaybeProtocol::Http);
                if data[8] != b'\n' {
                    self.exclude_current();
                    return Ok(None);
                }
                9
            }
            b'\n' => {
                self.exclude_other(MaybeProtocol::Http);
                8
            }
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        // offset 是命令行末尾之后的位置，再要求 MINIMUM_LEN_AFTER_METHOD 字节
        let data_len = data.len();
        if offset + MINIMUM_LEN_AFTER_METHOD > data_len {
            return Err(ProtocolInspectError::NeedMoreData(
                offset + MINIMUM_LEN_AFTER_METHOD - data_len,
            ));
        }

        // TODO check header and ending '\0'

        Ok(Some(Protocol::Stomp))
    }

    /// 检查 1.2 引入的 `STOMP` 命令帧。
    ///
    /// 该命令必须携带 `accept-version` / `host` 等头部，所以长度下限比
    /// CONNECT 分支大得多；头部本身不做逐项校验。
    fn check_stomp_stomp_method(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 命令行之后的最小字节数，用于容纳至少一个带值的头部行。
        /// 取值依据是下面这条注释给出的示例帧，代码不解析头部内容。
        // at least "STOMP\naccept-version:1.2\nhost:<xxx>\n\0"
        const MINIMUM_LEN_AFTER_METHOD: usize = 26;

        // exclude impossible protocols
        // 这些协议的首字节都不是 'S'（TLS 0x16、MQTT 0x10、SMPP 0、RTMP 0x03、
        // BitTorrent 0x13、LDAP 0x30）。
        // 列表里独缺 Http / Rtsp：RTSP 的 SETUP 方法同样以 'S' 开头，
        // HTTP 一侧也留到命令名核对之后再与 Rtsp 一起剔除（见下面两行）。
        //
        // 但 Ssh 是在**尚未核对 "TOMP" 之前**就被排除的：`SSH-...` 同样以 'S' 开头，
        // 所以若某条连接的候选集合同时含 Ssh 与 Stomp（例如端口表把两者都登记在同一端口），
        // 而首包是尚未读全的 `SSH-2.0-...`，走到本分支会把 SSH 候选一并标为不可能，
        // 之后即使数据读全也无法再判为 SSH。此处仅记录该时序，未作修改。
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // data[0] 已是 'S'，核对 "TOMP"；`SSH-2.0-...` 在这一行就会被排除
        if &data[1..5] != b"TOMP" {
            self.exclude_current();
            return Ok(None);
        }
        // 命令名确定是 STOMP：HTTP 与 RTSP 都没有这个方法名，可以剔除了
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Rtsp);

        // 同 CONNECT 分支：命令行必须以 \n 或 \r\n 结束
        let offset: usize = match data[5] {
            b'\r' => {
                if data[6] != b'\n' {
                    self.exclude_current();
                    return Ok(None);
                }
                7
            }
            b'\n' => 6,
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        // offset + 26 只是长度粗校验，不足则继续等数据
        let data_len = data.len();
        if offset + MINIMUM_LEN_AFTER_METHOD > data_len {
            return Err(ProtocolInspectError::NeedMoreData(
                offset + MINIMUM_LEN_AFTER_METHOD - data_len,
            ));
        }

        // TODO check header and ending '\0'

        Ok(Some(Protocol::Stomp))
    }
}
