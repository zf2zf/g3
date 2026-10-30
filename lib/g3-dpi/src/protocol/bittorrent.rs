/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! BitTorrent TCP 握手识别。
//!
//! BT 的 TCP 连接建立后，发起方第一个包就是固定文案的握手：
//!
//! ```text
//! byte 0   byte 1..20             byte 20..28   byte 28..48   byte 48..68
//! +------+----------------------+-------------+-------------+-------------+
//! | 0x13 | "BitTorrent protocol"| 保留字段 8B  | info_hash 20B| peer_id 20B |
//! |  =19 |  =19 字节             | 能力标志     |              |             |
//! +------+----------------------+-------------+-------------+-------------+
//! ```
//!
//! 判定依据是“1 字节长度 19 + 紧接着的 19 字节固定字符串”这一对组合：
//! 单独一个 0x13 毫无信息量，单独一段 `BitTorrent protocol` 也可能是巧合，
//! 两者必须同时命中；再加上要求读满整个 68 字节握手，随机数据基本无法冒充。
//!
//! 难点在于这个特征虽然强，但**必须等 68 字节读全**才能定论，要求的读前缀
//! 相当长；为此本函数在字节不足时直接报 `NeedMoreData`，期间不做任何部分匹配。
//!
//! 握手由发起方发出，但本端可能是发起方也可能是接收方，
//! 因此 inspect.rs 的两张分派表在客户端与服务端方向都调用了本函数。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 识别 BitTorrent TCP 握手，确认返回 [`Protocol::BitTorrentOverTcp`]。
    ///
    /// 两个方向共用：客户端首包与服务端首包都可能是这个握手报文。
    pub(crate) fn check_bittorrent_tcp_handshake(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 完整握手的长度：1 + 19 + 8 + 20 + 20 = 68 字节。
        // at least 0x13 BitTorrent <SP> protocol <Extension, 8 bytes> <sha1 hash of info, 20 bytes> <peer id, 20bytes>
        const BT_HANDSHAKE_SIZE: usize = 68;

        let data_len = data.len();
        if data_len < BT_HANDSHAKE_SIZE {
            return Err(ProtocolInspectError::NeedMoreData(
                BT_HANDSHAKE_SIZE - data_len,
            ));
        }

        // byte 0：协议名长度，固定 19（0x13），即后面紧跟的 "BitTorrent protocol" 的字节数
        if data[0] != 0x13 {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 0x13 是控制字符，与这批协议的首字节特征都不相符：文本类 greeting 用的
        // 都是可打印 ASCII（FTP / SMTP 以状态码数字开头，POP3 是 '+'，IMAP 是 '*'，
        // NATS 是 "INFO" 的 'I'），二进制协议则分别是 TLS 0x16、MQTT 0x10、
        // RTMP 0x03、SMPP 恒为 0、LDAP 0x30，以及 SSH / RTSP / STOMP 的 'S' 与 'C'。
        self.exclude_other(MaybeProtocol::Ftp);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Smtp);
        self.exclude_other(MaybeProtocol::Odmr);
        self.exclude_other(MaybeProtocol::Pop3);
        self.exclude_other(MaybeProtocol::Imap);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::Nats);
        self.exclude_other(MaybeProtocol::Ldap);

        // byte 1 起必须是 19 字节的固定协议名；用 data[1..] 前缀匹配，
        // 长度已由上面的 68 字节检查保证，不会越界
        if data[1..].starts_with(b"BitTorrent protocol") {
            Ok(Some(Protocol::BitTorrentOverTcp))
        } else {
            self.exclude_current();
            Ok(None)
        }
    }
}
