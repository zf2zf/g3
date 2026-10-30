/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RTMP over TCP 握手起始字节识别。
//!
//! 客户端握手的第一段 C0 只有 1 个字节，内容就是协议版本号：
//!
//! ```text
//! byte 0    byte 1..5      byte 5..9            byte 9..1537
//! +------+--------------+----------------+---------------------+
//! | C0   | C1 time(4)   | C1 zero(4)     | C1 random(1528)     |
//! | 0x03 |              | 必须为 0        | 任意                |
//! +------+--------------+----------------+---------------------+
//! ```
//!
//! 难点在于 C1 剩下的 1528 字节随机数无法校验，靠“版本号 0x03 + 4 字节零填充”
//! 两条硬特征加上必须读满整段 C0+C1（1537 字节）才下结论来压制误判。
//! 紧随 C0 的那 4 个字节（按 C1 布局是时间戳）取值随发起方而变，代码不做检查。
//!
//! 本探测只覆盖裸跑 TCP 的 RTMP，结果为 [`Protocol::RtmpOverTcp`]；
//! 封装在 HTTP 里的形态（`Protocol::RtmpOverHttp`）不在本文件的判定范围内。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从客户端首包识别 RTMP 握手，确认返回 [`Protocol::RtmpOverTcp`]。
    ///
    /// 三步：C0 版本号必须是 0x03 → C1 的 zero 字段（byte 5..9）必须是全 0 →
    /// 数据已读满 C0 + C1 全长。
    pub(crate) fn check_rtmp_tcp_client_handshake(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// C0 的版本号，本探测器只接受 3。
        const RTMP_VERSION: u8 = 3;
        /// C0 段长度：仅一个版本字节。
        const RTMP_HANDSHAKE_C0_LEN: usize = 1;
        /// C1 段长度：time(4) + zero(4) + random(1528)。
        const RTMP_HANDSHAKE_C1_LEN: usize = 1536;
        /// 做上述两项校验所需的最小字节数（C0 + time + zero）。
        const RTMP_HANDSHAKE_MINIMAL_LEN: usize = 9;
        /// 定论所需的完整前缀长度：C0 + C1。
        const RTMP_HANDSHAKE_LEN: usize = RTMP_HANDSHAKE_C0_LEN + RTMP_HANDSHAKE_C1_LEN;

        let data_len = data.len();
        if data_len < RTMP_HANDSHAKE_MINIMAL_LEN {
            // 连 C0 + time + zero 都没读全；这里直接按整段 C0+C1 的长度回报缺口，
            // 因为无论如何最终都要读满 1537 字节才肯下结论
            return Err(ProtocolInspectError::NeedMoreData(
                RTMP_HANDSHAKE_LEN - data_len,
            ));
        }

        if data[0] != RTMP_VERSION {
            // 0x03
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 首字节 0x03 与这批协议的特征都不相符：TLS 记录是 0x16、SSH 是 'S'、
        // HTTP 是方法名的 ASCII 字母、RTSP 只认 'S' 开头的方法、MQTT 是 0x10、
        // STOMP 是 'C'/'S'、SMPP 首字节恒为 0、BitTorrent 是 0x13、
        // LDAP 是 BER SEQUENCE 0x30。
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // byte 1..5 未被检查（按 C1 布局是时间戳字段，随发起方变化）；
        // byte 5..9 按布局应为全 0 的填充字段，是这里最有力的静态特征
        if &data[5..9] != b"\x00\x00\x00\x00" {
            self.exclude_current();
            return Ok(None);
        }

        // 特征都对上了，但还要等 C1 的 1528 字节随机数读满才定论
        if data_len < RTMP_HANDSHAKE_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                RTMP_HANDSHAKE_LEN - data_len,
            ));
        }

        Ok(Some(Protocol::RtmpOverTcp))
    }
}
