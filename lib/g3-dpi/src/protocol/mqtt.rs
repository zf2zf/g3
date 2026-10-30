/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! MQTT CONNECT 报文识别。
//!
//! MQTT 是二进制协议，首包（客户端方向）固定是 CONNECT 报文，判定依据集中在
//! 报文最前面的固定头 + 可变头：
//!
//! ```text
//! byte 0     byte 1     byte 2..8            byte 8   byte 9   byte 10..12
//! +------+----------+------------------+-----+------+------+
//! |固定头 |剩余长度   |协议名 0x0004+"MQTT"|版本号|连接标志|keep- |
//! |0x10  |(1 字节)   |(2 字节长度 + 4)  |      |      |alive |
//! +------+----------+------------------+-----+------+------+
//! ```
//!
//! 难点不在解析而在“够不够长就能定论”：CONNECT 的协议名字段位置是固定的，
//! 只要读到 12 字节就能同时校验固定头、协议名与版本号，其后的 ClientID、
//! Will、用户名/密码等载荷字段一概不必解析。
//!
//! 需要注意：代码只把 `data[1]` 当作剩余长度的**全部**（MQTT 的剩余长度是
//! 变长编码，理论上可占多字节），因此本探测器实际只覆盖“剩余长度可用单字节
//! 表示”的 CONNECT 报文；这类小包之后的协议名等字段偏移才正好对上代码里的
//! `data[2..8]`、`data[8]`。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从客户端首包识别 MQTT，确认返回 [`Protocol::Mqtt`]。
    ///
    /// 依次校验：长度足够 → 固定头是 CONNECT(0x10) → 剩余长度自洽 →
    /// 协议名字段是 `\x00\x04MQTT` → 版本号在已知集合内。
    /// 只有固定头一项就足以把首字节互斥的明文协议整体剔除。
    pub(crate) fn check_mqtt_client_connect_request(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 判定所需的最小字节数：固定头(1) + 剩余长度(1) + 协议名(6) +
        /// 版本号(1) + 连接标志(1) + keep-alive(2)。
        // at least FixedHeader, Protocol Name, Protocol Level, Connect Flags, and Keep Alive
        const MINIMUM_DATA_LEN: usize = 12;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // 固定头高 4 位是报文类型，1 == CONNECT；低 4 位是标志位，
        // CONNECT 报文必须为 0，所以整字节严格等于 0x10。
        if data[0] != 0x10 {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 0x10 与下列协议的首字节取值完全不相交：TLS 记录固定 0x16、
        // SSH 是 'S'、HTTP 是方法名 ASCII、RTSP 的探测器只认 'S' 开头的方法、
        // STOMP 是 'C'/'S'、SMPP 首字节恒为 0（命令长度不足 2^24）、
        // RTMP 是 0x03、BitTorrent 是 0x13、LDAP 是 BER SEQUENCE 0x30。
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // data[1] 是剩余长度，即可变头 + 载荷的字节数。
        // 报文总长 = 固定头 2 字节 + 剩余长度，必须容得下上面 12 字节的骨架，
        // 否则报文自相矛盾（随机数据常见形态）。
        let remaining_len = data[1] as usize;
        if remaining_len + 2 < MINIMUM_DATA_LEN {
            self.exclude_current();
            return Ok(None);
        }

        // 可变头开头是协议名：2 字节大端长度 0x0004 紧跟 "MQTT"
        if &data[2..8] != b"\x00\x04MQTT" {
            self.exclude_current();
            return Ok(None);
        }

        // 协议版本字节：代码只放行 0x04 与 0x05 这两个版本号取值，
        // 其余一律不认，避免让随机数据撞中协议名字段之后的这一字节
        let protocol_level = data[8];
        match protocol_level {
            0x04 => {}
            0x05 => {}
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        }

        Ok(Some(Protocol::Mqtt))
    }
}
