/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! SMPP PDU 定长头识别。
//!
//! SMPP 是运营商短信网关（ESME ↔ MC）之间的二进制协议，所有 PDU 共用同一个
//! 16 字节定长头，字段全部是大端 32 位：
//!
//! ```text
//! byte 0..4      byte 4..8      byte 8..12        byte 12..16
//! +------------+------------+---------------+---------------+
//! |command_len | command_id | command_status| sequence_num  |
//! +------------+------------+---------------+---------------+
//! ```
//!
//! 判定思路是“长度 + 命令号 + 状态”三重交叉验证：单看 command_id 很容易撞上
//! 随机数据，但再要求 command_len 自洽（不小于 16，且去掉定长头后的 body 落在
//! 该命令允许的区间内）、command_status 为 0（请求侧该字段恒为 0），
//! 误判率就极低。
//!
//! 难点在于**没有任何字符串特征**可锚定，只能靠数值区间筛，因此命令号只放行
//! 建会话用的四个 bind / outbind 请求，每个各配一组 body 长度区间。
//! sequence_number 不参与判定（取值随连接变化，没有区分度）。
//!
//! 本函数只在客户端方向被调用（服务端方向的候选 SMPP 在分派表里被直接排除），
//! 因此要求 command_status 为 0——非 0 的 PDU 就按“不是会话建立请求”排除。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

/// `bind_transmitter` 的 command_id：发送方 ESME 登录移动消息中心。
const SMPP_BIND_TRANSMITTER: u32 = 0x00000002;
/// `bind_receiver` 的 command_id：接收方 ESME 登录移动消息中心。
const SMPP_BIND_RECEIVER: u32 = 0x00000001;
/// `bind_transceiver` 的 command_id：同一连接既可发也可收。
const SMPP_BIND_TRANSCEIVER: u32 = 0x00000009;
/// `outbind` 的 command_id：由消息中心反向通知接收端启动。
const SMPP_OUTBIND: u32 = 0x0000000B;

/// bind 类 PDU 去掉 16 字节定长头后，body 长度的下限。
const SMPP_BIND_MIN_BODY: usize = 7;
/// bind 类 PDU body 长度的上限，由若干定长字段的长度上限累加而得。
/// 累加项与具体协议字段（system_id、password、system_type 等登录参数）的
/// 对应关系代码未标注，本函数不逐字段解析，只按区间粗筛。
const SMPP_BIND_MAX_BODY: usize = 16 + 9 + 13 + 1 + 1 + 1 + 41;
/// outbind PDU body 长度的下限。
const SMPP_OUTBIND_MIN_BODY: usize = 2;
/// outbind PDU body 长度的上限（16 + 9 两段字段）。
const SMPP_OUTBIND_MAX_BODY: usize = 16 + 9;

impl ProtocolInspectState {
    /// 从客户端首包识别 SMPP，确认返回 [`Protocol::Smpp`]。
    ///
    /// 只解析定长头的前 12 字节（command_len / command_id / command_status），
    /// 三者都通过合法性校验才下结论。
    pub(crate) fn check_smpp_session_request(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// SMPP 所有 PDU 共用的定长头长度。
        const SMPP_SESSION_REQUEST_HEADER_LEN: usize = 16;

        let data_len = data.len();
        if data_len < SMPP_SESSION_REQUEST_HEADER_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                SMPP_SESSION_REQUEST_HEADER_LEN - data_len,
            ));
        }

        // command_len 是 4 字节大端；bind / outbind 请求整体只有几十到一百多字节，
        // 远小于 2^24，所以最高字节必然为 0。非 0 直接否掉——这一条就能筛掉
        // 绝大多数随机数据，代价也最低。
        if data[0] != 0x00 {
            // the request is too small so the first byte should always be 0
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 首字节 0x00 与这批协议的特征首字节都不重合：TLS 记录是 0x16、
        // SSH 是 'S'、HTTP 是方法名的 ASCII 字母、RTSP 只认 'S' 开头的方法、
        // STOMP 是 'C'/'S'、MQTT 是 0x10、RTMP 是 0x03、BitTorrent 是 0x13、
        // LDAP 是 BER SEQUENCE 0x30。
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // byte 0..4：命令总长度，包含这 16 字节定长头本身
        let cmd_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if cmd_len < SMPP_SESSION_REQUEST_HEADER_LEN {
            self.exclude_current();
            return Ok(None);
        }

        // byte 4..8：命令号。只接受建会话用的四个请求命令，且都是明文请求的取值；
        // 命中其他命令号（例如各种消息类 PDU）说明这不像会话建立的第一个包。
        let cmd_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let (min_body, max_body) = match cmd_id {
            SMPP_BIND_TRANSMITTER | SMPP_BIND_RECEIVER | SMPP_BIND_TRANSCEIVER => {
                // ESME to MC
                (SMPP_BIND_MIN_BODY, SMPP_BIND_MAX_BODY)
            }
            SMPP_OUTBIND => {
                // MC to ESME
                (SMPP_OUTBIND_MIN_BODY, SMPP_OUTBIND_MAX_BODY)
            }
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        // 用长度自洽性再卡一遍：body = 总长 - 定长头，必须落在该命令的区间内
        let body_len = cmd_len - SMPP_SESSION_REQUEST_HEADER_LEN;
        if body_len < min_body || body_len > max_body {
            self.exclude_current();
            return Ok(None);
        }

        // byte 8..12：命令状态字段。客户端刚发起会话建立时它应为 0，非 0 即排除
        let cmd_status = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        if cmd_status != 0 {
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Smpp))
    }
}
