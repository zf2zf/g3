/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RTSP 请求识别。
//!
//! RTSP 的请求行语法照抄 HTTP（`方法 请求URI 版本`），所以它天然“形似 HTTP”，
//! 区分点只有两处：
//!
//! ```text
//! SETUP rtsp://host/path RTSP/1.0\r\n
//!       ^^^^^^^^^^^^^^^^  ^^^^^^^^^
//!       URI 的 scheme     版本标识是 RTSP/N.0，不是 HTTP/N.0
//! ```
//!
//! - 方法名：本探测器只认 `SETUP`（首字节 'S'）。
//! - URI scheme：`rtsp://` 是 HTTP 请求行里不会出现的绝对形式。
//!
//! 难点正是与 SSH / STOMP 抢 'S' 这个首字节：SSH 版本协商以 `SSH-` 开头、
//! STOMP 的 `STOMP` 命令也以 'S' 开头，所以只凭首字节不能排除它们，
//! 必须等 `SETUP rtsp://` 整串前缀核对成功后再剔除（HTTP 也留到同一时刻排除）。
//! 反过来，二进制协议的第一个字节都不是 'S'（TLS 0x16、MQTT 0x10、SMPP 0、
//! RTMP 0x03、BitTorrent 0x13、LDAP 0x30），在首字节这一步就能整体排除。
//!
//! 判定只看请求行的前缀，不校验版本字段与行尾，详见函数内注释。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

impl ProtocolInspectState {
    /// 从客户端首包识别 RTSP，确认返回 [`Protocol::Rtsp`]。
    ///
    /// 分两段排除：先用首字节 'S' 剔除二进制协议的候选，
    /// 再用 `SETUP rtsp://` 前缀剔除同为文本协议的 Ssh / Http / Stomp。
    pub(crate) fn check_rtsp_client_setup_request(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /// 最短合法请求行 `SETUP rtsp://<x> RTSP/<N>.0\r\n` 的长度：
        /// 13 字节前缀 + 1 字节资源名 + " RTSP/" + 版本 "1.0" + CRLF。
        // at least SETUP rtsp://<x> RTSP/<N>.0\r\n
        const MINIMUM_DATA_LEN: usize = 25;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        if data[0] != b'S' {
            // 0x53
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 只排除首字节不可能是 'S' 的那批二进制协议。
        // Ssh（`SSH-`）、Stomp（`STOMP` 命令）与 Http（`SEARCH` / `SOURCE` /
        // `SUBSCRIBE` 等方法）同样以 'S' 开头，必须留到下面的前缀判定后才能区分，
        // 因此 Http 也被推迟到同一时刻排除
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        // 方法名 + URI scheme 一起核对：HTTP 请求行不会出现 "rtsp://"，
        // SSH / STOMP 也不会出现 "SETUP rtsp://"
        if !data.starts_with(b"SETUP rtsp://") {
            self.exclude_current();
            return Ok(None);
        }

        // 前缀已确定是 RTSP 请求行，同为文本协议的三个候选可以剔除了
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Stomp);

        // seems there's no need to do more check
        // 现状：不再校验 " RTSP/<N>.0" 版本字段与行尾 CRLF——上面要求的 25 字节
        // 只保证请求行骨架存在，能凑出 `SETUP rtsp://` 前缀的数据撞车概率已足够低

        Ok(Some(Protocol::Rtsp))
    }
}
