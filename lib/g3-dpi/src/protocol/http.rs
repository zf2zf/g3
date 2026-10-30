/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP 请求行与连接前缀识别。
//!
//! 客户端先发言，判定依据是请求行的固定形态：
//!
//! ```text
//! <METHOD> SP <uri> SP HTTP/<x>.<y> CRLF
//! ```
//!
//! 分两步收敛：先按首字节（大写 ASCII 字母）把候选方法定位到具体字符串，
//! 再依次校验 URI 段与版本段 `HTTP/1.x`。HTTP/1.0 与 1.1 在识别阶段共用
//! [`Protocol::Http1`]；明文 HTTP/2（h2c）另有独立的 24 字节连接前缀。
//!
//! 难点有二：
//! 1. 方法集很大（标准方法 + WebDAV / Delta-V / Icecast 扩展），且首字节
//!    `S` 与 SSH（`SSH-`）、RTSP（`SETUP` 等）重叠，`C` 下也有多个候选，
//!    因此这些同族文本协议要等方法真正匹配成功后才排除，不能过早剔除。
//! 2. URI 长度不固定，需靠 `size_limit.http_client_request_uri` 设上限，
//!    避免因超长/无空格的数据而无限等待。
//!
//! 排除策略主要利用首字节互斥：方法首字母是 `A..=V`，而 TLS 记录恒为 `0x16`、
//! MQTT 恒为 `0x10`/`0x20`、BitTorrent 恒为 `0x13` 等，确认方法后一次性剔除。

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};
use crate::ProtocolInspectionSizeLimit;

impl ProtocolInspectState {
    /// 从客户端首包识别 HTTP：按首字节定位方法串，命中后交给
    /// `check_http1_after_method` 校验 URI 与版本段；`PRI ` 分支转
    /// `check_http2_connection_preface`。
    ///
    /// 返回 `Ok(Some(_))` 表示已确认版本；`Ok(None)` 表示不是 HTTP（已排除当前候选）；
    /// `Err(NeedMoreData)` 表示看着像但字节不足。
    pub(crate) fn check_http_request(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // 匹配某个方法前缀：命中即用方法串长度（含结尾空格）作为 URI 起始偏移
        macro_rules! check_method {
            ($m:literal) => {
                if data.starts_with($m) {
                    return self.check_http1_after_method(data, $m.len(), size_limit);
                }
            };
        }

        // at least <XYZ> <X> HTTP/<X>.<Y>\r\n\r\n
        // 最短请求行的粗略下限，未读满前先要求补数据
        const MINIMUM_DATA_LEN: usize = 18;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // 按首字节分派：每个大写首字母对应一组方法名。进入分支即说明首字节落在
        // 方法名取值域内，先执行 http_exclude_by_byte0(_s) 排除互斥候选。
        match data[0] {
            b'A' => {
                // 0x41
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"ACL ");
            }
            b'B' => {
                // 0x42
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"BIND ");
                check_method!(b"BASELINE-CONTROL ");
            }
            b'C' => {
                // 0x43
                // 注意 'C' 分支与 STOMP 的 CONNECT 冲突：此处先不整体排除 Stomp，
                // 只有确认了具体方法串（如 "CONNECT "）才排除它
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();

                if data.starts_with(b"CONNECT ") {
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 8, size_limit);
                }
                // COPY / CHECKIN / CHECKOUT 为 WebDAV 扩展方法
                if data.starts_with(b"COPY ") {
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 5, size_limit);
                }
                if data.starts_with(b"CHECKIN ") {
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 8, size_limit);
                }
                if data.starts_with(b"CHECKOUT ") {
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 9, size_limit);
                }
            }
            b'D' => {
                // 0x44
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"DELETE ");
            }
            b'G' => {
                // 0x47
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"GET ");
            }
            b'H' => {
                // 0x48
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"HEAD ");
            }
            b'L' => {
                // 0x4C
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"LOCK ");
                check_method!(b"LINK ");
                check_method!(b"LABEL ");
            }
            b'M' => {
                // 0x4D
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"MOVE ");
                check_method!(b"MKCOL ");
                check_method!(b"MERGE ");
                check_method!(b"MKACTIVITY ");
                check_method!(b"MKCALENDAR ");
                check_method!(b"MKREDIRECTREF ");
                check_method!(b"MKWORKSPACE ");
            }
            b'O' => {
                // 0x4F
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"OPTIONS ");
                check_method!(b"ORDERPATCH ");
            }
            b'P' => {
                // 0x50
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"POST ");
                check_method!(b"PUT ");
                // "PRI " 不是 HTTP/1.x 方法，而是 h2c 连接前缀 "PRI * HTTP/2.0..." 的开头
                if data.starts_with(b"PRI ") {
                    return self.check_http2_connection_preface(data);
                }
                check_method!(b"PROPFIND ");
                check_method!(b"PROPPATCH ");
                check_method!(b"PATCH ");
            }
            b'R' => {
                // 0x52
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"REPORT ");
                check_method!(b"REBIND ");
            }
            b'S' => {
                // 0x53
                // 'S' 与 SSH("SSH-")、RTSP("SETUP"/"DESCRIBE"...)、STOMP 首字节重叠，
                // 这里只做 http_exclude_by_byte0，待方法串确认后再排除同族文本协议
                self.http_exclude_by_byte0();

                if data.starts_with(b"SEARCH ") {
                    self.exclude_other(MaybeProtocol::Ssh);
                    self.exclude_other(MaybeProtocol::Rtsp);
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 7, size_limit);
                }
                if data.starts_with(b"SOURCE ") {
                    // Icecast, deprecated since 2.4.0
                    self.exclude_other(MaybeProtocol::Ssh);
                    self.exclude_other(MaybeProtocol::Rtsp);
                    self.exclude_other(MaybeProtocol::Stomp);
                    return self.check_http1_after_method(data, 7, size_limit);
                }
            }
            b'T' => {
                // 0x54
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"TRACE ");
            }
            b'U' => {
                // 0x55
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"UNLOCK ");
                check_method!(b"UNBIND ");
                check_method!(b"UNCHECKOUT ");
                check_method!(b"UNLINK ");
                check_method!(b"UPDATE ");
                check_method!(b"UNDATEREDIRECTREF ");
            }
            b'V' => {
                // 0x56
                self.http_exclude_by_byte0();
                self.http_exclude_by_byte0_s();
                self.exclude_other(MaybeProtocol::Stomp);

                check_method!(b"VERSION-CONTROL ");
            }
            _ => {}
        }

        // 首字节虽是大写字母，但没有任何方法串与之匹配：判定不是 HTTP，排除当前候选
        self.exclude_current();
        Ok(None)
    }

    /// 确认为 HTTP 方法首字节（大写 ASCII）后，排除所有首字节不可能是大写字母的候选：
    /// TLS(`0x16`)、MQTT(`0x10`/`0x20`)、SMPP、RTMP、BitTorrent(`0x13`)、LDAP(`0x30`)。
    fn http_exclude_by_byte0(&mut self) {
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);
    }

    /// 再排除 SSH 与 RTSP。仅在首字节确定不是 `'S'` 时调用——
    /// 因为 `SSH-` 与 RTSP 的部分方法同样以 `'S'` 开头，需留给方法匹配阶段甄别。
    fn http_exclude_by_byte0_s(&mut self) {
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Rtsp);
    }

    /// 方法串已匹配后，继续解析请求行的 URI 段。
    ///
    /// `url_offset` 是 URI 的起始偏移（即 `"METHOD "` 之后的位置，含结尾空格），
    /// 因此方法串本身位于 `data[0..url_offset-1]`（去掉结尾空格）。
    /// 在 URI 中找到下一个空格即版本段起点；找不到空格时，若 URI 已超过
    /// `size_limit.http_client_request_uri` 就判定非法，否则要求继续读数据。
    fn check_http1_after_method(
        &mut self,
        data: &[u8],
        url_offset: usize,
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least <X> HTTP/<X>.<Y>\r\n\r\n
        // 在方法串之后的部分所需的最短字节数
        const MINIMUM_DATA_LEN: usize = 14;

        let minimum_len = MINIMUM_DATA_LEN + url_offset;
        let data_len = data.len();
        if data_len < minimum_len {
            return Err(ProtocolInspectError::NeedMoreData(minimum_len - data_len));
        }

        let _method = &data[0..url_offset - 1];
        let left = &data[url_offset..];
        if let Some(p) = memchr::memchr(b' ', left) {
            // FIXME validate url?
            // url_offset + p 是 URI 结尾空格的位置，+1 跳到版本段 "HTTP/1.x" 的起点
            self.check_http1_after_url(data, url_offset + p + 1)
        } else if left.len() > size_limit.http_client_request_uri {
            // 到上限仍未出现空格：不像合法 URI，排除当前候选
            self.exclude_current();
            Ok(None)
        } else {
            // URI 还没结束也未超限，再多读一点
            Err(ProtocolInspectError::NeedMoreData(1))
        }
    }

    /// 校验请求行的版本段。
    ///
    /// `version_offset` 指向 `"HTTP/1.x"` 的起点，要求依次匹配 `HTTP/1.`、
    /// 次版本号 `0` 或 `1`、随后紧跟 `\r\n`；三者齐备即确认 [`Protocol::Http1`]。
    fn check_http1_after_url(
        &mut self,
        data: &[u8],
        version_offset: usize,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // at least HTTP/<X>.<Y>\r\n\r\n
        const MINIMUM_DATA_LEN: usize = 12;

        let minimum_len = MINIMUM_DATA_LEN + version_offset;
        let data_len = data.len();
        if data_len < minimum_len {
            return Err(ProtocolInspectError::NeedMoreData(minimum_len - data_len));
        }

        let left = &data[version_offset..];
        // left[7] 是 "HTTP/1." 之后的次版本号，只接受 1.0 / 1.1
        if left.starts_with(b"HTTP/1.")
            && matches!(left[7], b'0' | b'1')
            && left[8] == b'\r'
            && left[9] == b'\n'
        {
            return Ok(Some(Protocol::Http1));
        }

        self.exclude_current();
        Ok(None)
    }

    /// 识别明文 HTTP/2（h2c）连接前缀。
    ///
    /// 客户端首个请求必须以固定 24 字节串 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 开头，
    /// 逐字节相等即确认 [`Protocol::Http2`]。字节不足时先要求补齐再比较。
    fn check_http2_connection_preface(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        const H2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const H2_CONNECTION_PREFACE_LEN: usize = H2_CONNECTION_PREFACE.len();

        let data_len = data.len();
        if data_len < H2_CONNECTION_PREFACE_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                H2_CONNECTION_PREFACE_LEN - data_len,
            ));
        }

        // 前缀是定长字符串，任何一个字节不符即可否定 HTTP/2（但不排除其他候选）
        if !data.starts_with(H2_CONNECTION_PREFACE) {
            return Ok(None);
        }

        Ok(Some(Protocol::Http2))
    }
}
