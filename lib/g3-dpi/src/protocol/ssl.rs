/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! TLS/SSL 记录层与 ClientHello 识别。
//!
//! 只读前两个头部就下结论，不解析任何扩展（SNI、ALPN 等由上层 TLS 终结时再取）：
//!
//! ```text
//! 记录层头（5 字节）      Handshake 头（4 字节）   ClientHello
//! +---------------+---------------------------+--------------+
//! | type=0x16     | msg_type=0x01             | client_version|
//! | version(2)    | length(3)                 | random(32) ... |
//! | length(2)     |                           |              |
//! +---------------+---------------------------+--------------+
//! ```
//!
//! 判定依据是 **ClientHello 里的 client_version**，而不是记录层的
//! `legacy_record_version`：TLS 1.3 的 ClientHello 仍把 client_version 写成 0x0303，
//! 而记录层版本在中间盒兼容模式下可能被改成 0x0301，噪声更大。
//!
//! 难点在于 Handshake 消息可能跨多个 TLS 记录分片，且首个记录里可能只装了
//! Handshake 头的一部分，所以要靠 `fill_ssl_client_hello_handshake_header`
//! 逐条记录地把 6 字节关键前缀补齐。

use g3_codec::tls::{ContentType, HandshakeType};

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};

/// TLS 记录层头长度：type(1) + version(2) + length(2)。
const SSL_HDR_LEN: usize = 5;
/// Handshake 消息头长度：msg_type(1) + length(3)。
const SSL_HANDSHAKE_HDR_LEN: usize = 4;
/// Handshake 头之后紧跟的 client_version 字段长度。
const SSL_HANDSHAKE_VERSION_LEN: usize = 2;

impl ProtocolInspectState {
    /// 从客户端首包识别 TLS，并按版本代际返回 [`Protocol::Tls*`] / [`Protocol::SslLegacy`]。
    ///
    /// 三步走：
    /// 1. 校验记录层头（类型必须是 0x16 handshake，版本号与长度合法）。
    /// 2. 确认首个记录里能取到完整的 Handshake 头 + client_version（6 字节）。
    /// 3. 读 client_version 定代际。
    ///
    /// 第 1 步一旦确认 `data[0] == 0x16` 且版本号合法，就把所有「首字节不可能是 0x16」
    /// 的明文协议整体排除——这是本函数的主要性能收益，也是避免误判的关键。
    pub(crate) fn check_ssl_client_hello(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        let data_len = data.len();

        /*
         * check ssl hdr
         *
         * struct ssl_hdr {
         *     __u8   type;
         *     __be16 legacy_record_version;
         *     __be16 len;
         * } __attribute_packed__;
         */
        if data_len < SSL_HDR_LEN {
            return Err(ProtocolInspectError::NeedMoreData(SSL_HDR_LEN - data_len));
        }

        if data[0] != ContentType::Handshake as u8 {
            self.exclude_current();
            return Ok(None);
        }

        // exclude impossible protocols
        // 0x16 与下列协议的首字节集合完全互斥：SSH 以 'S'(0x53) 开头，
        // HTTP / RTSP 以方法名首字母开头，MQTT 首字节为 0x10/0x20，
        // STOMP 以 'S' 开头（CONNECT/NOTIFY 等），SMPP / RTMP / BitTorrent / LDAP
        // 的取值域也不同。确认是 TLS 记录后就把它们全部剔除。
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Stomp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Ldap);

        if check_legacy_version(data[1], data[2]).is_err() {
            self.exclude_current();
            return Ok(None);
        }
        let Ok(fragment_len) = check_fragment_len(data[3], data[4]) else {
            self.exclude_current();
            return Ok(None);
        };

        // 记录层头 + Handshake 头 + client_version = 5 + 4 + 2 = 9 字节
        if data_len < SSL_HDR_LEN + SSL_HANDSHAKE_HDR_LEN + SSL_HANDSHAKE_VERSION_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                SSL_HDR_LEN + SSL_HANDSHAKE_HDR_LEN + SSL_HANDSHAKE_VERSION_LEN - data_len,
            ));
        }
        if fragment_len >= SSL_HANDSHAKE_HDR_LEN + SSL_HANDSHAKE_VERSION_LEN {
            // seen full Handshake Message header in the first record
            // 常见情形：首个记录就装了完整的 ClientHello 开头，跳过跨记录拼接
            return self
                .check_ssl_client_hello_full_handshake_header(fragment_len, &data[SSL_HDR_LEN..]);
        }

        // 走到这里说明首个记录的载荷不足 6 字节（分片场景），
        // 需要跨记录把关键前缀拼出来。
        let mut offset = SSL_HDR_LEN;
        let left = &data[offset..];
        // 记录层自述的 fragment_len 可能大于实际已收到的载荷字节数：
        // 上面只保证 data_len >= 9，即 left 至少 4 字节，而 fragment_len 可取 1..=5。
        // 若不先对齐这个差额就按 fragment_len 拷贝，会越界读 data 之后的字节，
        // 因此要求首记录的载荷必须完整可读。
        if fragment_len > left.len() {
            return Err(ProtocolInspectError::NeedMoreData(
                fragment_len - left.len(),
            ));
        }
        let mut msg_hdr_nw = 0usize;
        let mut msg_hdr = [0u8; SSL_HANDSHAKE_HDR_LEN + SSL_HANDSHAKE_VERSION_LEN];
        // SAFETY: 上面已确认 fragment_len <= left.len()，且 fragment_len < 6
        // 等于 msg_hdr 的容量上界，故源与目标两侧的读取 / 写入长度都在各自边界内。
        unsafe {
            std::ptr::copy_nonoverlapping(left.as_ptr(), msg_hdr.as_mut_ptr(), fragment_len);
        }
        offset += fragment_len;
        msg_hdr_nw += fragment_len;

        loop {
            let left = &data[offset..];
            if left.is_empty() {
                return Err(ProtocolInspectError::NeedMoreData(
                    SSL_HDR_LEN + SSL_HANDSHAKE_HDR_LEN + SSL_HANDSHAKE_VERSION_LEN - msg_hdr_nw,
                ));
            }
            let r =
                self.fill_ssl_client_hello_handshake_header(left, &mut msg_hdr[msg_hdr_nw..])?;
            let Some(nw) = r else {
                return Ok(None);
            };
            msg_hdr_nw += nw;
            if msg_hdr_nw >= msg_hdr.len() {
                return self.check_ssl_client_hello_full_handshake_header(fragment_len, &msg_hdr);
            }
            // 每补 nw 字节载荷，都要再跨过下一条记录的 5 字节记录层头
            offset += SSL_HDR_LEN + nw;
        }
    }

    /// 在已凑齐 Handshake 头 + client_version 后判定具体协议代际。
    ///
    /// `buf` 的前 6 字节为 msg_type(1) + length(3) + client_version(2)。
    /// `fragment_len` 是记录层声明的本记录载荷长度，用于校验 Handshake 头
    /// 自述长度与记录层长度是否自相矛盾。
    fn check_ssl_client_hello_full_handshake_header(
        &mut self,
        fragment_len: usize,
        buf: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        /*
         * check ssh handshake hdr
         * struct ssl_handshake_hdr {
         *     __be32 hdr;
         * } __attribute_packed__;
         */
        if buf[0] != HandshakeType::ClientHello as u8 {
            self.exclude_current();
            return Ok(None);
        }
        // Handshake 长度为 3 字节大端，补 0 前缀转成 u32
        let handshake_payload_len = u32::from_be_bytes([0u8, buf[1], buf[2], buf[3]]) as usize;
        if handshake_payload_len + SSL_HANDSHAKE_HDR_LEN < fragment_len {
            // it's possible that the handshake payload fragmented in multiple record, but
            // the first record must only contain the handshake message
            // 首记录只能是 Handshake 消息的片段，不能装完 Handshake 还多出别的东西；
            // 若记录层长度明显大于 Handshake 自述总长，说明这不是合法的 ClientHello 开头。
            self.exclude_current();
            return Ok(None);
        }

        // 判定用 client_version：TLS 1.3 仍写 0x0303，故 TlsModern 覆盖 1.2 与 1.3
        let protocol = match (buf[4], buf[5]) {
            (0x01, 0x01) => Protocol::TlsTlcp,
            (0x02, 0x00) | (0x03, 0x00) => Protocol::SslLegacy,
            (0x03, 0x01) | (0x03, 0x02) => Protocol::TlsLegacy,
            (0x03, 0x03) | (0x03, 0x04) => Protocol::TlsModern,
            _ => {
                self.exclude_current();
                return Ok(None);
            }
        };

        Ok(Some(protocol))
    }

    /// 跨 TLS 记录把 Handshake 头补进 `hdr_buf`。
    ///
    /// 返回 `Ok(Some(n))`：从这条记录复制了 n 字节；
    /// `Ok(None)`：这条记录不符合 TLS（已排除当前候选）；
    /// `Err(NeedMoreData)`：连这条记录的载荷都没读全。
    /// 只做校验与拷贝，不下结论——判定在
    /// [`ProtocolInspectState::check_ssl_client_hello_full_handshake_header`]。
    fn fill_ssl_client_hello_handshake_header(
        &mut self,
        data: &[u8],
        hdr_buf: &mut [u8],
    ) -> Result<Option<usize>, ProtocolInspectError> {
        let data_len = data.len();

        /*
         * check ssl hdr
         *
         * struct ssl_hdr {
         *     __u8   type;
         *     __be16 legacy_record_version;
         *     __be16 len;
         * } __attribute_packed__;
         */
        if data_len < SSL_HDR_LEN {
            return Err(ProtocolInspectError::NeedMoreData(SSL_HDR_LEN - data_len));
        }

        if data[0] != ContentType::Handshake as u8 {
            self.exclude_current();
            return Ok(None);
        }

        if check_legacy_version(data[1], data[2]).is_err() {
            self.exclude_current();
            return Ok(None);
        }
        let Ok(fragment_len) = check_fragment_len(data[3], data[4]) else {
            self.exclude_current();
            return Ok(None);
        };

        // 取记录长度与目标缓冲剩余容量的较小值，保证不会写越界
        let copy_size = fragment_len.min(hdr_buf.len());
        if data_len < SSL_HDR_LEN + copy_size {
            return Err(ProtocolInspectError::NeedMoreData(
                SSL_HDR_LEN + copy_size - data_len,
            ));
        }

        let left = &data[SSL_HDR_LEN..];
        unsafe {
            std::ptr::copy_nonoverlapping(left.as_ptr(), hdr_buf.as_mut_ptr(), copy_size);
        }
        Ok(Some(copy_size))
    }
}

/// 校验记录层的 legacy_record_version 是否落在已知取值内。
///
/// 返回值目前未被使用——调用方只关心 `is_err()`，即“这个版本号根本不该出现在
/// TLS 记录里”。返回 `Protocol` 是为了与 [`check_fragment_len`] 保持同样的签名风格，
/// 也便于将来需要时按记录层版本做更细的判定。
fn check_legacy_version(byte0: u8, byte1: u8) -> Result<Protocol, ()> {
    match (byte0, byte1) {
        (0x01, 0x01) => Ok(Protocol::TlsTlcp),
        (0x02, 0x00) | (0x03, 0x00) => Ok(Protocol::SslLegacy),
        (0x03, 0x01) | (0x03, 0x02) => Ok(Protocol::TlsLegacy),
        (0x03, 0x03) => Ok(Protocol::TlsModern),
        _ => Err(()),
    }
}

/// 校验 TLS 记录层声明的载荷长度。
///
/// 长度为 0 或超过 2^14 都不可能是真实 TLS 记录（RFC 5246 第 6.2.1 节硬性上限），
/// 借此可以把大量随机数据快速排除掉。
fn check_fragment_len(byte0: u8, byte1: u8) -> Result<usize, ()> {
    let ssl_payload_len = u16::from_be_bytes([byte0, byte1]) as usize;
    if ssl_payload_len == 0 || ssl_payload_len > 1 << 14 {
        // The length MUST NOT exceed 2^14 bytes.
        Err(())
    } else {
        Ok(ssl_payload_len)
    }
}
