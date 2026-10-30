/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 G3-OSS developers.
 */

//! LDAP over TCP 请求报文的识别。
//!
//! 每个 LDAP 报文都是一个 ASN.1 BER 编码的 `SEQUENCE`（即 `LDAPMessage`）：
//!
//! ```text
//! 0x30 <BER length> 0x02 <len> <messageID> 0x60 ... <protocolOp>
//! ^tag(SEQUENCE)    ^变长    ^INTEGER         ^BindRequest
//! ```
//!
//! 判定只解析到 messageID，不解析 protocolOp：
//! 1. `data[0] == 0x30` —— SEQUENCE 的 BER tag，这是 LDAP 唯一的强特征。
//! 2. 变长长度字段（短形式 1 字节 / 长形式最多 8 字节长度内容，不接受不定长编码），
//!    且声明长度不超过 `size_limit.ldap_request_msg`。
//! 3. 序列体以 `0x02` INTEGER 开头即 messageID，可解析且**非 0**（LDAP 保留 0 不用）。
//!
//! 难点在于 BER 长度是变长的：`header_len` 必须按解析出的编码长度动态计算，
//! 不能假设固定偏移；因此需要先把整条报文的长度凑齐，才能定位 messageID 并读取它。
//! 首字节 `0x30` 与 TLS(`0x16`)、HTTP 方法（大写字母）、SSH(`'S'`) 等互斥，可整体排除。

use g3_codec::ldap::{LdapLength, LdapLengthParseError, LdapMessageId};

use super::{MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspectState};
use crate::ProtocolInspectionSizeLimit;

impl ProtocolInspectState {
    /// 识别 TCP 上客户端发出的 LDAP 报文：校验 SEQUENCE tag、解析 BER 长度、
    /// 再解析 messageID。三者都成立才返回 [`Protocol::Ldap`]。
    pub(crate) fn check_ldap_tcp_request_message(
        &mut self,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // 0x30 <LEN> 0x02 <Byte count of ID> <ID>
        // tag(1) + 长度(1) + ID tag(1) + ID 长度(1) + ID 值(1)
        const MINIMUM_DATA_LEN: usize = 5;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        if data[0] != 0x30 {
            // 不是 ASN.1 SEQUENCE，绝不可能是 LDAP 报文
            self.exclude_current();
            return Ok(None);
        }

        self.exclude_other(MaybeProtocol::BitTorrent);
        self.exclude_other(MaybeProtocol::Http);
        self.exclude_other(MaybeProtocol::Mqtt);
        self.exclude_other(MaybeProtocol::Rtmp);
        self.exclude_other(MaybeProtocol::Rtsp);
        self.exclude_other(MaybeProtocol::Smpp);
        self.exclude_other(MaybeProtocol::Ssh);
        self.exclude_other(MaybeProtocol::Ssl);
        self.exclude_other(MaybeProtocol::Stomp);
        // 已确认首字节为 0x30：以上候选的客户端首字节取值域均不含 0x30，一次性剔除
        // （DNS 以任意 ID 开头、不排除；Ftp/Smtp 等是服务端 greeting，本方向不涉及）

        // header_len = BER 长度字段自身占用的字节数 + 1 字节的 SEQUENCE tag
        let header_len;
        let content_len;
        match LdapLength::parse(&data[1..]) {
            Ok(v) => {
                if v.value() > size_limit.ldap_request_msg as u64 {
                    // 序列体长度超过配置上限：不可能是正常的 LDAP 请求
                    self.exclude_current();
                    return Ok(None);
                }
                header_len = v.encoded_len() + 1;
                content_len = v.value() as usize;
                if data.len() < header_len + content_len {
                    // 整条报文还没读全，无法定位并解析 messageID
                    return Err(ProtocolInspectError::NeedMoreData(
                        header_len + content_len - data.len(),
                    ));
                }
            }
            Err(LdapLengthParseError::NeedMoreData(n)) => {
                // 长度字段本身的字节还没读全，按提示补读
                return Err(ProtocolInspectError::NeedMoreData(n));
            }
            Err(_) => {
                // 其他解析失败（不定长编码、长度值过大等）都不是合法 LDAP 报文
                self.exclude_current();
                return Ok(None);
            }
        }

        // 序列体开头是 messageID（BER INTEGER）
        let content = &data[header_len..header_len + content_len];
        match LdapMessageId::parse(content) {
            Ok(id) => {
                if id.value() == 0 {
                    // messageID 0 为保留值，合法请求不会使用
                    self.exclude_current();
                    return Ok(None);
                }
            }
            Err(_) => {
                // 开头不是合法的 INTEGER 编码，说明并非 LDAPMessage
                self.exclude_current();
                return Ok(None);
            }
        }

        // TODO check protocolOP
        // 现状不校验 protocolOp 的 tag（BindRequest 应为 0x60），仅凭上述结构即下结论

        Ok(Some(Protocol::Ldap))
    }
}
