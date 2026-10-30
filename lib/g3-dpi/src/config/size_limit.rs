/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 各协议首包检查的字节上限。
//!
//! 识别器拿到的是从连接起始累积的字节前缀，而某些协议的判定需要扫描变长字段
//! （HTTP 的 request-URI、FTP/IMAP 的 greeting 行、NATS 的 INFO 行、LDAP 的整包）。
//! 这些上限限定探测器**最多愿意扫多少字节**：对端只要发一个永不结束的行，
//! 就能让识别阶段无限扫描，所以这是必要的防护，而不是性能调优项。
//!
//! 超过上限时探测器按“不是这个协议”处理（排除当前候选），而不是报错。
//!
//! 字段是 `pub(crate)` 以便各探测器直接读取，而构造只能通过公开的
//! `set_xxx` 方法进行——上层从 YAML 加载配置时逐项覆盖默认值。

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolInspectionSizeLimit {
    /// FTP 服务端 greeting 单行最大长度（RFC 959 未硬性规定，取实践中足够大的值）。
    pub(crate) ftp_server_greeting_msg: usize,
    /// HTTP 客户端请求行的 request-URI 最大长度，超出即判定不是 HTTP。
    pub(crate) http_client_request_uri: usize,
    /// IMAP 服务端 greeting（未登录态的 `* OK ...` 行）最大长度。
    pub(crate) imap_server_greeting_msg: usize,
    /// NATS 服务端首条 INFO 消息单行的最大长度。
    pub(crate) nats_server_info_line: usize,
    /// LDAP TCP 请求报文（含 BER 外层包装）的最大扫描长度。
    pub(crate) ldap_request_msg: usize,
}

impl Default for ProtocolInspectionSizeLimit {
    /// 默认上限：均取自各协议实践中的合理上界，足够宽松以免漏判，
    /// 又足够严格以保证识别阶段的最坏耗时有界。
    fn default() -> Self {
        ProtocolInspectionSizeLimit {
            ftp_server_greeting_msg: 512,
            http_client_request_uri: 4096,
            imap_server_greeting_msg: 512,
            nats_server_info_line: 1024,
            ldap_request_msg: 1024,
        }
    }
}

impl ProtocolInspectionSizeLimit {
    // 以下 set_xxx 只负责写入，不做范围校验：单位是字节，取 0 也无害
    // （等价于禁用该协议的载荷探测），交由上层配置校验层把关取值合理性。

    /// 设置 FTP 服务端 greeting 的最大检查字节数。
    pub fn set_ftp_server_greeting_msg(&mut self, size: usize) {
        self.ftp_server_greeting_msg = size;
    }

    /// 设置 HTTP 请求行中 request-URI 的最大检查字节数。
    pub fn set_http_client_request_uri(&mut self, size: usize) {
        self.http_client_request_uri = size;
    }

    /// 设置 IMAP 服务端 greeting 的最大检查字节数。
    pub fn set_imap_server_greeting_msg(&mut self, size: usize) {
        self.imap_server_greeting_msg = size;
    }

    /// 设置 NATS 服务端 INFO 行的最大检查字节数。
    pub fn set_nats_server_info_line(&mut self, size: usize) {
        self.nats_server_info_line = size;
    }

    /// 设置 LDAP 请求报文的最大检查字节数。
    pub fn set_ldap_request_msg(&mut self, size: usize) {
        self.ldap_request_msg = size;
    }
}
