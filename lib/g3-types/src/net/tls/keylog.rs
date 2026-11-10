/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! TLS KeyLog management for capturing SSLKEYLOGFILE format lines.
//!
//! This module provides thread-safe keylog buffer management for capturing
//! TLS session keys during handshake. The keylog data can be used by
//! tools like Wireshark to decrypt TLS traffic.
//!
//! # NSS KeyLog Format
//!
//! Each line in the keylog file follows the NSS format:
//! `<Label> <ClientRandom> <Secret>`
//!
//! Supported labels:
//! - CLIENT_RANDOM: Full TLS session secrets
//! - CLIENT_HANDSHAKE_TRAFFIC_SECRET: TLS 1.3 handshake secret (client side)
//! - SERVER_HANDSHAKE_TRAFFIC_SECRET: TLS 1.3 handshake secret (server side)
//! - CLIENT_TRAFFIC_SECRET_0: TLS 1.3 application data secret (client side)
//! - SERVER_TRAFFIC_SECRET_0: TLS 1.3 application data secret (server side)

use std::sync::Mutex;

#[cfg(feature = "openssl")]
use openssl::ssl::SslCipherRef;

use super::TlsVersion;

/// Maximum number of keylog entries per connection to prevent memory exhaustion
const MAX_KEYLOG_ENTRIES_PER_CONNECTION: usize = 128;

/// TLS KeyLog entry following NSS SSLKEYLOGFILE format
#[derive(Clone, Debug)]
pub struct TlsKeyLogEntry {
    /// The label identifying the type of key (e.g., "CLIENT_RANDOM")
    pub label: String,
    /// The client random in hex format
    pub client_random: String,
    /// The secret in hex format
    pub secret: String,
}

impl TlsKeyLogEntry {
    /// Create a new keylog entry
    pub fn new(label: String, client_random: String, secret: String) -> Self {
        TlsKeyLogEntry {
            label,
            client_random,
            secret,
        }
    }

    /// Parse a NSS keylog format line
    /// Format: `<Label> <ClientRandom> <Secret>`
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split_whitespace();
        let label = parts.next()?.to_string();
        let client_random = parts.next()?.to_string();
        let secret = parts.next()?.to_string();

        Some(TlsKeyLogEntry {
            label,
            client_random,
            secret,
        })
    }

    /// Convert to NSS keylog format line
    pub fn to_keylog_line(&self) -> String {
        format!("{} {} {}", self.label, self.client_random, self.secret)
    }
}

/// Buffer to collect TLS keylog entries for a single connection.
/// Thread-safe and bounded to prevent memory exhaustion.
pub struct TlsKeyLogBuffer {
    entries: Mutex<Vec<TlsKeyLogEntry>>,
    max_entries: usize,
    tls_version: Mutex<Option<TlsVersion>>,
    cipher_suite: Mutex<Option<u16>>,
    client_random: Mutex<Option<String>>,
    server_random: Mutex<Option<String>>,
}

impl TlsKeyLogBuffer {
    /// Create a new empty keylog buffer.
    pub fn new_empty() -> Self {
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(MAX_KEYLOG_ENTRIES_PER_CONNECTION)),
            max_entries: MAX_KEYLOG_ENTRIES_PER_CONNECTION,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            client_random: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Create a new empty keylog buffer with custom max entries.
    pub fn new_with_max(max_entries: usize) -> Self {
        let max = max_entries.min(MAX_KEYLOG_ENTRIES_PER_CONNECTION);
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(max)),
            max_entries: max,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            client_random: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Set the negotiated TLS version.
    pub fn set_tls_version(&self, version: TlsVersion) {
        *self.tls_version.lock().unwrap() = Some(version);
    }

    /// Get the negotiated TLS version.
    pub fn tls_version(&self) -> Option<TlsVersion> {
        *self.tls_version.lock().unwrap()
    }

    /// Set the negotiated cipher suite, as its two-byte protocol id.
    pub fn set_cipher_suite(&self, id: u16) {
        *self.cipher_suite.lock().unwrap() = Some(id);
    }

    /// Get the negotiated cipher suite's protocol id.
    pub fn cipher_suite(&self) -> Option<u16> {
        *self.cipher_suite.lock().unwrap()
    }

    /// Set the client random (hex format) as taken from the handshake itself.
    pub fn set_client_random(&self, random: String) {
        *self.client_random.lock().unwrap() = Some(random);
    }

    /// Get the client random (hex format).
    ///
    /// 握手侧没显式登记时退回 keylog 首条记录里的字段：NSS 每行都带
    /// `<client_random>`，TLS 1.2/1.3 都取得到。
    pub fn client_random(&self) -> Option<String> {
        let stored = self.client_random.lock().unwrap();
        if let Some(random) = stored.as_ref() {
            return Some(random.clone());
        }
        drop(stored);
        let entries = self.entries.lock().unwrap();
        entries.first().map(|e| e.client_random.clone())
    }

    /// Set the server random (hex format).
    pub fn set_server_random(&self, random: String) {
        *self.server_random.lock().unwrap() = Some(random);
    }

    /// Get the server random (hex format).
    pub fn server_random(&self) -> Option<String> {
        self.server_random.lock().unwrap().clone()
    }

    /// Add a keylog entry. Non-blocking, returns false if buffer is full.
    pub fn add_entry(&self, entry: TlsKeyLogEntry) -> bool {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.max_entries {
            return false;
        }
        entries.push(entry);
        true
    }

    /// Add a keylog entry from parsed components.
    /// Returns false if buffer is full.
    pub fn add(&self, label: String, client_random: String, secret: String) -> bool {
        self.add_entry(TlsKeyLogEntry::new(label, client_random, secret))
    }

    /// Get all collected keylog entries.
    pub fn entries(&self) -> Vec<TlsKeyLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Get all collected keylog entries as ICAP header name-value pairs.
    ///
    /// 头名按审计接口的连字符拼写，不是 NSS 的原样标签：标签里的 `_` 换成 `-`，
    /// TLS 1.3 密钥标签尾部的序号去掉（`CLIENT_TRAFFIC_SECRET_0` →
    /// `X-TLS-CLIENT-TRAFFIC-SECRET`）。value 只放密钥本身——客户端随机数是通用头
    /// `X-TLS-CLIENT-RANDOM`，由序列化侧单独发一次，不必每条密钥都重复一遍。
    ///
    /// TLS 1.2 的 `CLIENT_RANDOM` 是 NSS 给主密钥行起的标签名，随机数部分已经在
    /// 通用头里了，所以这条只出 `X-TLS-MASTER-SECRET`。
    pub fn to_icap_headers(&self) -> Vec<(String, String)> {
        let entries = self.entries.lock().unwrap();
        let mut headers = Vec::with_capacity(entries.len());
        for entry in entries.iter() {
            let name = if entry.label == "CLIENT_RANDOM" {
                "X-TLS-MASTER-SECRET".to_string()
            } else {
                format!("X-TLS-{}", icap_label_suffix(&entry.label))
            };
            headers.push((name, entry.secret.clone()));
        }
        headers
    }

    /// Get the number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

/// NSS 标签到接口头名后缀：去掉 TLS 1.3 密钥标签尾部的 `_0` 序号，再把 `_`
/// 换成 `-`。未知标签走同样规则，不上报就不认识的名字也比丢掉好排查。
fn icap_label_suffix(label: &str) -> String {
    let label = match label.rfind('_') {
        Some(i)
            if i > 0
                && i + 1 < label.len()
                && label[i + 1..].bytes().all(|c| c.is_ascii_digit()) =>
        {
            &label[..i]
        }
        _ => label,
    };
    label.replace('_', "-")
}

/// 协商出的加密套件的线上编号：IANA 分配的两字节 CipherSuite 值，
/// 如 `TLS_AES_256_GCM_SHA384` 是 `0x1302`（4866）。审计接口收的是这个整数，
/// 不是 OpenSSL 的名字串。
///
/// `SSL_CIPHER_get_protocol_id` 要到 OpenSSL 1.1.1 才是公开接口，取不到就返回
/// `None`、这条头不发——自己拼一张名字表更容易错，编错的号会让审计侧把整段
/// 流量解成乱码。
#[cfg(all(feature = "openssl", ossl111))]
pub fn cipher_suite_id(cipher: &SslCipherRef) -> Option<u16> {
    Some(u16::from_be_bytes(cipher.protocol_id()))
}

/// OpenSSL 1.1.0 与 LibreSSL 都没把两字节套件编号做成公开接口，这时不上报这条头
#[cfg(all(feature = "openssl", not(ossl111)))]
pub fn cipher_suite_id(_cipher: &SslCipherRef) -> Option<u16> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_for(entries: &[(&str, &str, &str)]) -> Vec<(String, String)> {
        let buf = TlsKeyLogBuffer::new_empty();
        for (label, client_random, secret) in entries {
            buf.add(
                (*label).to_string(),
                (*client_random).to_string(),
                (*secret).to_string(),
            );
        }
        buf.to_icap_headers()
    }

    #[test]
    fn tls12_client_random_label_reports_only_the_master_secret() {
        // 客户端随机数走通用头 X-TLS-CLIENT-RANDOM，不在这条里重复
        assert_eq!(
            headers_for(&[("CLIENT_RANDOM", "aabb", "ccdd")]),
            vec![("X-TLS-MASTER-SECRET".to_string(), "ccdd".to_string())]
        );
    }

    #[test]
    fn tls13_labels_use_hyphens_and_drop_the_key_schedule_index() {
        assert_eq!(
            headers_for(&[
                ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "aabb", "11"),
                ("SERVER_HANDSHAKE_TRAFFIC_SECRET", "aabb", "22"),
                ("CLIENT_TRAFFIC_SECRET_0", "aabb", "33"),
                ("SERVER_TRAFFIC_SECRET_0", "aabb", "44"),
                ("EXPORTER_SECRET", "aabb", "55"),
            ]),
            vec![
                (
                    "X-TLS-CLIENT-HANDSHAKE-TRAFFIC-SECRET".to_string(),
                    "11".to_string()
                ),
                (
                    "X-TLS-SERVER-HANDSHAKE-TRAFFIC-SECRET".to_string(),
                    "22".to_string()
                ),
                ("X-TLS-CLIENT-TRAFFIC-SECRET".to_string(), "33".to_string()),
                ("X-TLS-SERVER-TRAFFIC-SECRET".to_string(), "44".to_string()),
                ("X-TLS-EXPORTER-SECRET".to_string(), "55".to_string()),
            ]
        );
    }

    #[test]
    fn unknown_labels_are_hyphenated_not_dropped() {
        assert_eq!(
            headers_for(&[("CLIENT_EARLY_TRAFFIC_SECRET", "aabb", "66")]),
            vec![(
                "X-TLS-CLIENT-EARLY-TRAFFIC-SECRET".to_string(),
                "66".to_string()
            )]
        );
    }

    #[test]
    fn client_random_falls_back_to_the_keylog_lines() {
        let buf = TlsKeyLogBuffer::new_empty();
        assert_eq!(buf.client_random(), None);
        buf.add(
            "CLIENT_TRAFFIC_SECRET_0".to_string(),
            "aabb".to_string(),
            "33".to_string(),
        );
        assert_eq!(buf.client_random().as_deref(), Some("aabb"));
        buf.set_client_random("ccdd".to_string());
        assert_eq!(buf.client_random().as_deref(), Some("ccdd"));
    }
}
