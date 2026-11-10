/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 扩展头部字段拼装函数集合（crate 内部使用）。
//!
//! 每个 `add_*` 函数向头部缓冲区追加一组 "Name: value\r\n" 形式的 ICAP 头：
//! - `add_connection_tuple`：X-Proxy-IP/PORT、X-Remote-IP/PORT、X-Proto-P 五元组，
//!   供审计侧还原连接归属（repid 审计场景，见 wming 添加的标记）；
//! - `add_keylog_headers`：X-TLS-VERSION / X-TLS-CIPHER-SUITE / X-TLS-CLIENT-RANDOM /
//!   X-TLS-SERVER-RANDOM 以及各密钥日志对应的 X-TLS-* 头，值中的 ASCII 控制字符会被替换为空格，
//!   防止恶意 keylog 内容注入伪造头部（header injection）；
//! - `add_client_session_id`：X-Client-Session-ID，即 ICAP 请求所描述流量所属的客户端连接；
//! - `add_client_addr`：X-Client-IP / X-Client-Port，即 ICAP 请求所描述流量的客户端；
//! - `add_client_username`：X-Client-Username 明文 + X-Authenticated-User
//!   （base64("Local://<user>")，沿用 Squid 等 ICAP 服务的认证用户名编码约定）；
//! - `add_shared`：透传的原始 HTTP 共享头（按配置的白名单收集而来）。

use std::io::Write;
use std::net::SocketAddr;

use base64::prelude::*;
use bytes::BufMut;

use uuid::Uuid;

use g3_types::net::{HttpHeaderMap, TlsKeyLogBuffer};

/* added by wming for repid audit */
use crate::reqmod::ConnectionTuple;

/// 追加五元组信息头：X-Proxy-IP/PORT（服务端一侧地址）、X-Remote-IP/PORT
/// （对端地址）、X-Proto-P（传输协议的 IANA 协议号，TCP=6、UDP=17）。
pub fn add_connection_tuple(buf: &mut Vec<u8>, tuple: &ConnectionTuple) {
    let _ = write!(buf, "X-Proxy-IP: {}\r\n", tuple.server_addr.ip());
    let _ = write!(buf, "X-Proxy-PORT: {}\r\n", tuple.server_addr.port());
    let _ = write!(buf, "X-Remote-IP: {}\r\n", tuple.remote_addr.ip());
    let _ = write!(buf, "X-Remote-PORT: {}\r\n", tuple.remote_addr.port());
    let _ = write!(buf, "X-Proto-P: {}\r\n", tuple.protocol as u8);
}

/// Add TLS keylog entries as ICAP headers.
///
/// 中文补充：先写 TLS 版本/密码套件/两个握手随机数这四条通用头，再逐条追加密钥
/// （TLS 1.2 的 `X-TLS-MASTER-SECRET`、TLS 1.3 的 `X-TLS-*-TRAFFIC-SECRET` 与
/// `X-TLS-EXPORTER-SECRET`，命名规则见 `TlsKeyLogBuffer::to_icap_headers`）。
/// value 中的 ASCII 控制字符（\r、\n、NUL 等）一律替换为空格，避免破坏
/// "Name: value\r\n" 线格式、被利用注入额外头部。
pub fn add_keylog_headers(buf: &mut Vec<u8>, keylog: &TlsKeyLogBuffer) {
    // 元数据（版本/套件/两个随机数）与 keylog 条目任一存在就输出：
    // TLS 1.2 会话复用等场景可能没有新条目，但握手公开值仍有解密价值。
    let client_random = keylog.client_random();
    if keylog.is_empty()
        && keylog.tls_version().is_none()
        && keylog.cipher_suite().is_none()
        && client_random.is_none()
        && keylog.server_random().is_none()
    {
        return;
    }
    if let Some(version) = keylog.tls_version() {
        let _ = write!(buf, "X-TLS-VERSION: {}\r\n", version.as_icap_str());
    }
    if let Some(cipher) = keylog.cipher_suite() {
        let _ = write!(buf, "X-TLS-CIPHER-SUITE: {cipher}\r\n");
    }
    if let Some(client_random) = client_random {
        let _ = write!(buf, "X-TLS-CLIENT-RANDOM: {}\r\n", client_random);
    }
    if let Some(server_random) = keylog.server_random() {
        let _ = write!(buf, "X-TLS-SERVER-RANDOM: {}\r\n", server_random);
    }
    for (name, value) in keylog.to_icap_headers() {
        buf.put_slice(name.as_bytes());
        buf.put_slice(b": ");
        for c in value.chars() {
            // 控制字符（含 \r \n）替换为空格：防止 keylog 内容伪造行边界做头注入
            if c.is_ascii_control() {
                buf.put_slice(b" ");
            } else {
                buf.put_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            }
        }
        buf.put_slice(b"\r\n");
    }
}

/// 追加 X-Client-Session-ID 头：标明被检测流量属于哪一条客户端连接。
/// 值为不带 `-` 的 UUID；同一条长连接上的多次上报取值相同，审计侧据此把同一
/// 会话内的多个请求关联起来。
pub(crate) fn add_client_session_id(buf: &mut Vec<u8>, id: Uuid) {
    let _ = write!(buf, "X-Client-Session-ID: {}\r\n", id.simple());
}

/// 追加 X-Client-IP / X-Client-Port 头，标明被检测流量发起方的客户端地址。
pub(crate) fn add_client_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    let _ = write!(buf, "X-Client-IP: {}\r\n", addr.ip());
    let _ = write!(buf, "X-Client-Port: {}\r\n", addr.port());
}

/// 追加认证用户名头：X-Client-Username 为明文用户名；X-Authenticated-User 为
/// base64("Local://<user>")，"Local://" 前缀是 Squid 系 ICAP 生态对本地认证
/// 用户的惯例标识，部分检测服务只识别这个编码后的头。
pub(crate) fn add_client_username(buf: &mut Vec<u8>, user: &str) {
    buf.put_slice(b"X-Client-Username: ");
    buf.put_slice(user.as_bytes());
    buf.put_slice(b"\r\n");

    buf.put_slice(b"X-Authenticated-User: ");
    let v = BASE64_STANDARD.encode(format!("Local://{user}"));
    buf.put_slice(v.as_bytes());
    buf.put_slice(b"\r\n");
}

/// 追加需要透传给 ICAP 服务的原始 HTTP 共享头（名字已在配置白名单内、值已在
/// 采集侧做过清洗），逐个以 "Name: value\r\n" 原样写入。
pub(crate) fn add_shared(buf: &mut Vec<u8>, headers: &HttpHeaderMap) {
    headers.for_each(|name, value| {
        buf.put_slice(name.as_str().as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value.as_bytes());
        buf.put_slice(b"\r\n");
    });
}
