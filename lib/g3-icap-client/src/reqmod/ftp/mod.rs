/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP 上传审计适配器（薄壳，行为等价保留）。
//!
//! 审计管线已下沉到协议无关的 [`crate::reqmod::bypass`]。本模块只保留
//! FTP 协议特有的伪 HTTP 封装（[`build_ftp_framing`]：`PUT <path> HTTP/1.1`
//! + Host + Content-Type + X-FTP-Command）与兼容用类型别名；中继循环、
//! 背压、判决后台读取等全部由 bypass 管线实现。

use std::io::Write;

use g3_io_ext::{IdleCheck, StreamCopyConfig};

use crate::reqmod::IcapReqmodClient;
use crate::reqmod::bypass::{BypassAdapter, BypassEndState, BypassErrorKind, BypassFraming};
use crate::reqmod::mail::ReqmodAdaptationRunState;

pub use crate::reqmod::bypass::BypassAdaptationError;

/// 兼容别名：FTP 审计的终态/错误即通用旁路管线的对应类型。
pub type FtpAdaptationEndState = BypassEndState;
pub type FtpAdaptationErrorKind = BypassErrorKind;

/// 把 FTP 路径转成合法的 HTTP origin-form 请求目标。
///
/// 文件名可以是任意字节（中文、空格、百分号、CRLF），直接拼进请求行会让
/// ICAP 服务器解析封装区失败并回 400，整次上传审计被丢弃；CRLF 还能注入
/// 伪造的封装头。故按 RFC 3986 path 规则百分号编码，仅保留未保留字符与 `/`，
/// 并补上前导 `/`。
fn request_target(ftp_path: &str) -> String {
    const UNRESERVED: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/";
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut target = String::with_capacity(ftp_path.len() + 8);
    target.push('/');
    for byte in ftp_path.strip_prefix('/').unwrap_or(ftp_path).as_bytes() {
        if UNRESERVED.contains(byte) {
            target.push(*byte as char);
        } else {
            target.push('%');
            target.push(HEX[(byte >> 4) as usize] as char);
            target.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    target
}

/// 把一次 STOR 上传伪装成 HTTP 请求，作为 ICAP 封装区的 req-hdr。
pub fn build_ftp_framing(ftp_command: &str, ftp_path: &str) -> BypassFraming {
    let mut req_hdr = Vec::with_capacity(160);
    let _ = write!(
        req_hdr,
        "PUT {} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/octet-stream\r\n\
         X-FTP-Command: {}\r\n\
         \r\n",
        request_target(ftp_path),
        ftp_command
    );
    BypassFraming {
        req_hdr,
        transformed_from: "FTP",
        // FTP 数据通道没有 HTTP 版本与请求体成帧可言，保持既有记录形态不变
        http_version: None,
        body_framing: None,
    }
}

/// FTP 上传数据通道的 ICAP 审计适配器：`BypassAdapter` 的 FTP 薄壳。
pub struct FtpUploadAdapter<I: IdleCheck>(BypassAdapter<I>);

impl IcapReqmodClient {
    /// 构造流式 FTP 上传审计器（内部即 `bypass_adapter` + FTP framing）。
    pub async fn ftp_upload_audit_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> anyhow::Result<FtpUploadAdapter<I>> {
        self.bypass_adapter(copy_config, idle_checker)
            .await
            .map(FtpUploadAdapter)
    }
}

impl<I: IdleCheck> FtpUploadAdapter<I> {
    /// 记录客户端地址（X-Client-IP / X-Client-Port）。
    pub fn set_client_addr(&mut self, addr: std::net::SocketAddr) {
        self.0.set_client_addr(addr);
    }

    /// 注入数据通道五元组（X-Proxy-IP / X-Remote-IP / X-Proto-P）。
    pub fn set_connection_tuple(&mut self, tuple: crate::reqmod::ConnectionTuple) {
        self.0.set_connection_tuple(tuple);
    }

    /// 注入 TLS keylog 缓冲区（X-TLS-*）。
    pub fn set_keylog_buffer(&mut self, buffer: std::sync::Arc<g3_types::net::TlsKeyLogBuffer>) {
        self.0.set_keylog_buffer(buffer);
    }

    /// 边转发上游边旁路审计；ICAP 失败绝不阻断上传。
    pub async fn audit_and_forward<CR, UW>(
        self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: &mut UW,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: tokio::io::AsyncRead + Send + Sync + Unpin,
        UW: tokio::io::AsyncWrite + Send + Sync + Unpin,
    {
        self.0
            .audit_and_forward(state, build_ftp_framing(ftp_cmd, ftp_path), clt_r, ups_w)
            .await
    }

    /// audit-only 模式：数据只送 ICAP，由调用方自行转发。
    pub async fn audit_only<CR>(
        self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: tokio::io::AsyncRead + Send + Sync + Unpin,
    {
        self.0
            .audit_only(state, build_ftp_framing(ftp_cmd, ftp_path), clt_r)
            .await
    }
}

/// 便捷构造：FTP 调用方直接建一个空的运行状态。
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState {
    crate::reqmod::bypass::new_run_state()
}

#[cfg(test)]
mod tests {
    use super::build_ftp_framing;

    #[test]
    fn test_build_ftp_framing_exact_bytes() {
        let f = build_ftp_framing("STOR", "/data/file.bin");
        assert_eq!(f.transformed_from, "FTP");
        assert_eq!(
            f.req_hdr,
            b"PUT /data/file.bin HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/octet-stream\r\n\
             X-FTP-Command: STOR\r\n\
             \r\n"
        );
    }

    #[test]
    fn test_build_ftp_framing_percent_encodes_target() {
        let f = build_ftp_framing("STOR", "报告 2026.pdf");
        let head = std::str::from_utf8(&f.req_hdr).unwrap();
        assert!(
            head.starts_with("PUT /%E6%8A%A5%E5%91%8A%202026.pdf HTTP/1.1\r\n"),
            "{head}"
        );
    }

    #[test]
    fn test_build_ftp_framing_origin_form_for_relative_path() {
        let f = build_ftp_framing("STOR", "file.txt");
        let head = std::str::from_utf8(&f.req_hdr).unwrap();
        assert!(head.starts_with("PUT /file.txt HTTP/1.1\r\n"), "{head}");
    }

    #[test]
    fn test_build_ftp_framing_empty_path() {
        let f = build_ftp_framing("STOU", "");
        let head = std::str::from_utf8(&f.req_hdr).unwrap();
        assert!(head.starts_with("PUT / HTTP/1.1\r\n"), "{head}");
    }

    #[test]
    fn test_build_ftp_framing_neutralizes_crlf_in_path() {
        let f = build_ftp_framing("STOR", "a\r\nX-Evil: yes\r\n");
        let head = std::str::from_utf8(&f.req_hdr).unwrap();
        assert!(
            head.starts_with("PUT /a%0D%0AX-Evil%3A%20yes%0D%0A HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(!head.contains("\r\nX-Evil"), "{head}");
    }
}
