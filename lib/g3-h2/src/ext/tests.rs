/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! [`RequestExt::serialize_for_adapter`] 的封装字节断言：旁路审计把它产出的
//! 字节直接放进 ICAP 的 req-hdr 封装区，审计服务端看到的就是这份伪 HTTP/1.1
//! 报文头，所以请求行、头名大小写与 hop-by-hop 过滤都必须逐字节固定。

use http::Request;

use crate::RequestExt;

#[test]
fn serialize_keeps_request_line_and_headers() {
    let req = Request::builder()
        .method("POST")
        .uri("http://example.org/upload?a=1")
        .header("Host", "example.org")
        .header("Content-Length", "5")
        .body(())
        .unwrap();

    assert_eq!(
        req.serialize_for_adapter(),
        b"POST /upload?a=1 HTTP/1.1\r\nhost: example.org\r\ncontent-length: 5\r\n\r\n"
    );
}

#[test]
fn serialize_synthesizes_host_and_skips_te() {
    // h2 客户端只发伪头，Host 由 URI 的 authority 补齐；TE 是 hop-by-hop 头，
    // 不能出现在给审计端的报文头里
    let req = Request::builder()
        .method("PUT")
        .uri("https://origin.example:8443/put")
        .header("TE", "trailers")
        .header("X-Tag", "audit")
        .body(())
        .unwrap();

    assert_eq!(
        req.serialize_for_adapter(),
        b"PUT /put HTTP/1.1\r\nx-tag: audit\r\nHost: origin.example\r\n\r\n"
    );
}
