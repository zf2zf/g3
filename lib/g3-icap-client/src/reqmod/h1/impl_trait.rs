/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 为 g3-http 的 HTTP/1.1 请求类型实现 [`HttpRequestForAdaptation`]。
//!
//! 状态机本身（mod.rs 及各分支文件）只依赖 trait，不认识具体的请求类型；
//! 本文件是它与 g3proxy 服务器侧类型的"胶水"，覆盖两种接入形态：
//! - `HttpProxyClientRequest`：正向代理客户端请求（带显式目标 URI）；
//! - `HttpTransparentRequest`：透明代理客户端请求（目标地址来自连接本身）。
//!
//! 两类类型的实现完全一致，都是把自己已有的字段/方法转接到 trait 上：
//! 序列化与"用 ICAP 报文重建自身"的真实逻辑仍在 g3-http 里，因此这里
//! 全部是薄封装（注意各方法内部调用的是 g3-http 的同名 inherent 方法，
//! 不是递归调用 trait 方法）。
//! `append_upgrade_header` 是唯一的"翻译"动作：把 hop-by-hop 的 `Upgrade:`
//! 换成 ICAP 扩展头 `X-HTTP-Upgrade:`（可能多个值 → 多行）。

use bytes::BufMut;
use http::{Method, header};

use g3_http::HttpBodyType;
use g3_http::server::{HttpProxyClientRequest, HttpTransparentRequest};

use super::{HttpAdaptedRequest, HttpRequestForAdaptation};

/// 正向代理请求接入 REQMOD h1 适配器。
impl HttpRequestForAdaptation for HttpProxyClientRequest {
    fn method(&self) -> &Method {
        &self.method
    }

    fn body_type(&self) -> Option<HttpBodyType> {
        self.body_type()
    }

    fn serialize_for_adapter(&self) -> Vec<u8> {
        self.serialize_for_adapter()
    }

    fn append_upgrade_header(&self, buf: &mut Vec<u8>) {
        // Upgrade 是多值头：每个值单独一行 X-HTTP-Upgrade，避免 ICAP 侧解析歧义
        for v in self.hop_by_hop_headers.get_all(header::UPGRADE) {
            buf.put_slice(b"X-HTTP-Upgrade: ");
            buf.put_slice(v.as_bytes());
            buf.put_slice(b"\r\n");
        }
    }

    fn adapt_with_body(&self, other: HttpAdaptedRequest) -> Self {
        self.adapt_with_body(other)
    }

    fn adapt_without_body(&self, other: HttpAdaptedRequest) -> Self {
        self.adapt_without_body(other)
    }
}

/// 透明代理请求接入 REQMOD h1 适配器（语义与上面完全一致）。
impl HttpRequestForAdaptation for HttpTransparentRequest {
    fn method(&self) -> &Method {
        &self.method
    }

    fn body_type(&self) -> Option<HttpBodyType> {
        self.body_type()
    }

    fn serialize_for_adapter(&self) -> Vec<u8> {
        self.serialize_for_adapter()
    }

    fn append_upgrade_header(&self, buf: &mut Vec<u8>) {
        for v in self.hop_by_hop_headers.get_all(header::UPGRADE) {
            buf.put_slice(b"X-HTTP-Upgrade: ");
            buf.put_slice(v.as_bytes());
            buf.put_slice(b"\r\n");
        }
    }

    fn adapt_with_body(&self, other: HttpAdaptedRequest) -> Self {
        self.adapt_with_body(other)
    }

    fn adapt_without_body(&self, other: HttpAdaptedRequest) -> Self {
        self.adapt_without_body(other)
    }
}
