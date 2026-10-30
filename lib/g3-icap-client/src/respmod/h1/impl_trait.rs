/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! [`HttpResponseForAdaptation`] / [`HttpResponseClientWriter`] 的默认实现。
//!
//! 本文件把"适配所需的四种能力"桥接到 g3-http 已有的两种上游响应表示上：
//! - `HttpTransparentResponse`：透明转发场景，响应头基本保持上游原样；
//! - `HttpForwardRemoteResponse`：远程转发场景，响应头由库自行解析/重建。
//!
//! 两者的 `serialize()` / `serialize_for_adapter()` / `adapt_with_body()` /
//! `adapt_without_body()` 方法签名完全一致，因此 impl 只是逐方法转发调用，
//! 新增一种响应类型只需在此再加一个 impl 块，RESPMOD 状态机本身无需改动。
//! 这与 `reqmod::h1::impl_trait`（为请求类型实现 `HttpRequestForAdaptation`）对称。
//!
//! 文件末尾还给"任意 `AsyncWrite`"实现了 [`HttpResponseClientWriter`]，即默认
//! 直接把序列化后的响应头写入流——客户端如果不需要额外处理，用这个泛型实现即可。

use std::io;

use http::Method;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use g3_http::HttpBodyType;
use g3_http::client::{HttpForwardRemoteResponse, HttpTransparentResponse};

use super::{HttpAdaptedResponse, HttpResponseClientWriter, HttpResponseForAdaptation};

/// 远程转发响应接入 RESPMOD 适配。
impl HttpResponseForAdaptation for HttpForwardRemoteResponse {
    /// 按请求方法判定 body 传输方式：`None` 表示该响应不得携带 body，
    /// 适配器随后只上报响应头。
    fn body_type(&self, method: &Method) -> Option<HttpBodyType> {
        self.body_type(method)
    }

    /// 发给客户端的响应头（含逐跳头处理后的最终形态）。
    fn serialize_for_client(&self) -> Vec<u8> {
        self.serialize()
    }

    /// 封装进 ICAP 报文的响应头：仅端到端头，body 随后在 ICAP 层重新 chunked 分块。
    fn serialize_for_adapter(&self) -> Vec<u8> {
        self.serialize_for_adapter()
    }

    /// 采纳 ICAP 改写的响应头 + 后续 chunked body。
    fn adapt_with_body(&self, other: HttpAdaptedResponse) -> Self {
        self.adapt_with_body(other)
    }

    /// 采纳 ICAP 改写的响应头，且响应不含 body。
    fn adapt_without_body(&self, other: HttpAdaptedResponse) -> Self {
        self.adapt_without_body(other)
    }
}

/// 透明转发响应接入 RESPMOD 适配（与上一 impl 逐一对应）。
impl HttpResponseForAdaptation for HttpTransparentResponse {
    /// 按请求方法判定 body 传输方式。
    fn body_type(&self, method: &Method) -> Option<HttpBodyType> {
        self.body_type(method)
    }

    /// 发给客户端的响应头。
    fn serialize_for_client(&self) -> Vec<u8> {
        self.serialize()
    }

    /// 封装进 ICAP 报文的响应头。
    fn serialize_for_adapter(&self) -> Vec<u8> {
        self.serialize_for_adapter()
    }

    /// 采纳 ICAP 改写的响应头 + 后续 chunked body。
    fn adapt_with_body(&self, other: HttpAdaptedResponse) -> Self {
        self.adapt_with_body(other)
    }

    /// 采纳 ICAP 改写的响应头，且响应不含 body。
    fn adapt_without_body(&self, other: HttpAdaptedResponse) -> Self {
        self.adapt_without_body(other)
    }
}

/// 通用兜底实现：任何可写字节流都能作为客户端写出端。
///
/// 注意这里只负责"响应头"，body 由各转发分支用 `StreamCopy` / chunked 重编码
/// 直接写入同一个流。
impl<W, H> HttpResponseClientWriter<H> for W
where
    W: AsyncWrite + Send + Unpin,
    H: HttpResponseForAdaptation + Sync,
{
    /// 序列化响应头并整块写出；不主动 flush，留给后续 body 写入或调用方。
    async fn send_response_header(&mut self, req: &H) -> io::Result<()> {
        let head = req.serialize_for_client();
        self.write_all(&head).await
    }
}
