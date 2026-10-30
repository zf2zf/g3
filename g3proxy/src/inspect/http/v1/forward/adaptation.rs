/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP reqmod 送检路径的上游写端适配。
//!
//! [`HttpRequestWriterForAdaptation`] 把上游写端（`ups_w`）包装为异步写类型，
//! 并同时实现 g3_icap_client 要求的 `HttpRequestUpstreamWriter` 协议，
//! 使 ICAP 适配器能够将（可能改写过的）请求头与请求体直接写入上游。

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use g3_http::server::HttpTransparentRequest;
use g3_icap_client::reqmod::h1::HttpRequestUpstreamWriter;

/// ICAP 适配器写请求用的上游写端包装器：所有写操作透传给内部的 `W`
/// （即响应侧 IO 结构中的 `ups_w`）。
pub(crate) struct HttpRequestWriterForAdaptation<'a, W> {
    pub(crate) inner: &'a mut W,
}

impl<W> AsyncWrite for HttpRequestWriterForAdaptation<'_, W>
where
    W: AsyncWrite + Unpin,
{
    // 以下各方法均为对内层写端的简单委托，保留向量化写能力
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<W> HttpRequestUpstreamWriter<HttpTransparentRequest> for HttpRequestWriterForAdaptation<'_, W>
where
    W: AsyncWrite + Send + Unpin,
{
    /// 请求头以面向源站的透明形式序列化后写出，
    /// 请求体随后由适配器经同一写端继续发送。
    async fn send_request_header(&mut self, req: &HttpTransparentRequest) -> io::Result<()> {
        let head = req.serialize_for_origin();
        self.inner.write_all(&head).await
    }
}
