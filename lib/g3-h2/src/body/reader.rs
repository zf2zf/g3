/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h2::RecvStream;
use http::HeaderMap;
use tokio::io::{AsyncRead, ReadBuf};

/// [`H2StreamReader`] 把数据侧读完之后的收尾状态。
#[derive(Debug)]
pub enum H2StreamBodyEnd {
    /// 收到 END_STREAM：请求体完整，且其后没有 TRAILERS 帧
    EndOfStream,
    /// 请求体之后收到 TRAILERS 帧
    Trailers(HeaderMap),
    /// 数据侧没有正常结束（中继被掐断、流被 reset 或读失败）：请求体不完整，
    /// 调用方不应对上游发 END_STREAM
    Incomplete,
}

pub struct H2StreamReader {
    recv_stream: RecvStream,
    received_bytes: Option<Bytes>,
    /// poll_data 已返回 None（END_STREAM 或 TRAILERS 帧已到）
    data_eof: bool,
    /// poll_data 已返回错误（流被 reset 等）
    aborted: bool,
}

impl H2StreamReader {
    pub fn new(stream: RecvStream) -> Self {
        H2StreamReader {
            recv_stream: stream,
            received_bytes: None,
            data_eof: false,
            aborted: false,
        }
    }

    /// 数据侧结束（[`AsyncRead`] 已返回 EOF 或错误）之后取出可能存在的
    /// TRAILERS 帧，并报告请求体是否完整送达。未结束时调用会立即返回
    /// [`H2StreamBodyEnd::Incomplete`]，不会等待后续帧。
    pub async fn body_end(&mut self) -> H2StreamBodyEnd {
        if self.aborted || !self.data_eof {
            return H2StreamBodyEnd::Incomplete;
        }
        match poll_fn(|cx| self.recv_stream.poll_trailers(cx)).await {
            Ok(Some(trailers)) => H2StreamBodyEnd::Trailers(trailers),
            Ok(None) => H2StreamBodyEnd::EndOfStream,
            Err(_) => H2StreamBodyEnd::Incomplete,
        }
    }
}

impl AsyncRead for H2StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(mut b) = self.received_bytes.take() {
                let to_put = buf.remaining().min(b.len());
                let split = b.split_to(to_put);
                buf.put_slice(&split);
                if !b.is_empty() {
                    self.received_bytes = Some(b);
                }
                return Poll::Ready(Ok(()));
            }

            match ready!(self.recv_stream.poll_data(cx)) {
                Some(Ok(b)) => {
                    if b.is_empty() {
                        continue;
                    }
                    self.recv_stream
                        .flow_control()
                        .release_capacity(b.len())
                        .map_err(|e| {
                            if e.is_io() {
                                e.into_io().unwrap()
                            } else {
                                io::Error::other(e)
                            }
                        })?;
                    self.received_bytes = Some(b);
                }
                Some(Err(e)) => {
                    self.data_eof = true;
                    self.aborted = true;
                    return if e.is_io() {
                        Poll::Ready(Err(e.into_io().unwrap()))
                    } else {
                        Poll::Ready(Err(io::Error::other(e)))
                    };
                }
                None => {
                    self.data_eof = true;
                    return Poll::Ready(Ok(()));
                }
            };
        }
    }
}
