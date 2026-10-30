/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 替代响应（用于直接回复客户端的 HTTP 响应）的解析与序列化。
//!
//! 当 REQMOD 的 ICAP 返回 `200 + res-hdr/res-body` 时，代理不再访问上游，而是把
//! 封装在 ICAP 里的这个 HTTP 响应"解封"后回给客户端，本类型就是解封后的中间表示。
//! 之所以自己手写解析而不复用 g3-http 的客户端响应解析器：这里的输入来自 ICAP
//! 连接的封装内容，长度由 Encapsulated 偏移界定，且需要刻意丢弃与"重新分块"冲突的头。
//!
//! 头部丢弃策略（见 handle_header）：
//! - `Connection` / `Keep-Alive`：描述的是 ICAP↔代理这条跳的长连接，与客户端↔代理
//!   这条跳无关，必须由代理重新生成；
//! - `Transfer-Encoding` / `Content-Length`：封装的 body 会被重新按 chunked 传输，
//!   原长度信息不再成立，由 `set_chunked_encoding()` 统一改写。

use std::io::Write;
use std::str::FromStr;

use bytes::BufMut;
use http::{HeaderName, StatusCode, Version};
use tokio::io::AsyncBufRead;

use g3_http::client::HttpResponseParseError;
use g3_http::{HttpHeaderLine, HttpLineParseError, HttpStatusLine};
use g3_io_ext::LimitedBufReadExt;
use g3_types::net::{HttpHeaderMap, HttpHeaderValue};

/// 从 ICAP 封装内容解析出的 HTTP 响应（状态行 + 头，body 由调用方另行处理）。
pub struct HttpAdapterErrorResponse {
    /// HTTP 版本。
    pub version: Version,
    /// 状态码。
    pub status: StatusCode,
    /// 原因短语（序列化时原样写回）。
    pub reason: String,
    /// 保留下来的响应头（hop-by-hop 与长度相关头已剔除）。
    pub headers: HttpHeaderMap,
}

impl HttpAdapterErrorResponse {
    fn new(version: Version, status: StatusCode, reason: String) -> Self {
        HttpAdapterErrorResponse {
            version,
            status,
            reason,
            headers: HttpHeaderMap::default(),
        }
    }

    /// 声明 body 采用 chunked：ICAP 封装的 body 会以 chunked 继续转给客户端。
    pub(crate) fn set_chunked_encoding(&mut self) {
        self.headers.insert(
            http::header::TRANSFER_ENCODING,
            HttpHeaderValue::from_static("chunked"),
        );
    }

    /// 从 reader 解析一个完整的 HTTP 响应头。
    ///
    /// `header_size` 是封装内容中"响应头"的字节数（来自 ICAP 的 Encapsulated 偏移），
    /// 用它做硬上限：既防止 ICAP 服务写出超长头（TooLargeHeader），也保证只消费
    /// 属于本响应的字节，多一个字节都会破坏后续 body 的解析位置。
    /// 首行是状态行，之后逐行读头，遇到单独空行（`\r\n` 或 `\n`）结束。
    pub async fn parse<R>(
        reader: &mut R,
        header_size: usize,
    ) -> Result<Self, HttpResponseParseError>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut line_buf = Vec::<u8>::with_capacity(1024);
        let mut read_size: usize = 0;

        // 状态行：单独读一次，其长度也计入 header_size 预算
        let (found, nr) = reader
            .limited_read_until(b'\n', header_size, &mut line_buf)
            .await?;
        if nr == 0 {
            return Err(HttpResponseParseError::RemoteClosed);
        }
        if !found {
            // 没读到换行：长度未用满说明对端提前关闭，用满说明头超长
            return if nr < header_size {
                Err(HttpResponseParseError::RemoteClosed)
            } else {
                Err(HttpResponseParseError::TooLargeHeader(header_size))
            };
        }
        read_size += nr;

        let mut rsp = HttpAdapterErrorResponse::build_from_status_line(&line_buf)?;

        loop {
            if read_size >= header_size {
                return Err(HttpResponseParseError::TooLargeHeader(header_size));
            }
            line_buf.clear();
            // 每行最多只能读到封装响应的边界，避免越界消费 body
            let max_len = header_size - read_size;
            let (found, nr) = reader
                .limited_read_until(b'\n', max_len, &mut line_buf)
                .await?;
            if nr == 0 {
                return Err(HttpResponseParseError::RemoteClosed);
            }
            if !found {
                return if nr < max_len {
                    Err(HttpResponseParseError::RemoteClosed)
                } else {
                    Err(HttpResponseParseError::TooLargeHeader(header_size))
                };
            }
            read_size += nr;
            if (line_buf.len() == 1 && line_buf[0] == b'\n')
                || (line_buf.len() == 2 && line_buf[0] == b'\r' && line_buf[1] == b'\n')
            {
                // header end line
                break;
            }

            rsp.parse_header_line(&line_buf)?;
        }

        Ok(rsp)
    }

    /// 解析状态行（`HTTP/1.1 403 Forbidden`）为版本 + 状态码 + 原因短语。
    fn build_from_status_line(line_buf: &[u8]) -> Result<Self, HttpResponseParseError> {
        let rsp =
            HttpStatusLine::parse(line_buf).map_err(HttpResponseParseError::InvalidStatusLine)?;
        let version = match rsp.version {
            0 => Version::HTTP_10,
            1 => Version::HTTP_11,
            2 => Version::HTTP_2,
            _ => unreachable!(),
        };
        let status = StatusCode::from_u16(rsp.code).map_err(|_| {
            HttpResponseParseError::InvalidStatusLine(HttpLineParseError::InvalidStatusCode)
        })?;

        Ok(HttpAdapterErrorResponse::new(
            version,
            status,
            rsp.reason.to_string(),
        ))
    }

    fn parse_header_line(&mut self, line_buf: &[u8]) -> Result<(), HttpResponseParseError> {
        let header =
            HttpHeaderLine::parse(line_buf).map_err(HttpResponseParseError::InvalidHeaderLine)?;
        self.handle_header(header)
    }

    /// 收录单个响应头，并按"逐跳头/长度头必须重算"的规则丢弃不该透传的头。
    fn handle_header(&mut self, header: HttpHeaderLine) -> Result<(), HttpResponseParseError> {
        let name = HeaderName::from_str(header.name).map_err(|_| {
            HttpResponseParseError::InvalidHeaderLine(HttpLineParseError::InvalidHeaderName)
        })?;

        match name.as_str() {
            // 逐跳头：属于 ICAP↔代理这条连接，不能透给客户端
            "connection" | "keep-alive" => return Ok(()),
            // 长度/分块头：body 会重新按 chunked 传输，由代理重新给出
            "transfer-encoding" | "content-length" => return Ok(()),
            _ => {}
        }

        let mut value = HttpHeaderValue::from_str(header.value).map_err(|_| {
            HttpResponseParseError::InvalidHeaderLine(HttpLineParseError::InvalidHeaderValue)
        })?;
        // 保留原始大小写，便于客户端看到与 ICAP 一致的头部风格
        value.set_original_name(header.name);
        // append 而非 insert：同名多值头（如 Set-Cookie）必须全部保留
        self.headers.append(name, value);
        Ok(())
    }

    /// 序列化成写给客户端的 HTTP 响应头字节（状态行 + 头 + 空行）。
    ///
    /// `close_connection` 决定 `Connection:` 的取值：ICAP 替代响应通常不带
    /// 可复用的长度信息，由代理按自身连接策略重新生成该头。
    pub fn serialize(&self, close_connection: bool) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(2048);

        let _ = write!(
            buf,
            "{:?} {} {}\r\n",
            self.version,
            self.status.as_u16(),
            self.reason
        );

        self.headers
            .for_each(|name, value| value.write_to_buf(name, &mut buf));
        // Connection 由代理按自己与客户端之间的连接策略重新生成
        // （close → "Connection: Close"，否则 "Connection: Keep-Alive"）
        let connection_value = g3_http::header::connection_as_bytes(close_connection);
        buf.put_slice(connection_value);
        // 空行结束响应头，随后由调用方写入（chunked 的）body
        buf.put_slice(b"\r\n");
        buf
    }
}
