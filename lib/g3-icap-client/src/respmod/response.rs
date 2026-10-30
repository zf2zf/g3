/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 解析 ICAP RESPMOD 响应的状态行与头部。
//!
//! 只负责"头"部分（`ICAP/1.0 200 ...` + 头字段 + 空行），解析出：
//! - 状态码/原因短语：判断审计结论（204 放行、200 带修改后的封装体等）；
//! - `Connection`：决定该 ICAP 连接能否归还连接池复用；
//! - `Encapsulated`：交给 [`IcapRespmodResponsePayload::parse`] 还原
//!   封装后的 HTTP 响应布局。
//! 封装体（修改后的 HTTP 响应）本身由 h1/h2 适配器按 `payload` 继续读取。

use tokio::io::AsyncBufRead;

use g3_io_ext::LimitedBufReadExt;

use super::{IcapRespmodParseError, IcapRespmodResponsePayload};
use crate::parse::{HeaderLine, StatusLine};

/// 解析完成的 RESPMOD ICAP 响应头信息。
pub(crate) struct RespmodResponse {
    /// ICAP 状态码（204 = 不修改直接放行；200 = 带有封装的响应体）。
    pub(crate) code: u16,
    /// 状态行原因短语，用于日志展示。
    pub(crate) reason: String,
    /// 是否允许把该 ICAP 连接放回连接池复用（`Connection: close` 时为 false）。
    pub(crate) keep_alive: bool,
    /// `Encapsulated` 头描述的封装体布局。
    pub(crate) payload: IcapRespmodResponsePayload,
}

impl RespmodResponse {
    fn new(code: u16, reason: String) -> Self {
        RespmodResponse {
            code,
            reason,
            // ICAP 1.x 默认长连接，只有对端显式声明 close 才关闭复用
            keep_alive: true,
            payload: IcapRespmodResponsePayload::NoPayload,
        }
    }

    /// 从连接上流式读取并解析一条完整的 ICAP RESPMOD 响应头。
    ///
    /// `max_header_size` 是整份头（含状态行）的字节上限，用来防御
    /// 异常服务器发送的超长头部；读取全程使用受限读，不会超预算。
    pub(crate) async fn parse<R>(
        reader: &mut R,
        max_header_size: usize,
    ) -> Result<RespmodResponse, IcapRespmodParseError>
    where
        R: AsyncBufRead + Unpin,
    {
        // 单行复用同一个缓冲区，读到一行解析一行，避免逐行分配
        let mut line_buf = Vec::<u8>::with_capacity(1024);
        // 已累计消耗的头字节数，用于总预算控制
        let mut header_size = 0;

        // 先读状态行
        let (found, nr) = reader
            .limited_read_until(b'\n', max_header_size, &mut line_buf)
            .await?;
        if nr == 0 {
            // 还没读到任何字节连接就被关闭：典型的池化连接失效
            return Err(IcapRespmodParseError::RemoteClosed);
        }
        if !found {
            // 读满预算仍未见 '\n'：区分"远端半途断开"与"头部超长"，
            // 前者 nr 小于预算，后者说明已达 max_header_size 上限
            return if nr < max_header_size {
                Err(IcapRespmodParseError::RemoteClosed)
            } else {
                Err(IcapRespmodParseError::TooLargeHeader(max_header_size))
            };
        }
        header_size += nr;
        let mut rsp = Self::build_from_status_line(&line_buf)?;

        // 逐行读头字段，直到空行结束
        loop {
            if header_size >= max_header_size {
                return Err(IcapRespmodParseError::TooLargeHeader(max_header_size));
            }
            line_buf.clear();
            // 每次只允许读"剩余预算"，保证头总长不越界
            let max_len = max_header_size - header_size;
            let (found, nr) = reader
                .limited_read_until(b'\n', max_len, &mut line_buf)
                .await?;
            if nr == 0 {
                return Err(IcapRespmodParseError::RemoteClosed);
            }
            if !found {
                // 同状态行处的判断：语义一致的两种截断
                return if nr < max_len {
                    Err(IcapRespmodParseError::RemoteClosed)
                } else {
                    Err(IcapRespmodParseError::TooLargeHeader(max_header_size))
                };
            }
            header_size += nr;
            // 空行（裸 LF 或 CRLF）即头部结束标志
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

    fn build_from_status_line(line_buf: &[u8]) -> Result<Self, IcapRespmodParseError> {
        // StatusLine 同时兼容 ICAP/1.x 与 HTTP 风格的 "协议 状态码 原因"
        let status =
            StatusLine::parse(line_buf).map_err(IcapRespmodParseError::InvalidStatusLine)?;

        let rsp = RespmodResponse::new(status.code, status.message.to_string());
        Ok(rsp)
    }

    fn parse_header_line(&mut self, line: &[u8]) -> Result<(), IcapRespmodParseError> {
        let header = HeaderLine::parse(line).map_err(IcapRespmodParseError::InvalidHeaderLine)?;

        // 只关心影响连接复用与封装布局的两个头，其余（如 X-Methods）忽略
        match header.name.to_lowercase().as_str() {
            "connection" => {
                let value = header.value.to_lowercase();

                // Connection 是逗号分隔列表，逐项判断
                for v in value.as_str().split(',') {
                    if v.is_empty() {
                        continue;
                    }

                    match v.trim() {
                        "keep-alive" => {
                            // keep the original value from request
                        }
                        "close" => {
                            // 对端要求关闭：解析成功后也不能归还连接池复用
                            self.keep_alive = false;
                        }
                        _ => {} // ignore other custom hop-by-hop headers
                    }
                }
            }
            // 委托 payload.rs 解析封装布局（res-hdr/res-body/null-body）
            "encapsulated" => self.payload = IcapRespmodResponsePayload::parse(header.value)?,
            _ => {}
        }

        Ok(())
    }
}
