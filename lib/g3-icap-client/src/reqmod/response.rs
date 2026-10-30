/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! REQMOD 场景下 ICAP 响应（状态行 + 头部）的解析。
//!
//! [`ReqmodResponse::parse`] 从 ICAP 连接上逐行读取响应头部，产出：
//! - `code` / `reason`：状态行（如 `ICAP/1.0 200 OK`）中的状态码与原因短语；
//! - `keep_alive`：由 Connection 头决定该 ICAP 连接是否可复用；
//! - `payload`：Encapsulated 头解析结果，配合状态码构成客户端行为决策表：
//!   - 204（通常无 Encapsulated 头）→ payload 保持默认 NoPayload → 原样放行；
//!   - 200 + `req-hdr=0, req-body|null-body=N` → 用返回的 HTTP 请求替换原请求转发上游；
//!   - 200 + `res-hdr=0, res-body|null-body=N` → 不回源，用返回的 HTTP 响应直接回复客户端；
//!   - 其它状态码 → 由各协议适配器判定为错误（可能触发 bypass）。
//!   注意：状态码语义由各适配器检查，本模块只负责如实解析头部；
//! - `shared_headers`：命中配置 `respond_shared_names` 白名单的响应头，
//!   会被收集起来回传给调用方（例如 ICAP 服务附加的审计/标注头）。

use std::collections::BTreeSet;
use std::str::FromStr;

use http::HeaderName;
use tokio::io::AsyncBufRead;

use g3_io_ext::LimitedBufReadExt;
use g3_types::net::{HttpHeaderMap, HttpHeaderValue};

use super::{IcapReqmodParseError, IcapReqmodResponsePayload};
use crate::parse::{HeaderLine, IcapLineParseError, StatusLine};

/// 解析后的 ICAP REQMOD 响应：状态码、连接复用标志、封装载荷类型与共享头。
pub(crate) struct ReqmodResponse {
    pub(crate) code: u16,
    pub(crate) reason: String,
    pub(crate) keep_alive: bool,
    pub(crate) payload: IcapReqmodResponsePayload,
    shared_headers: HttpHeaderMap,
}

impl ReqmodResponse {
    /// 构造初始响应对象：keep_alive 默认为 true（ICAP/HTTP 连接默认可复用），
    /// payload 默认为 NoPayload（对应 204 No Content 等无 Encapsulated 头的响应）。
    fn new(code: u16, reason: String) -> Self {
        ReqmodResponse {
            code,
            reason,
            keep_alive: true,
            payload: IcapReqmodResponsePayload::NoPayload,
            shared_headers: HttpHeaderMap::default(),
        }
    }

    /// 取走（take）收集到的共享响应头，交给上层继续处理。
    pub(crate) fn take_shared_headers(&mut self) -> HttpHeaderMap {
        std::mem::take(&mut self.shared_headers)
    }

    /// Returns true if the ICAP response has a body that needs to be drained.
    /// 204 No Content and other NoPayload responses have no body.
    ///
    /// 判断响应是否携带需要读取/排空（drain）的 body：
    /// 只有 Encapsulated 解析出非 NoPayload 结果时才有封装的 HTTP 报文体。
    pub(crate) fn has_body(&self) -> bool {
        !matches!(self.payload, IcapReqmodResponsePayload::NoPayload)
    }

    /// 从 reader 逐行解析完整的 ICAP 响应头部。
    ///
    /// - `max_header_size`：整个头部块的字节上限，超限返回 TooLargeHeader；
    ///   每行读取时也用剩余配额做限制，防止对端发送超大头部；
    /// - `shared_names`：需要回传给调用方的响应头名白名单（小写形式）。
    ///
    /// 解析顺序：先读状态行，再循环读头部行直到遇到空行（"\r\n" 或 "\n"）。
    pub(crate) async fn parse<R>(
        reader: &mut R,
        max_header_size: usize,
        shared_names: &BTreeSet<String>,
    ) -> Result<ReqmodResponse, IcapReqmodParseError>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut line_buf = Vec::<u8>::with_capacity(1024);
        let mut header_size = 0;

        // 第一行：ICAP 状态行，例如 "ICAP/1.0 200 OK"
        let (found, nr) = reader
            .limited_read_until(b'\n', max_header_size, &mut line_buf)
            .await?;
        if nr == 0 {
            // 读到 EOF 且没有任何字节：连接被对端关闭
            return Err(IcapReqmodParseError::RemoteClosed);
        }
        if !found {
            // 未读到 '\n'：区分"连接中途断开（nr < 上限）"与"头部超长（nr == 上限）"
            return if nr < max_header_size {
                Err(IcapReqmodParseError::RemoteClosed)
            } else {
                Err(IcapReqmodParseError::TooLargeHeader(max_header_size))
            };
        }
        header_size += nr;
        let mut rsp = Self::build_from_status_line(&line_buf)?;

        // 循环解析头部行，直到空行结束
        loop {
            if header_size >= max_header_size {
                return Err(IcapReqmodParseError::TooLargeHeader(max_header_size));
            }
            line_buf.clear();
            // 每行的读取配额 = 总上限 - 已消费字节，保证头部总量不超限
            let max_len = max_header_size - header_size;
            let (found, nr) = reader
                .limited_read_until(b'\n', max_len, &mut line_buf)
                .await?;
            if nr == 0 {
                return Err(IcapReqmodParseError::RemoteClosed);
            }
            if !found {
                // 同状态行处的区分逻辑：提前断开 vs 超长
                return if nr < max_len {
                    Err(IcapReqmodParseError::RemoteClosed)
                } else {
                    Err(IcapReqmodParseError::TooLargeHeader(max_header_size))
                };
            }
            header_size += nr;
            // 空行（单独的 "\n" 或 "\r\n"）标记头部结束
            if (line_buf.len() == 1 && line_buf[0] == b'\n')
                || (line_buf.len() == 2 && line_buf[0] == b'\r' && line_buf[1] == b'\n')
            {
                // header end line
                break;
            }

            rsp.parse_header_line(&line_buf, shared_names)?;
        }

        Ok(rsp)
    }

    /// 解析状态行并生成初始响应对象（此时 keep_alive/payload 尚为默认值）。
    fn build_from_status_line(line_buf: &[u8]) -> Result<Self, IcapReqmodParseError> {
        let status =
            StatusLine::parse(line_buf).map_err(IcapReqmodParseError::InvalidStatusLine)?;

        let rsp = ReqmodResponse::new(status.code, status.message.to_string());
        Ok(rsp)
    }

    /// 解析单个头部行并更新到 self。
    ///
    /// 头部名统一转小写后匹配（大小写不敏感，符合 RFC 语义）：
    /// - `Connection`：逐值解析，"close" 关闭复用；"keep-alive" 保持默认；其它值忽略；
    /// - `Encapsulated`：委托 [`IcapReqmodResponsePayload::parse`] 解析载荷类型；
    /// - 其它头部名：若命中 `shared_names` 白名单，则收集进 shared_headers 回传给调用方。
    fn parse_header_line(
        &mut self,
        line: &[u8],
        shared_names: &BTreeSet<String>,
    ) -> Result<(), IcapReqmodParseError> {
        let header = HeaderLine::parse(line).map_err(IcapReqmodParseError::InvalidHeaderLine)?;

        match header.name.to_lowercase().as_str() {
            "connection" => {
                let value = header.value.to_lowercase();

                // Connection 可能是逗号分隔的多值列表，逐个判断
                for v in value.as_str().split(',') {
                    if v.is_empty() {
                        continue;
                    }

                    match v.trim() {
                        "keep-alive" => {
                            // keep the original value from request
                            // 默认即为 true，无需修改
                        }
                        "close" => {
                            // 对端要求关闭该 ICAP 连接，用完后不能放回连接池
                            self.keep_alive = false;
                        }
                        _ => {} // ignore other custom hop-by-hop headers
                    }
                }
            }
            "encapsulated" => self.payload = IcapReqmodResponsePayload::parse(header.value)?,
            header_name => {
                // 命中白名单的头部作为"共享头"回传：先校验其为合法的 HTTP 头部名/值
                if shared_names.contains(header_name) {
                    let name = HeaderName::from_str(header_name).map_err(|_| {
                        IcapReqmodParseError::InvalidHeaderLine(
                            IcapLineParseError::InvalidHeaderName,
                        )
                    })?;
                    let value = HttpHeaderValue::from_str(header.value).map_err(|_| {
                        IcapReqmodParseError::InvalidHeaderLine(
                            IcapLineParseError::InvalidHeaderValue,
                        )
                    })?;
                    self.shared_headers.append(name, value);
                }
            }
        }

        Ok(())
    }
}
