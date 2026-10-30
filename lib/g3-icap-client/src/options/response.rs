/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP OPTIONS 响应的解析与能力缓存结构 `IcapServiceOptions`。
//!
//! 逐行读取响应头（限长防滥用），提取 reqmod/respmod 上报流程所需的能力信息：
//! - Preview：服务端愿意接收的预览字节数（决定请求 body 是否先截断发送）；
//! - Allow：服务端支持的处置码（204 直接放行 / 206 允许仅对 preview 做处置）；
//! - ISTag：服务实例标识，后续每个 ICAP 请求须原样回传，防止会话打到重启/切换
//!   后的不同服务实例上（必需字段，缺失即 `check()` 报错）；
//! - Options-TTL：本份结果的有效期（秒），到期后连接池会重新发起 OPTIONS。

use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use tokio::io::AsyncBufRead;
use tokio::time::Instant;

use g3_io_ext::LimitedBufReadExt;

use super::IcapOptionsParseError;
use crate::IcapMethod;
use crate::parse::{HeaderLine, StatusLine};

/// 一次 OPTIONS 探测得到的 ICAP 服务能力，带 TTL 缓存语义（见 `expired`）。
pub struct IcapServiceOptions {
    method: IcapMethod,
    server: Option<String>,
    service_tag: String,
    service_id: Option<String>,
    max_connections: Option<usize>,
    expire: Option<Instant>,
    pub(crate) support_204: bool,
    pub(crate) support_206: bool,
    pub(crate) preview_size: Option<usize>,
}

impl IcapServiceOptions {
    fn new(method: IcapMethod) -> Self {
        IcapServiceOptions {
            method,
            server: None,
            service_tag: String::new(),
            service_id: None,
            max_connections: None,
            expire: None,
            support_204: false,
            support_206: false,
            preview_size: None,
        }
    }

    /// 构造一个"已过期"的占位能力项：expire 设为当前时刻，使 `expired()` 立即
    /// 为真，逼迫连接池在下一次使用前重新执行 OPTIONS 探测。
    pub(crate) fn new_expired(method: IcapMethod) -> Self {
        IcapServiceOptions {
            method,
            server: None,
            service_tag: String::new(),
            service_id: None,
            max_connections: None,
            expire: Some(Instant::now()),
            support_204: false,
            support_206: false,
            preview_size: None,
        }
    }

    /// Options-TTL 推导出的到期时间是否已过；未设置 expire（服务未返回 TTL）视为永不过期。
    pub(crate) fn expired(&self) -> bool {
        if let Some(expire) = self.expire {
            Instant::now() >= expire
        } else {
            false
        }
    }

    /// 从 reader 读取并解析完整的 OPTIONS 响应头：状态行 + 若干头部行 + 空行。
    ///
    /// 所有读取都受 `max_header_size` 累计限长约束：单行未读到 '\n' 且已达上限
    /// 判为超大头部；未达上限却读到 EOF 则判为远端提前关闭。解析完成后调用
    /// `check()` 校验必需字段（ISTag）。
    pub(crate) async fn parse<R>(
        reader: &mut R,
        method: IcapMethod,
        max_header_size: usize,
    ) -> Result<IcapServiceOptions, IcapOptionsParseError>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut options = IcapServiceOptions::new(method);

        let mut line_buf = Vec::<u8>::with_capacity(1024);
        let mut header_size = 0;

        // 第一行：ICAP 状态行
        let (found, nr) = reader
            .limited_read_until(b'\n', max_header_size, &mut line_buf)
            .await?;
        if nr == 0 {
            return Err(IcapOptionsParseError::RemoteClosed);
        }
        if !found {
            // 没读到 '\n'：没吃满配额说明对端提前 EOF，吃满则头部超大
            return if nr < max_header_size {
                Err(IcapOptionsParseError::RemoteClosed)
            } else {
                Err(IcapOptionsParseError::TooLargeHeader(max_header_size))
            };
        }
        header_size += nr;
        options.parse_status_line(&line_buf)?;

        // 后续各头部行，直到空行（"\n" 或 "\r\n"）为止
        loop {
            if header_size >= max_header_size {
                return Err(IcapOptionsParseError::TooLargeHeader(max_header_size));
            }
            line_buf.clear();
            // 本行最多还能读的量 = 总配额剩余，保证整组头部不超限
            let max_len = max_header_size - header_size;
            let (found, nr) = reader
                .limited_read_until(b'\n', max_len, &mut line_buf)
                .await?;
            if nr == 0 {
                return Err(IcapOptionsParseError::RemoteClosed);
            }
            if !found {
                return if nr < max_len {
                    Err(IcapOptionsParseError::RemoteClosed)
                } else {
                    Err(IcapOptionsParseError::TooLargeHeader(max_header_size))
                };
            }
            header_size += nr;
            if (line_buf.len() == 1 && line_buf[0] == b'\n')
                || (line_buf.len() == 2 && line_buf[0] == b'\r' && line_buf[1] == b'\n')
            {
                // header end line
                break;
            }

            options.parse_header_line(&line_buf)?;
        }
        options.check()?;

        Ok(options)
    }

    /// 解析后的一致性校验：ISTag 为必需头（每个后续请求都要回显它）。
    fn check(&self) -> Result<(), IcapOptionsParseError> {
        if self.service_tag.is_empty() {
            return Err(IcapOptionsParseError::NoServiceTagSet);
        }
        Ok(())
    }

    /// 状态行须为 2xx（200..300），否则视为服务侧明确失败。
    fn parse_status_line(&mut self, line: &[u8]) -> Result<(), IcapOptionsParseError> {
        let status = StatusLine::parse(line).map_err(IcapOptionsParseError::InvalidStatusLine)?;

        if status.code < 200 || status.code >= 300 {
            return Err(IcapOptionsParseError::RequestFailed(
                status.code,
                status.message.to_string(),
            ));
        }

        Ok(())
    }

    /// 解析单条头部行并合并进 self。
    ///
    /// 头部名先 to_lowercase 再匹配，实现不区分大小写处理；未知头部直接忽略。
    /// 关键头：
    /// - Methods：确认服务支持本配置的方法，否则 MethodNotMatch；
    /// - ISTag / Service / Service-Id / Max-Connections：服务信息；
    /// - Allow：记录支持的 204/206；
    /// - Preview：预览字节上限；
    /// - Options-TTL：换算为绝对到期时刻存入 expire；
    /// - Opt-Body-Type：本客户端不支持带 opt-body，直接报 UnsupportedBody。
    fn parse_header_line(&mut self, line: &[u8]) -> Result<(), IcapOptionsParseError> {
        let header = HeaderLine::parse(line).map_err(IcapOptionsParseError::InvalidHeaderLine)?;

        match header.name.to_lowercase().as_str() {
            "methods" => {
                // 逗号分隔的方法列表中必须包含本服务配置的方法
                for v in header.value.split(',') {
                    if self.method.as_str() == v.trim() {
                        return Ok(());
                    }
                }
                return Err(IcapOptionsParseError::MethodNotMatch);
            }
            "service" => self.server = Some(header.value.to_string()),
            "istag" => self.service_tag = header.value.to_string(),
            "encapsulated" => {
                // OPTIONS 响应只允许 null-body / opt-body 两种封装声明，值本身此处不消费
                for p in header.value.split(',') {
                    let Some((name, _value)) = p.trim().split_once('=') else {
                        return Err(IcapOptionsParseError::InvalidHeaderValue("Encapsulated"));
                    };
                    match name.to_lowercase().as_str() {
                        "null-body" => {}
                        "opt-body" => {}
                        _ => return Err(IcapOptionsParseError::InvalidHeaderValue("Encapsulated")),
                    }
                }
            }
            "opt-body-type" => {
                // 服务声明要返回 opt-body（本客户端不解析该 body），视为不支持
                return Err(IcapOptionsParseError::UnsupportedBody(
                    header.value.to_string(),
                ));
            }
            "max-connections" => {
                let max_connections = usize::from_str(header.value)
                    .map_err(|_| IcapOptionsParseError::InvalidHeaderValue("Max-Connections"))?;
                self.max_connections = Some(max_connections);
            }
            "options-ttl" => {
                // TTL 单位是秒：以"收到响应的当下"为基准换算成绝对到期时刻
                let ttl = usize::from_str(header.value)
                    .map_err(|_| IcapOptionsParseError::InvalidHeaderValue("Options-TTL"))?;
                let expire = Instant::now().add(Duration::from_secs(ttl as u64));
                self.expire = Some(expire);
            }
            "service-id" => self.service_id = Some(header.value.to_string()),
            "allow" => {
                // 逗号分隔的处置码列表，只关心 204（完整响应处置）与 206（preview 处置）
                for p in header.value.split(',') {
                    let code = u16::from_str(p.trim())
                        .map_err(|_| IcapOptionsParseError::InvalidHeaderValue("Allow"))?;
                    match code {
                        204 => self.support_204 = true,
                        206 => self.support_206 = true,
                        _ => {}
                    }
                }
            }
            "preview" => {
                // 服务端期望的 preview 字节数；后续 reqmod 上报时先发这么多再等 100-continue
                let size = usize::from_str(header.value)
                    .map_err(|_| IcapOptionsParseError::InvalidHeaderValue("Preview"))?;
                self.preview_size = Some(size);
            }
            _ => {}
        }

        Ok(())
    }
}
