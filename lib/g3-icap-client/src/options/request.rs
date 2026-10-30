/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 构造并发送 ICAP OPTIONS 请求，然后交给 `IcapServiceOptions::parse` 读取响应。
//! OPTIONS 请求没有封装 body，头部以 Allow（声明本代理是否接受 206 部分响应）+
//! 空行结束即可。

use std::io;

use bytes::BufMut;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{IcapOptionsParseError, IcapServiceOptions};
use crate::{IcapClientConnection, IcapServiceConfig};

/// 一次 OPTIONS 能力探测请求（借用服务配置，可反复用于同一连接的探活）。
pub(crate) struct IcapOptionsRequest<'a> {
    config: &'a IcapServiceConfig,
}

impl<'a> IcapOptionsRequest<'a> {
    pub(crate) fn new(config: &'a IcapServiceConfig) -> Self {
        IcapOptionsRequest { config }
    }

    /// 写出 "OPTIONS <url> ICAP/1.0" 请求行 + 基础头 + Allow 头 + 空行。
    /// Allow 声明本客户端能接受的处置码：配置允许 206 时同时声明支持部分响应。
    async fn send<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut header = self.config.build_options_request();
        if self.config.icap_206_enable {
            header.put_slice(b"Allow: 204, 206\r\n");
        } else {
            header.put_slice(b"Allow: 204\r\n");
        }
        // 空行结束头部（OPTIONS 无封装 body）
        header.put_slice(b"\r\n");

        writer.write_all(&header).await
    }

    /// 在给定连接上执行一次 OPTIONS 探测：发送请求 -> 解析响应头（受
    /// `max_header_size` 限长保护）-> 返回服务能力 `IcapServiceOptions`。
    ///
    /// 若本代理配置未开启 206，则强制清除服务端声明的 support_206，
    /// 保证后续 preview 截断逻辑与本地配置一致。
    pub(crate) async fn get_options(
        &self,
        conn: &mut IcapClientConnection,
        max_header_size: usize,
    ) -> Result<IcapServiceOptions, IcapOptionsParseError> {
        self.send(&mut conn.writer)
            .await
            .map_err(IcapOptionsParseError::IoFailed)?;
        conn.mark_writer_finished();

        let mut options =
            IcapServiceOptions::parse(&mut conn.reader, self.config.method, max_header_size)
                .await?;
        conn.mark_reader_finished();

        // 本地未启用 206 时忽略服务端的 206 能力（取交集语义）
        if !self.config.icap_206_enable {
            options.support_206 = false;
        }
        Ok(options)
    }
}
