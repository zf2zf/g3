/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 服务配置：[`IcapServiceConfig`] 的构造、字段定义与请求头拼装。
//!
//! 关键语义：
//! - URL scheme 区分明文 `icap://` 与 `icaps://`（后者自动启用 rustls TLS 客户端）；
//! - URL 中可嵌入 Basic 鉴权信息（user:pass），解析后被剥离并存入 `auth` 字段，
//!   发送时以 `Authorization: Basic <base64>` 头携带；
//! - `tls_name`（SNI/证书校验名）默认取 URL host，亦可由 yaml `tls_name` 覆盖；
//! - `connection_pool` 决定 [`super::super::pool::IcapServicePool`] 行为：
//!   空闲上下限、idle 超时、周期检查间隔；
//! - `icap_max_header_size`：读取 ICAP 头时的上限，防止服务端异常导致 OOM；
//! - `disable_preview`：禁用 ICAP PREVIEW（100-continue）流程，直接发送完整消息；
//! - `preview_data_read_timeout`：PREVIEW 等待上层喂数据的超时，避免死锁；
//! - `respond_shared_names`：RESPMOD 响应中允许透传给客户端的扩展头白名单
//!   （如 `X-ICAP-Header`），不在名单内的扩展头会被丢弃；
//! - `bypass`：ICAP 服务故障时是否放行流量（true = 降级放行；false = 拒绝）。
//!
//! 请求头拼装：[`IcapServiceConfig::build_request_header`] 产出"请求头前缀"
//! （请求行 + Host + User-Agent + Authorization），上层协议适配器在此基础上
//! 追加各自扩展头与空行即可。

use std::collections::BTreeSet;
use std::io::Write;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use http::HeaderName;
use rustls_pki_types::ServerName;
use url::Url;

use g3_types::net::{
    ConnectionPoolConfig, HttpAuth, RustlsClientConfigBuilder, TcpKeepAliveConfig, UpstreamAddr,
};

#[cfg(feature = "yaml")]
mod yaml;

use super::IcapMethod;

/// ICAP 服务配置：被连接池、连接器与请求生成共享。
///
/// 设计上字段大多 `pub(crate)`，外部仅能通过 `set_*` 方法修改（保证校验语义），
/// `config/yaml.rs` 中的 yaml 解析器直接对字段赋值是 crate 内部特权。
pub struct IcapServiceConfig {
    pub(crate) method: IcapMethod,
    // 不含鉴权信息的 ICAP URL（请求行里使用，path 即服务名）。
    url: Url,
    // 从 URL  userinfo 解析出的 Basic 鉴权（或 None）。
    auth: HttpAuth,
    user_agent: Option<String>,
    // 上游地址（host + port），由 URL 派生；连接器据此解析对端 socket 地址。
    pub(crate) upstream: UpstreamAddr,
    // TLS 客户端配置 builder：scheme=icaps 时 Some，明文时 None。
    pub(crate) tls_client: Option<RustlsClientConfigBuilder>,
    // TLS SNI/证书校验名：默认取 URL host（见 IcapServiceConfig::new），
    // 也可通过 set_tls_name 覆盖（如 ICAP 走 LB 时）。
    pub(crate) tls_name: ServerName<'static>,
    pub(crate) connection_pool: ConnectionPoolConfig,
    pub(crate) tcp_keepalive: TcpKeepAliveConfig,
    #[cfg(unix)]
    pub(crate) use_unix_socket: Option<PathBuf>,
    // 是否启用 ICAP 206 (Use-after-Arrival 通知) 响应。
    pub(crate) icap_206_enable: bool,
    // 读取 ICAP 头（请求/响应/204/206）的最大字节数，超出即断开防 OOM。
    pub(crate) icap_max_header_size: usize,
    // 是否禁用 PREVIEW（短消息直接发完整内容，跳过 100-continue）。
    pub(crate) disable_preview: bool,
    // PREVIEW 阶段等待上层喂数据的超时：超时后回 204 释放连接。
    pub(crate) preview_data_read_timeout: Duration,
    // RESPMOD 响应扩展头白名单（小写归一）：命中才透传给 HTTP 客户端。
    pub(crate) respond_shared_names: BTreeSet<String>,
    // ICAP 服务故障时是否 bypass：true = 放行原流量，false = 报错拒接。
    pub(crate) bypass: bool,
}

impl IcapServiceConfig {
    /// 从 ICAP URL 构造配置。
    ///
    /// 处理流程：
    /// 1. 校验 scheme ∈ {`icap`, `icaps`}，`icaps` 启用默认 rustls 客户端；
    /// 2. 解析 URL 中的 userinfo 为 Basic 鉴权，并把 username/password 从 URL
    ///    中清空（避免后续 `url` 字段被请求行泄露）；
    /// 3. 派生 upstream 地址、tls_name（默认取 host）。
    pub fn new(method: IcapMethod, mut url: Url) -> anyhow::Result<Self> {
        let tls_client = match url.scheme().to_ascii_lowercase().as_str() {
            "icap" => None,
            "icaps" => Some(RustlsClientConfigBuilder::default()),
            _ => return Err(anyhow!("unsupported ICAP URL scheme: {}", url.scheme())),
        };

        if !url.has_authority() {
            return Err(anyhow!("no authority part found in this url"));
        }
        let auth = HttpAuth::try_from(&url).map_err(|e| anyhow!("invalid auth info: {e}"))?;
        url.set_username("")
            .map_err(|_| anyhow!("failed to clear username in url"))?;
        url.set_password(None)
            .map_err(|_| anyhow!("failed to clear password in url"))?;

        let upstream = UpstreamAddr::try_from(&url)
            .map_err(|e| anyhow!("failed to get upstream address from url: {e}"))?;
        let tls_name = ServerName::try_from(upstream.host())
            .map_err(|e| anyhow!("invalid ICAP server name: {e}"))?;
        Ok(IcapServiceConfig {
            method,
            url,
            auth,
            user_agent: None,
            upstream,
            tls_client,
            tls_name,
            connection_pool: ConnectionPoolConfig::default(),
            tcp_keepalive: TcpKeepAliveConfig::default_enabled(),
            #[cfg(unix)]
            use_unix_socket: None,
            icap_206_enable: false,
            icap_max_header_size: 8192,
            disable_preview: false,
            preview_data_read_timeout: Duration::from_secs(4),
            respond_shared_names: BTreeSet::new(),
            bypass: false,
        })
    }

    /// 覆盖默认 TCP keepalive 配置（用于探测半开连接）。
    pub fn set_tcp_keepalive(&mut self, config: TcpKeepAliveConfig) {
        self.tcp_keepalive = config;
    }

    /// 替换 rustls TLS 客户端配置（会话缓存、CA 等）。
    pub fn set_tls_client(&mut self, config: RustlsClientConfigBuilder) {
        self.tls_client = Some(config);
    }

    /// 显式覆盖 TLS ServerName（SNI/证书校验名），常用于走 LB/CDN 的场景。
    pub fn set_tls_name(&mut self, name: ServerName<'static>) {
        self.tls_name = name;
    }

    /// 设置 ICAP 头读取上限（防 OOM）。
    pub fn set_icap_max_header_size(&mut self, max_size: usize) {
        self.icap_max_header_size = max_size;
    }

    /// 设置 PREVIEW 等待业务数据的超时。
    pub fn set_preview_data_read_timeout(&mut self, time: Duration) {
        self.preview_data_read_timeout = time;
    }

    /// 故障 bypass 开关：true = ICAP 不可用时放行；false = 拒绝。
    pub fn set_bypass(&mut self, bypass: bool) {
        self.bypass = bypass;
    }

    /// 向 RESPMOD 响应头白名单中添加一项；内部以小写字符串存储。
    pub fn add_respond_shared_name(&mut self, name: HeaderName) {
        self.respond_shared_names.insert(name.as_str().to_string());
    }

    /// 生成"可复用的请求头前缀"：请求行 + Host + User-Agent + Authorization。
    ///
    /// REQMOD/RESPMOD 协议适配器拿到该前缀后，只需追加各自的扩展头 + `\r\n`
    /// 空行结尾即可发送，避免每次请求重复拼装静态部分。
    pub(crate) fn build_request_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(1024);
        self.write_header(&mut header, self.method.as_str());
        header
    }

    /// 生成 OPTIONS 请求的固定头部（OPTIONS 与 REQMOD/RESPMOD 共用 write_header，
    /// 仅 method 字段不同）。
    pub(crate) fn build_options_request(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(256);
        self.write_header(&mut header, "OPTIONS");
        header
    }

    /// 真正的头部拼装实现：写入 `{method} {url} ICAP/1.0` 请求行 + 鉴权等通用头。
    fn write_header(&self, header: &mut Vec<u8>, method: &str) {
        let _ = write!(header, "{method} {} ICAP/1.0\r\n", self.url);
        if let Some(host) = self.url.host_str() {
            let _ = write!(header, "Host: {host}\r\n");
        }
        if let Some(user_agent) = &self.user_agent {
            let _ = write!(header, "User-Agent: {user_agent}\r\n");
        }
        match &self.auth {
            HttpAuth::None => {}
            HttpAuth::Basic(basic_auth) => {
                let _ = write!(
                    header,
                    "Authorization: Basic {}\r\n",
                    basic_auth.encoded_value()
                );
            }
        }
    }
}
