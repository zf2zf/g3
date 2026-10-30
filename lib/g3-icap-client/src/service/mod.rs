/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 服务子模块：负责与单个远端 ICAP 服务交互的全部逻辑。
//!
//! 关键类型：
//! - [`IcapServiceConfig`]（`config` 子模块）：服务配置（URL/鉴权/TLS/连接池/预览等）。
//! - [`IcapServiceClient`]（`client` 子模块）：对外唯一出口，负责取/还连接。
//! - [`IcapClientConnection`]（`connection` 子模块）：单条连接的读写端封装。
//! - [`IcapServicePool`]（`pool` 子模块）：后台连接池任务，维护空闲连接。
//!
//! 连接生命周期：
//! 1. 首次使用或池空时，由 `IcapConnector::create()` 新建 TCP/TLS 连接；
//! 2. 新建的连接会立即发送 OPTIONS 请求，获取服务能力（`IcapServiceOptions`）；
//! 3. 使用完毕且读写均干净的连接通过 `SaveConnection` 命令回池，交由
//!    `IcapConnectionEofPoller` 后台探测（EOF / 空闲超时 / 被再次取走）；
//! 4. 空闲连接被 EOF、超时或被取用后，池会根据 min_idle_count 补足连接；
//!    OPTIONS 结果过期时，池会主动新建连接刷新服务能力。

mod config;
pub use config::IcapServiceConfig;

mod connection;
pub(super) use connection::{IcapClientConnection, IcapClientReader, IcapClientWriter};
use connection::{IcapConnectionEofPoller, IcapConnectionPollRequest, IcapConnector};

mod client;
pub use client::IcapServiceClient;

mod pool;
use pool::{IcapServiceClientCommand, IcapServicePool};

/// ICAP 协议定义的方法（RFC 3507）。
///
/// - `Options`：查询服务能力，用于探活与获取 Allow 列表；
/// - `Reqmod`：对 HTTP 请求做修改/拦截；
/// - `Respmod`：对 HTTP 响应做修改/拦截。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcapMethod {
    Options,
    Reqmod,
    Respmod,
}

impl IcapMethod {
    /// 返回协议线上使用的字符串形式（用于拼装请求行）。
    pub fn as_str(&self) -> &'static str {
        match self {
            IcapMethod::Options => "OPTIONS",
            IcapMethod::Reqmod => "REQMOD",
            IcapMethod::Respmod => "RESPMOD",
        }
    }
}
