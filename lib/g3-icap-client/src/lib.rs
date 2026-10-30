/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! g3-icap-client：ICAP（RFC 3507）客户端库的 crate 根。
//!
//! 本 crate 把 g3proxy 采集到的流量（HTTP 请求/响应、SMTP 邮件、IMAP APPEND、
//! FTP 上传、TLS keylog 等）按 ICAP 线格式封装上报给远端 ICAP 检测/审计服务，
//! 并解析其处置结果（204 放行 / 200 改写或替代响应 / 100 continue 配合 preview）。
//!
//! 模块划分：
//! - `serialize`：ICAP 请求头各扩展字段（X-Client-IP、X-Transformed-From 等）的拼装；
//! - `parse`：ICAP 响应状态行/头部行的零拷贝解析；
//! - `options`：OPTIONS 请求发送与服务能力（Preview/Allow/ISTag/Options-TTL）解析；
//! - `reqmod` / `respmod`：请求修改与响应修改两类核心业务的上报与结果处理；
//! - `reason`：统一的 ICAP 错误原因枚举 `IcapErrorReason`；
//! - `service`：连接池、连接管理与面向外部服务的客户端配置（`IcapServiceConfig`）。
//!
//! 对外主要导出：`reqmod`、`respmod` 子模块以及 `IcapServiceOptions`、
//! `IcapMethod`、`IcapServiceClient`、`IcapServiceConfig`。

mod parse;
mod reason;
mod serialize;

pub mod reqmod;

pub mod respmod;

mod options;
pub use options::IcapServiceOptions;

mod service;

use service::{IcapClientConnection, IcapClientReader, IcapClientWriter};
pub use service::{IcapMethod, IcapServiceClient, IcapServiceConfig};
