/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP OPTIONS 请求的发送与响应解析（能力探测）。
//!
//! 连接建立/空闲时向 ICAP 服务发送 OPTIONS 请求，解析响应中的能力信息：
//! Preview 大小、Allow 支持的 204/206、ISTag（服务标识，须回显在后续请求中）、
//! Options-TTL（结果缓存有效期，据此判断 `IcapServiceOptions` 是否过期）。
//!
//! - `request`：拼装并发送 OPTIONS 请求，得到解析后的服务能力；
//! - `response`：`IcapServiceOptions` 及响应头逐行解析；
//! - `error`：`IcapOptionsParseError` 解析错误枚举。

mod error;
pub(crate) use error::IcapOptionsParseError;

mod response;
pub use response::IcapServiceOptions;

mod request;
pub(crate) use request::IcapOptionsRequest;
