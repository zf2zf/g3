/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP 协议拦截的模块出口。
//!
//! 按版本拆分为两套互相独立的检测实现：
//! - [`v1::H1InterceptObject`]：HTTP/1.1，一条连接同一时刻只有一个请求，
//!   状态机围绕请求行/头、CONNECT 隧道、Upgrade 切换与转发展开。
//! - [`v2::H2InterceptObject`]：HTTP/2，连接上复用多个逻辑流，额外处理帧、
//!   PING 保活与扩展 CONNECT。
//!
//! 两者的错误类型统一向上归并为 `InterceptionError`。

mod v2;
pub(super) use v2::{H2InterceptObject, H2InterceptionError};

mod v1;
pub(crate) use v1::H1InterceptObject;
pub(super) use v1::H1InterceptionError;
