/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应行的零拷贝解析：把整行字节切成借用的 &str 片段，不做内存分配拷贝。
//!
//! - `StatusLine`：解析 "ICAP/1.0 <code> <reason>" 状态行；
//! - `HeaderLine`：按第一个 ':' 拆分头部名与值（值做 trim，因此天然容错行尾的
//!   \r\n，也支持非 ASCII 的头部名/值）；头部名比较由调用方按不区分大小写
//!   （如 to_lowercase / eq_ignore_ascii_case）进行；
//! - `IcapLineParseError`：单行解析失败的统一错误类型。
//!
//! 被 `options`（OPTIONS 响应）与 `reqmod`/`respmod`（业务响应）模块复用。

mod error;
pub use error::IcapLineParseError;

mod header_line;
pub(crate) use header_line::HeaderLine;

mod status_line;
pub(crate) use status_line::StatusLine;
