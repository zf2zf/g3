/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 请求头序列化：把代理侧掌握的连接/用户/共享头等信息以字节形式追加到
//! 待发送的 ICAP 头部缓冲区（见 `header` 子模块的具体 `add_*` 函数）。
//! 所有函数直接写入 `Vec<u8>`，线格式为 "Name: value\r\n"。

mod header;
pub(crate) use header::*;
