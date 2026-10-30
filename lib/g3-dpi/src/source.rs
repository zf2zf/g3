/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 首包数据的来源方向。
//!
//! 协议识别依赖“谁先说话”：很多文本协议（FTP / SMTP / POP3 / IMAP / NNTP / NATS）
//! 是服务端先发 greeting，而 HTTP / SSH 客户端 / MQTT 等是客户端先发请求。
//! 同一份字节放在不同方向上会得出完全不同的结论，因此探测器必须按方向分组调用。

/// 一条连接上某批首包数据来自哪一方。
pub enum Source {
    /// 客户端主动发出的数据：请求行、协议版本协商、TLS ClientHello 等。
    Client,
    /// 服务端先返回的数据：greeting / banner / INFO 消息等。
    Server,
}
