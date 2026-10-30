/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP RESPMOD（响应修改/上报）公共层。
//!
//! 与 `reqmod` 对称：`reqmod` 审计"请求方向"的数据，RESPMOD 则把
//! 发回客户端的 HTTP 响应（状态行 + 头 + 体）用 `Encapsulated:
//! res-hdr=0, res-body=N` 封装进 ICAP 消息送给服务器。本模块提供
//! 与协议版本无关的公共部分：
//! - `error`：响应解析错误；
//! - `payload`：`Encapsulated` 头（封装布局）解析；
//! - `response`：ICAP 响应状态行 + 头 + 共享头回传的解析；
//! - `h1` / `h2`：分别针对 HTTP/1.x 与 HTTP/2 响应的具体适配器。

use std::sync::Arc;

use crate::IcapServiceClient;

mod error;
pub use error::IcapRespmodParseError;

mod payload;
pub use payload::IcapRespmodResponsePayload;

mod response;

pub mod h1;
pub mod h2;

/// RESPMOD 客户端句柄：对共享的 `IcapServiceClient`（连接池 + 配置）
/// 的轻量包装，用 `Arc` 克隆即可在多个响应流之间低成本传递。
#[derive(Clone)]
pub struct IcapRespmodClient {
    inner: Arc<IcapServiceClient>,
}

impl IcapRespmodClient {
    /// 从已有的服务客户端实例（含连接池）构造 RESPMOD 句柄。
    pub fn new(inner: Arc<IcapServiceClient>) -> IcapRespmodClient {
        IcapRespmodClient { inner }
    }

    /// 配置是否开启 bypass：为 true 时上层直接放行响应、
    /// 完全跳过 RESPMOD 上报（用于临时下线审计服务的场景）。
    pub fn bypass(&self) -> bool {
        self.inner.config.bypass
    }
}
