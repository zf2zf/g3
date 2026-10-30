/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 单个 H2 逻辑流的入口分发器。
//!
//! 连接级状态机（`super::H2InterceptObject`）每接受一个客户端流，就把
//! 请求头与两侧流句柄交给 [`transfer`]：CONNECT 类请求分发给
//! [`H2ConnectTask`]（标准 CONNECT）或 [`H2ExtendedConnectTask`]（带
//! `:protocol` 伪头的扩展 CONNECT），其余普通方法交给 [`H2ForwardTask`]
//! 做请求/响应双向转发。

use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use h2::RecvStream;
use h2::client::SendRequest;
use h2::ext::Protocol;
use h2::server::SendResponse;
use http::{Method, Request};

use g3_types::net::{HttpUpgradeToken, TlsKeyLogBuffer};

use super::{H2ConnectTask, H2ExtendedConnectTask, H2ForwardTask};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;

/// 处理一条客户端逻辑流：按伪头/请求头选择 CONNECT、扩展 CONNECT 或
/// 普通方法转发任务。本函数是流的唯一执行体，返回即代表该流结束。
pub(super) async fn transfer<SC>(
    mut clt_req: Request<RecvStream>,
    clt_send_rsp: SendResponse<Bytes>,
    h2s: SendRequest<Bytes>,
    ctx: StreamInspectContext<SC>,
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
) where
    SC: ServerConfig + Send + Sync + 'static,
{
    // 按配置剥离客户端伪造的转发头，防止内部拓扑经 X-Forwarded-For 泄露
    if ctx.h1_interception().steal_forwarded_for {
        clt_req.headers_mut().remove(http::header::FORWARDED);
        clt_req.headers_mut().remove("x-forwarded-for");
    }
    let clt_stream_id = clt_send_rsp.stream_id();
    if clt_req.method().eq(&Method::CONNECT) {
        // 扩展 CONNECT（RFC 8441/9220 等）：请求携带 :protocol 伪头，
        // h2 crate 会将其解析为 extensions 中的 Protocol，据此映射升级协议
        if let Some(protocol) = clt_req.extensions().get::<Protocol>() {
            let upgrade_protocol = HttpUpgradeToken::from_str(protocol.as_str())
                .unwrap_or_else(|_e| HttpUpgradeToken::Unsupported(protocol.as_str().to_string()));

            let connect_task = H2ExtendedConnectTask::new(ctx, clt_stream_id, upgrade_protocol);
            connect_task.into_running(clt_req, clt_send_rsp, h2s).await;
        } else {
            // 标准 CONNECT：隧道建立后按 TCP 字节流处理
            let connect_task = H2ConnectTask::new(ctx, clt_stream_id);
            connect_task.into_running(clt_req, clt_send_rsp, h2s).await
        };
    } else {
        let forward_task = H2ForwardTask::new(ctx, clt_stream_id, &clt_req, keylog_buffer);
        forward_task.forward(clt_req, clt_send_rsp, h2s).await
    }
}
