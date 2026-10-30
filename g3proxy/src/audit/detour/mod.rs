/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::sync::oneshot;

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::Protocol;
use g3_io_ext::IdleWheel;
use g3_types::net::UpstreamAddr;

use crate::config::audit::AuditStreamDetourConfig;
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectTaskNotes;

// QUIC 引流检测（stream detour）：
// 代理不把内容交给内置规则判断，而是把连接信息（PPv2 头 + 附加数据）和后续双向流量转给外部检测服务，
// 由服务返回裁决（继续代理 / 旁路直连 / 阻断）。
// 与检测服务之间用一条 QUIC 长连接承载多个任务的流，靠连接池复用，避免每任务一次握手。
//
// 一次任务的调用顺序（见 inspect/ 下各协议的 interception 分支）：
//   open_detour_stream()  -> 从池里取一对 QUIC 双向流
//   build_context()       -> 组装本次检测的上下文（服务器配置、任务信息、上游与协议）
//   check_detour_action() -> 发送 PPv2 头 + payload，读取裁决
//   裁决为 Continue 时 relay() 双向搬运流量；Bypass/Block 时 finish() 归还流

mod connect; // QUIC 连接建立与单连接上的流分配
use connect::{StreamDetourConnector, StreamDetourRequest};

mod pool; // 连接池后台任务：维持空闲连接、按需扩容
use pool::{StreamDetourPool, StreamDetourPoolHandle};

mod stream; // 单个任务的流量中继与裁决协议编解码
use stream::StreamDetourStream;

/// 外部检测服务对一条连接的裁决。
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum DetourAction {
    Continue, // 检测通过：流量继续经代理中继到上游
    Bypass,   // 不再检查：断开检测流，由调用方直连放行
    Block,    // 拒绝：由调用方返回阻断错误
}

impl From<u16> for DetourAction {
    /// 服务返回 0/1 以外的值一律按最严格的 Block 处理。
    fn from(value: u16) -> Self {
        match value {
            0 => DetourAction::Continue,
            1 => DetourAction::Bypass,
            _ => DetourAction::Block,
        }
    }
}

/// 一次引流检测所需的上下文：借用任务侧的只读信息，并持有待发送的预览数据。
///
/// 生命周期与单个任务一致，`relay` 和 `check_detour_action` 都以 self 消费/借用它，
/// 因此可以在取到裁决后继续用于中继阶段。
pub(crate) struct StreamDetourContext<'a, SC> {
    server_config: &'a Arc<SC>, // 服务器配置：取限速用的 copy 配置、任务空闲上限
    server_quit_policy: &'a Arc<ServerQuitPolicy>, // 服务下线状态，中继时用于优雅退出
    idle_wheel: &'a Arc<IdleWheel>, // 全局空闲计时轮，注册后按周期检查空闲
    task_notes: &'a StreamInspectTaskNotes, // 任务信息：客户端/服务端地址、用户名、任务 ID
    upstream: &'a UpstreamAddr, // 目标上游地址，随 PPv2 头告知检测服务
    protocol: Protocol,         // 被检测的协议类型
    payload: Vec<u8>, // 随检测请求附加发送的数据，由各协议自行序列化（如 websocket 的握手信息），可为空
    request_timeout: Duration, // 等待检测服务返回裁决的超时
    max_idle_count: usize, // 允许的空闲周期数，超过即判定任务空闲超时
}

impl<SC> StreamDetourContext<'_, SC> {
    /// 填入附加数据：检测服务在裁决时除 PPv2 头外还会读到这段内容。
    pub(crate) fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }
}

/// 引流服务的客户端：向连接池投递"给我一个可用流"的请求。
///
/// 每个 auditor 节点一个实例（Arc 共享给该节点下所有服务器与任务）。
pub(crate) struct StreamDetourClient {
    config: Arc<AuditStreamDetourConfig>,
    req_sender: kanal::AsyncSender<StreamDetourRequest>, // 多生产者队列，各任务并发投递请求
    pool_handle: StreamDetourPoolHandle,                 // 用于提示池提前建连
}

impl StreamDetourClient {
    /// 创建客户端并 spawn 其连接池后台任务。
    pub(super) fn new(config: Arc<AuditStreamDetourConfig>) -> anyhow::Result<Self> {
        let (req_sender, req_receiver) = kanal::unbounded_async();
        let connector = StreamDetourConnector::new(config.clone())?;
        let pool_handle =
            StreamDetourPool::spawn(config.connection_pool, req_receiver, Arc::new(connector));
        Ok(StreamDetourClient {
            config,
            req_sender,
            pool_handle,
        })
    }

    /// 为一次任务组装检测上下文：从任务侧借用只读信息，并从服务器/用户配置解析空闲上限。
    pub(crate) fn build_context<'a, SC>(
        &self,
        server_config: &'a Arc<SC>,
        server_quit_policy: &'a Arc<ServerQuitPolicy>,
        idle_wheel: &'a Arc<IdleWheel>,
        task_notes: &'a StreamInspectTaskNotes,
        upstream: &'a UpstreamAddr,
        protocol: Protocol,
    ) -> StreamDetourContext<'a, SC>
    where
        SC: ServerConfig,
    {
        // 用户站点可覆盖任务空闲上限，未覆盖时回落到服务器配置
        let max_idle_count = task_notes
            .user()
            .and_then(|u| u.task_max_idle_count())
            .unwrap_or(server_config.task_max_idle_count());
        StreamDetourContext {
            server_config,
            server_quit_policy,
            idle_wheel,
            task_notes,
            upstream,
            protocol,
            payload: Vec::new(),
            request_timeout: self.config.request_timeout,
            max_idle_count,
        }
    }

    /// 向连接池申请一条可用的引流流（一对 QUIC 双向流）。
    ///
    /// 请求通过 channel 投递给池任务，池内某条连接取走后用 oneshot 回送流；
    /// 等待超过 stream_open_timeout 即认为申请失败，任务按内部错误处理。
    pub(crate) async fn open_detour_stream(&self) -> anyhow::Result<StreamDetourStream> {
        let (sender, receiver) = oneshot::channel();
        let req = StreamDetourRequest(sender);

        // 请求排队拥挤时提示连接池提前建立新连接
        if self.req_sender.is_full() {
            self.pool_handle.request_new_connection();
        }
        if self.req_sender.send(req).await.is_err() {
            return Err(anyhow!("stream detour client is down"));
        }

        match tokio::time::timeout(self.config.stream_open_timeout, receiver).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(anyhow!("failed to open detour stream: {e}")),
            Err(_) => Err(anyhow!("timed out to open detour stream")),
        }
    }
}
