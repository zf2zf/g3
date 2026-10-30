/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 拦截（拆解重组）配置。
//!
//! 与识别无关（识别只看服务端 `* OK` greeting）；这里控制代理接管 IMAP 会话后
//! 各阶段的超时、单行长度上限，以及两个空闲计数阈值。
//!
//! 用**计数**而不是时长做空闲判定，是因为 IMAP 的 `IDLE` 会让连接长时间合法静默：
//! 靠超时无法区分“客户端在 IDLE”和“客户端已消失”，只能按空闲周期累加、超阈值回收。

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImapInterceptionConfig {
    /// 等待服务端 greeting（`* OK ...`）的超时。
    pub greeting_timeout: Duration,
    /// 等待客户端完成认证（LOGIN / AUTHENTICATE 交换）的超时。
    pub authenticate_timeout: Duration,
    /// 发出 LOGOUT 后等待服务端确认的超时；明显短于其他超时，
    /// 因为退出阶段不该让会话挂着不放。
    pub logout_wait_timeout: Duration,
    /// 客户端命令单行字节上限。
    pub command_line_max_size: usize,
    /// 服务端响应单行字节上限。
    pub response_line_max_size: usize,
    /// 命令中继阶段的空闲周期上限：连续这么多周期两个方向都没流量，
    /// 就回 `BYE` 并以本机主动断开结束会话。
    /// `IDLE` 期间同样受这个计数约束。
    pub forward_max_idle_count: usize,
    /// 正文搬运阶段（`FETCH` / 上行大段数据）的空闲周期上限。
    /// 比 [`ImapInterceptionConfig::forward_max_idle_count`] 小得多，
    /// 因为一旦进入批量数据传输，静默就意味着链路真的停了。
    pub transfer_max_idle_count: usize,
}

impl Default for ImapInterceptionConfig {
    fn default() -> Self {
        ImapInterceptionConfig {
            greeting_timeout: Duration::from_secs(300),
            authenticate_timeout: Duration::from_secs(300),
            logout_wait_timeout: Duration::from_secs(10),
            command_line_max_size: 4096,
            response_line_max_size: 4096,
            forward_max_idle_count: 30,
            transfer_max_idle_count: 5,
        }
    }
}
