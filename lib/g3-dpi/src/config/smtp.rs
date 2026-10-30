/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP 拦截（拆解重组）配置。
//!
//! 与识别无关（识别只看服务端 220 greeting）；这里控制的是代理接管一条 SMTP
//! 会话后各阶段的超时，以及允许哪些可选扩展。
//!
//! 超时的命名规律反映 SMTP 的对话本质：客户端发命令、服务端回响应，
//! 因此 `command_wait_timeout`（等客户端下一条）与 `response_wait_timeout`
//! （等服务端回码）成对出现，各自独立可调。

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpInterceptionConfig {
    /// 等待服务端 220 greeting 的超时。
    pub greeting_timeout: Duration,
    /// 发出 QUIT 后等待服务端关闭的超时。
    pub quit_wait_timeout: Duration,
    /// 等待客户端下一条命令的超时；本质是会话空闲上限，所以取得很长。
    pub command_wait_timeout: Duration,
    /// 等待服务端返回码的超时（例如转发场景下等对端服务器响应）。
    pub response_wait_timeout: Duration,
    /// DATA 阶段：等待客户端开始发送正文的超时。
    pub data_initiation_timeout: Duration,
    /// DATA 阶段：等待正文发送结束（`\r\n.\r\n`）的超时。
    /// 比 initiation 长得多，因为大邮件正文上行的耗时不可预估。
    pub data_termination_timeout: Duration,
    /// 是否放行 ODMR（RFC 2645 按需邮件中继，`TURN` 命令）。
    pub allow_on_demand_mail_relay: bool,
    /// 是否放行 CHUNKING（RFC 3034，`BDAT` 命令）——不用点填充的二进制分块传输。
    pub allow_data_chunking: bool,
    /// 是否放行 BURL（RFC 4468，把正文直接提交到存储而非内存转发）。
    pub allow_burl_data: bool,
}

impl Default for SmtpInterceptionConfig {
    /// 默认值取向：三个 `allow_*` 全关，即默认只按 SMTP 基础命令集处理。
    /// 这三个扩展都会改变邮件正文的承载方式（分块、或绕过内存直写存储），
    /// 拦截器需要额外实现才能拿到完整正文，因此默认不启用。
    ///
    /// 超时方面 initiation 短（120s）、termination 长（600s）：前者是客户端
    /// 发完 `DATA` 后应立即开始上行正文，停顿说明它卡住了；后者要容纳大邮件的传输耗时。
    fn default() -> Self {
        SmtpInterceptionConfig {
            greeting_timeout: Duration::from_secs(300),
            quit_wait_timeout: Duration::from_secs(60),
            command_wait_timeout: Duration::from_secs(300),
            response_wait_timeout: Duration::from_secs(300),
            data_initiation_timeout: Duration::from_secs(120),
            data_termination_timeout: Duration::from_secs(600),
            allow_on_demand_mail_relay: false,
            allow_data_chunking: false,
            allow_burl_data: false,
        }
    }
}
