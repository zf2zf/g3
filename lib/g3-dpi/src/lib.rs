/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 应用层协议识别（DPI）库。
//!
//! 本库只做一件事：在一条 TCP 连接（或 QUIC / UDP 数据报）刚开始时，
//! 从最先到达的若干字节里判断这条连接使用的是哪种应用层协议，并给出
//! 一个 [`protocol::Protocol`] 结论。它不负责解析完整报文，也不缓存业务数据。
//!
//! 对外暴露三层能力：
//!
//! - 识别引擎：[`ProtocolInspector`]，状态机式地消费客户端 / 服务端首包数据。
//! - 配置：[`ProtocolInspectionConfig`]（首包读取的缓冲区大小、超时、深度等）、
//!   [`ProtocolInspectionSizeLimit`]（各协议首包检查的字节上限）、
//!   [`ProtocolInspectPolicy`]（按目标主机 / 网段决定是否拦截）。
//! - 结果消费方辅助类型：[`Source`]（数据来自哪一方）、
//!   [`MaybeProtocol`]（候选协议）、[`ProtocolPortMap`]（端口到候选协议的映射）。
//!
//! 典型调用顺序：
//!
//! 1. 用 [`ProtocolInspector::new`] 建一个识别器，必要时用
//!    [`ProtocolInspector::push_protocol`] 把上层已知的候选协议插到队首。
//! 2. 读到数据后调用 [`ProtocolInspector::check_client_initial_data`] 或
//!    [`ProtocolInspector::check_server_initial_data`]。
//! 3. 若返回 [`ProtocolInspectError::NeedMoreData`]，按其中给出的字节数继续读，读满后再调一次；
//!    若返回 [`Protocol::Unknown`]，说明本批数据无法定论。
//! 4. 拿到 [`Protocol`] 后，上层代理再决定用哪个协议栈接管这条连接。

mod source;
pub use source::Source;

mod protocol;
pub use protocol::{
    MaybeProtocol, Protocol, ProtocolInspectError, ProtocolInspector, ProtocolPortMap,
    ProtocolPortMapValue,
};

// 拦截策略与首包读取参数：由上层（g3proxy / g3http 等）从 YAML 配置转换而来
mod config;
pub use config::{
    H1InterceptionConfig, H2InterceptionConfig, ImapInterceptionConfig, ProtocolInspectAction,
    ProtocolInspectPolicy, ProtocolInspectPolicyBuilder, ProtocolInspectionConfig,
    ProtocolInspectionSizeLimit, SmtpInterceptionConfig,
};
