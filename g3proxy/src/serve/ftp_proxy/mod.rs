/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy server module.
//!
//! Handles native FTP protocol:
//!   * Control channel interception (PASV/EPSV rewriting)
//!   * Data channel interception for upload auditing via ICAP REQMOD
//!   * Graceful shutdown and stats tracking
//!
//! FTP 代理服务器模块。
//!
//! 处理原生 FTP 协议：
//!   * 控制通道拦截：改写上游返回的 PASV/EPSV 应答，把数据通道牵引到本代理
//!   * 数据通道拦截：上传内容经 ICAP REQMOD 审计后再转发给上游
//!   * 优雅退出与运行统计

/// ICAP REQMOD 上传审计桥接：把数据通道的字节同时转发与送审
pub(crate) mod audit_bridge;
/// FTP over HTTP CONNECT 隧道模式下的桥接实现（目前未被调用，保留待接入）
#[allow(dead_code)]
pub(crate) mod connect_bridge;
/// 控制通道解析与 PASV/EPSV 应答改写等公共逻辑，原生模式与 CONNECT 模式共用
pub(crate) mod ctl_common;
/// FTP 代理服务器主体：监听、配置热加载、上游选择与任务派发
pub(crate) mod server;
/// 服务器级别的运行统计指标（连接数、存活任务数、字节数）
pub(crate) mod stats;
/// 单条 FTP 控制连接的任务：上游建连、通道转发与数据通道拦截
pub(crate) mod task;
/// 跨连接共享的 FTP 上传/FTPS 状态表（HTTP CONNECT 模式下控制与数据分离时使用）
pub(crate) mod upload_state;

pub(crate) use server::FtpProxyServer;
