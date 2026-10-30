/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use super::{CommonTaskContext, HttpProxyServerStats, protocol};

// FTP-over-HTTP 任务模块：把 HTTP 请求（GET/PUT/DELETE）翻译为对上游 FTP 服务器的操作，
// 客户端通过 HTTP 隧道（ConnectTask）承载 FTP 控制/数据连接。

// 核心任务实现：FtpOverHttpTask，负责按 HTTP 方法分发到 FTP 登录/列表/下载/上传/删除流程
mod task;
pub(super) use task::FtpOverHttpTask;

// 本任务的字节数/流量统计结构
mod stats;
use stats::{FtpOverHttpTaskCltWrapperStats, FtpOverHttpTaskStats};

// FTP 连接提供者：把 g3-ftp-client 的建连请求桥接到 tcp_connect 隧道模块
mod connection;
use connection::HttpProxyFtpConnectionProvider;

// 目录列表响应写出器：chunked 编码与无长度直接结尾两种模式
mod list;
use list::{ChunkedListWriter, EndingListWriter, ListWriter};
