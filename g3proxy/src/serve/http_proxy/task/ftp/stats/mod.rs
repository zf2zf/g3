/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use super::HttpProxyServerStats;

// FTP-over-HTTP 任务的统计子模块：任务级字节统计 + 客户端读写流的统计包装器

// FtpOverHttpTaskStats：单任务的 FTP 控制/数据连接与 HTTP 客户端字节统计
mod task;
pub(super) use task::FtpOverHttpTaskStats;

// FtpOverHttpTaskCltWrapperStats：挂到客户端读写流上的统计回调，聚合到服务器/任务/用户三级
mod wrapper;
pub(super) use wrapper::FtpOverHttpTaskCltWrapperStats;
