/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! FTP 协议拦截模块出口。
//!
//! 导出控制连接拦截对象 [`FtpInterceptObject`]，以及数据连接（上传方向）相关的
//! [`FtpUploadDataInterceptObject`]、上传标记查询 [`check_ftp_upload_data`]
//! 和 FTPS 域名查询 [`get_ftps_domain`]。

pub(crate) mod object;
pub(crate) use object::FtpInterceptObject;

pub(crate) mod upload_data;
pub(crate) use upload_data::{
    FtpUploadDataInterceptObject, check_ftp_upload_data, get_ftps_domain,
};
