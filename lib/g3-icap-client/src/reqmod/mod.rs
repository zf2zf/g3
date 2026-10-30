/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! REQMOD（请求修改）公共层。
//!
//! ICAP 的 REQMOD 模式用于把"代理采集到的请求内容"上报给远端 ICAP 检测/审计服务。
//! 本模块提供各协议适配器（HTTP h1/h2、SMTP、IMAP、FTP 等）共用的基础设施：
//!
//! - [`ConnectionTuple`]：记录连接五元组信息，供 ICAP 扩展头（X-Client-IP/X-Proxy-IP 等）
//!   与 repid 审计使用（本机扩展，非 RFC 3507 必需字段）。
//! - `IcapReqmodClient`：对底层 `IcapServiceClient`（连接池 + 配置）的薄包装，
//!   是构造各协议适配器的入口。
//! - [`error::IcapReqmodParseError`]：解析 ICAP 响应时的统一错误类型。
//! - `payload`（内部）：解析 Encapsulated 头，
//!   决定后续按"改写请求 / 替代响应 / 无载荷"处理。
//! - `response`（内部）：解析 ICAP 响应状态行 + 头部。
//! - [`mail`]：SMTP/IMAP 适配器共用的运行状态与结束状态。
//!
//! 上报线格式 = ICAP 请求行 + 扩展头（X-Transformed-From、X-Client-IP/Port、
//! X-Client-Username/X-Authenticated-User（base64）、X-Proxy-IP 等五元组、
//! X-TLS-* keylog、Allow、Encapsulated、Preview）+ 空行 + 封装的 HTTP 报文（body 采用 chunked 编码）。
//!
//! ICAP 响应侧的典型决策表（响应码 + Encapsulated 头组合 → 客户端行为）：
//!
//! | 响应码 | Encapsulated | 客户端行为 |
//! | --- | --- | --- |
//! | 204 No Content | 无 | 原样放行，不做任何修改（REQMOD 最常见结果） |
//! | 200 | req-hdr=0, req-body=null-body | 用 ICAP 返回的 HTTP 请求替换原请求转发给上游 |
//! | 200 | res-hdr=0, res-body=null-body | 不再访问上游，直接用 ICAP 返回的 HTTP 响应回复客户端 |
//! | 200 | null-body=0 | 无载荷，仅头部信息（如共享头）生效，原请求继续转发 |
//! | 其它（3xx/5xx 等） | — | 按错误处理，通常触发 bypass 或直接报错 |

use std::net::SocketAddr;
use std::sync::Arc;

use g3_types::net::TlsKeyLogBuffer;

use crate::IcapServiceClient;

mod error;
// REQMOD 解析错误，对外公开
pub use error::IcapReqmodParseError;

mod payload;
// Encapsulated 头解析结果，仅在本模块树内部使用
use payload::IcapReqmodResponsePayload;

mod response;

// HTTP/1.x 请求修改适配器
pub mod h1;
// HTTP/2 请求修改适配器
pub mod h2;

// SMTP/IMAP 适配器共用的状态机与 body 读取工具
pub mod mail;

// FTP 控制/数据通道请求修改适配器
pub mod ftp;
pub mod imap;
pub mod smtp;

/* added by wming for repid audit */
/// 连接五元组信息（本机扩展，用于 repid 审计与 ICAP 扩展头填充）。
///
/// - `server_addr`：代理侧监听地址（客户端连接到的地址）；
/// - `remote_addr`：上游服务器地址；
/// - `protocol`：传输层协议号，写入 ICAP 请求时用于区分 TCP/UDP 会话。
pub struct ConnectionTuple {
    pub server_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: ConnectionProtocol,
}

/// 传输层协议枚举，取值与 IP 协议号一致（写入 ICAP 头时使用数值形式）。
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionProtocol {
    Tcp = 6,
    Udp = 17,
}

/// REQMOD 客户端：包装底层 `IcapServiceClient`（连接池 + 配置），
/// 提供各协议适配器构造所需的统一入口。可廉价 Clone（内部为 Arc）。
#[derive(Clone)]
pub struct IcapReqmodClient {
    inner: Arc<IcapServiceClient>,
}

impl IcapReqmodClient {
    /// 基于已有的服务客户端实例（Arc 共享连接池/配置）构造 REQMOD 客户端。
    pub fn new(inner: Arc<IcapServiceClient>) -> IcapReqmodClient {
        IcapReqmodClient { inner }
    }

    /// 是否配置为 bypass 模式：true 表示只做旁路上报/审计，
    /// 不根据 ICAP 响应改写或拦截流量。
    pub fn bypass(&self) -> bool {
        self.inner.config.bypass
    }

    /// Get a reference to the inner service client, used by protocol adapters.
    ///
    /// 返回内部服务客户端引用，供各协议适配器直接访问连接池与配置。
    pub fn service_client(&self) -> &Arc<IcapServiceClient> {
        &self.inner
    }
}
