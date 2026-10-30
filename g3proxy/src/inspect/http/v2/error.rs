/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/2 拦截的错误类型定义。
//!
//! 分两个层级：[`H2InterceptionError`] 描述整条 H2 连接级别的失败（握手、
//! 空闲、被封锁等），由 `H2InterceptObject::intercept` 返回并转换为服务器任务
//! 错误；[`H2StreamTransferError`] 描述单个逻辑流转发过程中的失败，并可通过
//! [`H2StreamTransferError::build_reply`] 决定能否给客户端合成一个 HTTP 响应。
//! 两个 From impl 负责把 ICAP reqmod/respmod 适配层错误映射为流级错误。

use std::io;
use std::time::Duration;

use anyhow::anyhow;
use http::{Response, StatusCode, Version};
use thiserror::Error;

use g3_h2::H2StreamBodyTransferError;
use g3_icap_client::reqmod::h2::H2ReqmodAdaptationError;
use g3_icap_client::respmod::h2::H2RespmodAdaptationError;
use g3_io_ext::IdleForceQuitReason;

/// H2 连接级拦截错误：握手、连接拆除、空闲超时及策略性取消等原因。
#[derive(Debug, Error)]
pub(crate) enum H2InterceptionError {
    /// 与源站做 h2 握手时底层字节流出现 IO 错误
    #[error("upstream io error during handshake: {0:?}")]
    UpstreamHandshakeIoError(io::Error),
    /// 与源站做 h2 握手超时
    #[error("timeout to handshake with upstream")]
    UpstreamHandshakeTimeout,
    /// 与客户端做 h2 握手时底层字节流出现 IO 错误
    #[error("client io error during handshake: {0:?}")]
    ClientHandshakeIoError(io::Error),
    /// 与客户端做 h2 握手超时
    #[error("timeout to handshake with client")]
    ClientHandshakeTimeout,
    /// 源站 h2 连接以错误终止，携带原始 h2 错误
    #[error("upstream connection closed: {0}")]
    UpstreamConnectionClosed(h2::Error),
    /// 源站 TCP 连接被断开（IO 错误为 NotConnected）
    #[error("upstream connection disconnected")]
    UpstreamConnectionDisconnected,
    /// 连接被阻断策略拒绝（do_block 路径的固定结果）
    #[error("client connection blocked")]
    ClientConnectionBlocked,
    /// 客户端 h2 连接以错误终止，携带原始 h2 错误
    #[error("client connection closed: {0}")]
    ClientConnectionClosed(h2::Error),
    /// 用户被封锁，连接被主动取消
    #[error("canceled as user blocked")]
    CanceledAsUserBlocked,
    /// 服务器退出，连接被主动取消
    #[error("canceled as server quit")]
    CanceledAsServerQuit,
    /// 无存活流且连续空闲超过阈值：字段为空闲周期与触发次数
    #[error("idle after {0:?} x {1}")]
    Idle(Duration, usize),
    /// 未归类的内部错误，保留原始 anyhow 错误供排查
    #[error("unexpected error: {0:}")]
    UnexpectedError(anyhow::Error),
}

impl H2InterceptionError {
    /// 把与源站握手的 h2 错误归类：仅 IO 类错误有明确语义，
    /// 其余（协议/帧错误等）统一落入 UnexpectedError。
    pub(super) fn upstream_handshake_failed(e: h2::Error) -> Self {
        if e.is_io() {
            H2InterceptionError::UpstreamHandshakeIoError(e.into_io().unwrap())
        } else {
            H2InterceptionError::UnexpectedError(anyhow!(
                "unhandled error while handshake to upstream: {e:?}"
            ))
        }
    }

    /// 把与客户端握手的 h2 错误归类，规则同 upstream_handshake_failed。
    pub(super) fn client_handshake_failed(e: h2::Error) -> Self {
        if e.is_io() {
            H2InterceptionError::ClientHandshakeIoError(e.into_io().unwrap())
        } else {
            H2InterceptionError::UnexpectedError(anyhow!(
                "unhandled error while handshake to client: {e:?}"
            ))
        }
    }
}

/// 单个 H2 逻辑流转发过程中的错误：涵盖开流、头/体收发、空闲超时与策略取消。
#[derive(Debug, Error)]
pub(crate) enum H2StreamTransferError {
    /// 代理内部逻辑错误（如构造响应失败），携带静态描述
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    /// 内部适配器（ICAP/detour 等）返回的错误
    #[error("internal adapter error: {0}")]
    InternalAdapterError(anyhow::Error),
    /// 向源站打开新流失败（源站 GOAWAY/REFUSED 等），携带原始 h2 错误
    #[error("failed to open upstream stream: {0}")]
    UpstreamStreamOpenFailed(h2::Error),
    /// 等待源站流可写（h2s.ready）超时
    #[error("timeout to open upstream stream")]
    UpstreamStreamOpenTimeout,
    /// 请求头部发送失败
    #[error("failed to send request head: {0}")]
    RequestHeadSendFailed(h2::Error),
    /// Host 头缺失或无法解析为合法目的地址
    #[error("invalid Host header")]
    InvalidHostHeader,
    /// 接收源站响应头部失败
    #[error("failed to recv response head: {0}")]
    ResponseHeadRecvFailed(h2::Error),
    /// 等待源站响应头部超时
    #[error("timeout to recv response head")]
    ResponseHeadRecvTimeout,
    /// 向客户端发送响应头部失败
    #[error("failed to send response head: {0}")]
    ResponseHeadSendFailed(h2::Error),
    /// 请求体转发失败，携带体传输层的具体原因
    #[error("failed to transfer request body: {0}")]
    RequestBodyTransferFailed(H2StreamBodyTransferError),
    /// 响应体转发失败，携带体传输层的具体原因
    #[error("failed to transfer response body: {0}")]
    ResponseBodyTransferFailed(H2StreamBodyTransferError),
    /// 用户被封锁，本流被取消
    #[error("canceled as user blocked")]
    CanceledAsUserBlocked,
    /// 服务器退出，本流被取消
    #[error("canceled as server quit")]
    CanceledAsServerQuit,
    /// 从客户端 h2 流读取数据时空闲
    #[error("read from http client idle")]
    HttpClientReadIdle,
    /// 向客户端 h2 流写入数据时空闲
    #[error("write to http client idle")]
    HttpClientWriteIdle,
    /// 从源站 h2 流读取数据时空闲
    #[error("read from http upstream idle")]
    HttpUpstreamReadIdle,
    /// 向源站 h2 流写入数据时空闲
    #[error("write to http upstream idle")]
    HttpUpstreamWriteIdle,
    /// 本流空闲超过阈值：字段为空闲周期与触发次数
    #[error("idle after {0:?} x {1}")]
    Idle(Duration, usize),
}

impl H2StreamTransferError {
    /// 为错误合成给客户端的 HTTP 响应；返回 None 表示无法/不应回复响应：
    /// 开流阶段的失败应直接 RST 流（请求尚未发往源站，可安全重试），
    /// 其余未列出的变体（如已处于体传输阶段）也应答不明，不再合成响应。
    pub(super) fn build_reply(&self) -> Option<Response<()>> {
        let status_code = match self {
            H2StreamTransferError::UpstreamStreamOpenFailed(_)
            | H2StreamTransferError::UpstreamStreamOpenTimeout => {
                // we should refuse stream
                return None;
            }
            H2StreamTransferError::RequestHeadSendFailed(_) => StatusCode::BAD_GATEWAY,
            H2StreamTransferError::InvalidHostHeader => StatusCode::BAD_REQUEST,
            H2StreamTransferError::ResponseHeadRecvFailed(_) => StatusCode::BAD_GATEWAY,
            H2StreamTransferError::ResponseHeadRecvTimeout => StatusCode::GATEWAY_TIMEOUT,
            _ => return None,
        };
        let rsp = Response::builder()
            .status(status_code)
            .version(Version::HTTP_2);
        rsp.body(()).ok()
    }
}

/// 把 ICAP 请求修改（reqmod）适配错误映射为流转发错误：按请求在适配流程中
/// 所处的阶段（客户端收/源站发/源站收响应）还原成语义最接近的本地错误。
impl From<H2ReqmodAdaptationError> for H2StreamTransferError {
    fn from(e: H2ReqmodAdaptationError) -> Self {
        match e {
            H2ReqmodAdaptationError::InternalServerError(s) => {
                H2StreamTransferError::InternalServerError(s)
            }
            H2ReqmodAdaptationError::HttpClientRecvDataFailed(e) => {
                H2StreamTransferError::RequestBodyTransferFailed(
                    H2StreamBodyTransferError::RecvDataFailed(e),
                )
            }
            H2ReqmodAdaptationError::HttpClientRecvTrailerFailed(e) => {
                H2StreamTransferError::RequestBodyTransferFailed(
                    H2StreamBodyTransferError::RecvTrailersFailed(e),
                )
            }
            H2ReqmodAdaptationError::HttpUpstreamSendHeadFailed(e) => {
                H2StreamTransferError::RequestHeadSendFailed(e)
            }
            H2ReqmodAdaptationError::HttpUpstreamSendDataFailed(e) => {
                H2StreamTransferError::RequestBodyTransferFailed(
                    H2StreamBodyTransferError::SendDataFailed(e),
                )
            }
            H2ReqmodAdaptationError::HttpUpstreamSendTrailedFailed(e) => {
                H2StreamTransferError::RequestBodyTransferFailed(
                    H2StreamBodyTransferError::SendTrailersFailed(e),
                )
            }
            H2ReqmodAdaptationError::HttpClientReadIdle => {
                H2StreamTransferError::HttpClientReadIdle
            }
            H2ReqmodAdaptationError::HttpUpstreamWriteIdle => {
                H2StreamTransferError::HttpUpstreamWriteIdle
            }
            H2ReqmodAdaptationError::IdleForceQuit(reason) => match reason {
                IdleForceQuitReason::UserBlocked => H2StreamTransferError::CanceledAsUserBlocked,
                IdleForceQuitReason::ServerQuit => H2StreamTransferError::CanceledAsServerQuit,
            },
            H2ReqmodAdaptationError::HttpUpstreamRecvResponseFailed(e) => {
                H2StreamTransferError::ResponseHeadRecvFailed(e)
            }
            H2ReqmodAdaptationError::HttpUpstreamRecvResponseTimeout => {
                H2StreamTransferError::ResponseHeadRecvTimeout
            }
            e => H2StreamTransferError::InternalAdapterError(anyhow!("reqmod: {e}")),
        }
    }
}

/// 把 ICAP 响应修改（respmod）适配错误映射为流转发错误：按响应在适配流程中
/// 所处的阶段（源站收/客户端发）还原成语义最接近的本地错误。
impl From<H2RespmodAdaptationError> for H2StreamTransferError {
    fn from(e: H2RespmodAdaptationError) -> Self {
        match e {
            H2RespmodAdaptationError::InternalServerError(s) => {
                H2StreamTransferError::InternalServerError(s)
            }
            H2RespmodAdaptationError::HttpUpstreamRecvDataFailed(e) => {
                H2StreamTransferError::ResponseBodyTransferFailed(
                    H2StreamBodyTransferError::RecvDataFailed(e),
                )
            }
            H2RespmodAdaptationError::HttpUpstreamRecvTrailerFailed(e) => {
                H2StreamTransferError::ResponseBodyTransferFailed(
                    H2StreamBodyTransferError::RecvTrailersFailed(e),
                )
            }
            H2RespmodAdaptationError::HttpClientSendHeadFailed(e) => {
                H2StreamTransferError::ResponseHeadSendFailed(e)
            }
            H2RespmodAdaptationError::HttpClientSendDataFailed(e) => {
                H2StreamTransferError::ResponseBodyTransferFailed(
                    H2StreamBodyTransferError::SendDataFailed(e),
                )
            }
            H2RespmodAdaptationError::HttpClientSendTrailerFailed(e) => {
                H2StreamTransferError::ResponseBodyTransferFailed(
                    H2StreamBodyTransferError::SendTrailersFailed(e),
                )
            }
            H2RespmodAdaptationError::HttpUpstreamReadIdle => {
                H2StreamTransferError::HttpUpstreamReadIdle
            }
            H2RespmodAdaptationError::HttpClientWriteIdle => {
                H2StreamTransferError::HttpClientWriteIdle
            }
            H2RespmodAdaptationError::IdleForceQuit(reason) => match reason {
                IdleForceQuitReason::UserBlocked => H2StreamTransferError::CanceledAsUserBlocked,
                IdleForceQuitReason::ServerQuit => H2StreamTransferError::CanceledAsServerQuit,
            },
            e => H2StreamTransferError::InternalAdapterError(anyhow!("respmod: {e}")),
        }
    }
}
