/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 旁路上传审计的错误类型（协议无关）。
//!
//! 核心设计是"审计失败绝不阻断传输"，因此错误本身只用于归类与日志，
//! 上层真正关心的是 [`BypassErrorKind`]——它回答"这次失败发生在
//! 哪一侧（客户端读 / 上游写 / ICAP 读 / ICAP 写 / 强制退出 / 内部），
//! 原始数据还能不能继续送进上游"。

use std::io;

use thiserror::Error;

use super::BypassErrorKind;
use crate::reqmod::IcapReqmodParseError;

/// 上传审计 + 转发流水线中的所有失败形态。
#[derive(Debug, Error)]
pub enum BypassAdaptationError {
    /// 向 ICAP 服务器写请求失败（TCP 断开、对端重置等）——仅影响审计，不影响上传。
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    /// 从 ICAP 服务器读判决失败——审计结果未知，上传不受影响。
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    /// ICAP 连接被对端关闭，未读到完整响应。
    #[error("icap server connection closed")]
    IcapServerConnectionClosed,
    /// ICAP 响应语法非法（状态行/头/Encapsulated 解析失败）。
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    /// 从客户端数据通道读取失败——已无数据可转发，传输必须终止。
    #[error("read from client failed: {0:?}")]
    ClientReadFailed(io::Error),
    /// 向上游服务器写入失败——上传本身失败。
    #[error("write to upstream failed: {0:?}")]
    UpstreamWriteFailed(io::Error),
    /// 库内部逻辑/配置错误（如参数缺失），与具体连接无关。
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    /// 空闲检查器（idle checker）判定传输停滞过久，强制中止整条流水线。
    #[error("force quit from idle checker")]
    ForceQuit,
    /// 读客户端方向空闲超时。
    #[error("idle while reading from client")]
    ClientReadIdle,
    /// 写上游方向空闲超时（上游卡住或零窗口）。
    #[error("idle while writing to upstream")]
    UpstreamWriteIdle,
    /// 读 ICAP 方向空闲超时（服务器迟迟不给判决）。
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    /// 写 ICAP 方向空闲超时（服务器消费数据过慢）。
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    /// 请求了尚未实现的功能特性（保留的防御性错误）。
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}

#[allow(dead_code)]
impl BypassAdaptationError {
    /// 把细粒度错误收敛为六大失败面，供上层决定 fallback 策略。
    pub(crate) fn kind(&self) -> BypassErrorKind {
        match self {
            // 客户端读侧失败：数据源头断了，传输只能整体终止
            BypassAdaptationError::ClientReadFailed(_) | BypassAdaptationError::ClientReadIdle => {
                BypassErrorKind::ClientRead
            }
            // 上游写侧失败：上传目的地断了，同样无法继续
            BypassAdaptationError::UpstreamWriteFailed(_)
            | BypassAdaptationError::UpstreamWriteIdle => BypassErrorKind::UpstreamWrite,
            // ICAP 写侧失败：仅审计缺一段，原始数据仍可自行转发
            BypassAdaptationError::IcapServerWriteFailed(_)
            | BypassAdaptationError::IcapServerWriteIdle => BypassErrorKind::IcapWrite,
            // ICAP 读侧失败：判决未知；"响应非法"归入此类是因为解析失败
            // 等价于没能从连接上取回有效判决（连接状态也已不可信）
            BypassAdaptationError::IcapServerReadFailed(_)
            | BypassAdaptationError::IcapServerReadIdle
            | BypassAdaptationError::IcapServerConnectionClosed
            | BypassAdaptationError::InvalidIcapServerResponse(_) => BypassErrorKind::IcapRead,
            // 外部强制中止（空闲看门狗 / 用户封禁），与任何一侧 IO 无关
            BypassAdaptationError::ForceQuit => BypassErrorKind::ForceQuit,
            // 内部错误：不是网络问题，通常意味着配置或用法有误
            BypassAdaptationError::InternalServerError(_)
            | BypassAdaptationError::NotImplemented(_) => BypassErrorKind::Internal,
        }
    }
}
