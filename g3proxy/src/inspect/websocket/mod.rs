/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! WebSocket 协议检测（inspection）子模块。
//!
//! WebSocket 通过 HTTP/1 协议切换（upgrade）或 HTTP/2 extended CONNECT 建立，
//! 建立后即为双向转发的帧（frame）流。本子模块在 `src/inspect` 检测状态机处于
//! `Websocket` 阶段时接管该流：依据 `StreamInspectContext` 的检测结果决定
//! 拦截（intercept）、转接（detour）、放行（bypass）或阻断（block），并完成
//! 相应的帧转发与关闭握手。
//!
//! 对外仅暴露两个拦截对象：[`H1WebsocketInterceptObject`]（基于 HTTP/1 upgrade）
//! 与 [`H2WebsocketInterceptObject`]（基于 HTTP/2）；关闭帧构造见内部 `close` 子模块。

mod close;
use close::{ClientCloseFrame, ServerCloseFrame};

mod h1;
pub(crate) use h1::H1WebsocketInterceptObject;

mod h2;
pub(crate) use self::h2::H2WebsocketInterceptObject;
