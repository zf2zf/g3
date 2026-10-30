/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! WebSocket 关闭帧（close frame）的构造。
//!
//! 当检测策略判定需要阻断（block）或转接（detour）出错时，代理需要主动向对端
//! 发送一个关闭帧以正确结束 WebSocket 会话。本文件提供 [`ServerCloseFrame`] 与
//! [`ClientCloseFrame`] 两个类型，分别用于生成"服务端→客户端"和"客户端→服务端"
//! 方向的关闭帧字节。二者都以 `const fn` 在编译期拼出完整的帧，供 h1/h2 拦截对象
//! 作为静态常量写入底层流。

/// 由代理以"服务端"身份发往客户端的关闭帧。
///
/// WebSocket 帧由客户端发起时必须掩码（masked），而服务端发出的帧不掩码，
/// 因此本类型生成的帧不带掩码位与掩码密钥。
pub struct ServerCloseFrame {}

impl ServerCloseFrame {
    /// 构造一个仅携带状态码的服务端关闭帧（共 4 字节）。
    ///
    /// 布局：`0x88`（FIN=1、opcode=8/关闭）、`0x02`（负载长度 2，未掩码）、
    /// 随后是 2 字节大端序的状态码。无负载原因文本，仅传达关闭原因码。
    pub(super) const fn encode_with_status_code(status_code: u16) -> [u8; 4] {
        let code = status_code.to_be_bytes();
        [0x88, 0x02, code[0], code[1]]
    }
}

/// 由代理以"客户端"身份发往上游服务端的关闭帧。
///
/// 客户端发出的帧必须掩码，因此本类型生成的帧带掩码位与 4 字节掩码密钥。
pub struct ClientCloseFrame {}

impl ClientCloseFrame {
    /// 构造一个仅携带状态码的客户端关闭帧（共 8 字节）。
    ///
    /// 布局：`0x88`（FIN=1、opcode=8/关闭）、`0x82`（掩码位=1、负载长度 2）、
    /// 4 字节全零掩码密钥、随后是 2 字节大端序的状态码。掩码密钥取零，因此
    /// 掩码后的负载字节与原始状态码相同，省去异或计算。
    pub(super) const fn encode_with_status_code(status_code: u16) -> [u8; 8] {
        let code = status_code.to_be_bytes();
        [0x88, 0x82, 0x00, 0x00, 0x00, 0x00, code[0], code[1]]
    }
}
