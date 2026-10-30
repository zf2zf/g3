/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! ICAP 错误原因枚举。
//!
//! `IcapErrorReason` 汇总了 reqmod/respmod 在与 ICAP 服务端交互过程中常见的
//! 协议层失败原因（响应码非法、100-continue 配合 preview 的语义错误、找不到
//! body 等），供各子模块的错误类型（如 `ReqmodError`）包装复用；本枚举自身通过
//! `Display` 输出固定的英文描述文本。

use std::fmt;

/// ICAP 交互失败的协议层原因（不含 IO 错误，IO 错误由各模块直接包装 `io::Error`）。
#[derive(Debug)]
pub enum IcapErrorReason {
    /// 响应码不满足协议要求（如 preview 阶段收到既非 204/200/206/100 的合法组合）
    InvalidResponse,
    /// 响应码不在本客户端支持的取值范围内
    UnknownResponse,
    /// 发送完整 body 后（收到 100-continue 之后）返回了非法响应码
    InvalidResponseAfterContinue,
    /// 发送完整 body 后（收到 100-continue 之后）返回了不支持的响应码
    UnknownResponseAfterContinue,
    /// preview 数据已经发到结尾（EOF）时服务端仍要求 100-continue 继续发送
    ContinueAfterPreviewEof,
    /// preview 阶段返回了不支持的响应码
    UnknownResponseForPreview,
    /// 按线格式（chunked 编码）读取不到 ICAP 封装的 body
    NoBodyFound,
}

impl IcapErrorReason {
    /// 返回用于日志/错误展示的静态描述文本。
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            IcapErrorReason::InvalidResponse => "invalid ICAP response code",
            IcapErrorReason::UnknownResponse => "unknown ICAP response code",
            IcapErrorReason::InvalidResponseAfterContinue => {
                "invalid ICAP response code after 100-continue"
            }
            IcapErrorReason::UnknownResponseAfterContinue => {
                "unknown ICAP response code after 100-continue"
            }
            IcapErrorReason::ContinueAfterPreviewEof => {
                "invalid 100-continue response as preview is eof"
            }
            IcapErrorReason::UnknownResponseForPreview => "unknown ICAP response code for preview",
            IcapErrorReason::NoBodyFound => "no ICAP body found",
        }
    }
}

impl fmt::Display for IcapErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
