/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应状态行解析：识别 "ICAP/1.0 <3位状态码> [原因短语]" 格式。

use atoi::FromRadix10;

use super::IcapLineParseError;

/// 已解析的状态行：code 为三位 ICAP 状态码，message 借用原始缓冲区（可为空串）。
pub(crate) struct StatusLine<'a> {
    pub(crate) code: u16,
    pub(crate) message: &'a str,
}

impl<'a> StatusLine<'a> {
    /// 解析一条状态行（buf 应包含到行尾的完整内容，尾部 \r\n 由 trim 去除）。
    ///
    /// 步骤：长度检查 -> 前缀 "ICAP/1.0 " 检查 -> 前缀之后恰好读取 3 位数字
    /// 作为状态码（atoi 返回实际消费长度 len，len != 3 说明后面不是数字）->
    /// 状态码范围须落在 100..600 -> 第 4 位起剩余部分 trim 后作为原因短语。
    pub(crate) fn parse(buf: &'a [u8]) -> Result<StatusLine<'a>, IcapLineParseError> {
        const PREFIX: &str = "ICAP/1.0 ";
        const MINIMAL_LENGTH: usize = 13; // ICAP/1.0 XYZ\n

        if buf.len() < MINIMAL_LENGTH {
            return Err(IcapLineParseError::NotLongEnough);
        }
        if !buf.starts_with(PREFIX.as_bytes()) {
            return Err(IcapLineParseError::InvalidIcapVersion);
        }

        let left = &buf[PREFIX.len()..];
        let (code, len) = u16::from_radix_10(left);
        // len 必须恰为 3：保证是 "200" 这类定长三位码，且第 4 字符应为空格分隔符
        if len != 3 || !(100..600).contains(&code) {
            return Err(IcapLineParseError::InvalidStatusCode);
        }

        if left.len() < len + 1 {
            return Err(IcapLineParseError::NotLongEnough);
        }
        // 跳过状态码后的 1 个分隔符（空格），整段余下内容 trim 后即为原因短语
        // （无原因短语时得到空串，如 "ICAP/1.0 200\r\n"）
        let message = std::str::from_utf8(&left[len + 1..])?.trim();

        Ok(StatusLine { code, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal() {
        let status = StatusLine::parse(b"ICAP/1.0 200 OK\r\n").unwrap();
        assert_eq!(status.code, 200);
        assert_eq!(status.message, "OK");
    }

    #[test]
    fn no_reason() {
        let status = StatusLine::parse(b"ICAP/1.0 200\r\n").unwrap();
        assert_eq!(status.code, 200);
        assert_eq!(status.message, "");
    }
}
