/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应头部行解析（零拷贝）：按行内第一个 ':' 拆出 name/value 借用切片。

use super::IcapLineParseError;

/// 一条已拆分的头部行：name 与 value 均借用原始行缓冲区，不做额外分配。
/// 头部名的查询（不区分大小写）由调用方自行处理。
pub(crate) struct HeaderLine<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
}

impl<'a> HeaderLine<'a> {
    /// 解析一条完整头部行（含或不含行尾 \r\n 均可）。
    ///
    /// 规则：以行内第一个 ':' 为界，冒号前为 name，冒号后整体 trim（顺带去掉
    /// 行尾的 \r\n 与前导空格）作为 value。注意 ':' 之前的偏移按字节计算，
    /// 由于 ':' 是单字节且 UTF-8 多字节字符首字节均 >= 0x80，字节切分点不会
    /// 落在字符中间，因此非 ASCII 头部名/值也能正确拆分（见 tests::encoding）。
    ///
    /// 错误：无 ':' 返回 `NoDelimiterFound(':')`；以 ':' 开头返回
    /// `MissingHeaderName`；非 UTF-8 返回 `InvalidUtf8Encoding`。
    pub(crate) fn parse(buf: &'a [u8]) -> Result<HeaderLine<'a>, IcapLineParseError> {
        let line = std::str::from_utf8(buf)?;

        // 定位第一个 ':'（memchr 按字节扫描，UTF-8 续字节不会等于 ':'）
        let p = memchr::memchr(b':', line.as_bytes())
            .ok_or(IcapLineParseError::NoDelimiterFound(':'))?;
        if p == 0 {
            return Err(IcapLineParseError::MissingHeaderName);
        }

        let name = &line[0..p];
        let value = line[p + 1..].trim();
        Ok(HeaderLine { name, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        let s = "测试: 结果\r\n";
        let header = HeaderLine::parse(s.as_bytes()).unwrap();

        assert_eq!(header.name, "测试");
        assert_eq!(header.value, "结果");
    }
}
