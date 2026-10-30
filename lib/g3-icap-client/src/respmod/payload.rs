/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 解析 ICAP RESPMOD 响应的 `Encapsulated` 头。
//!
//! RESPMOD 与 reqmod 方向相反：客户端把"原始 HTTP 响应"封装在 ICAP
//! 消息体中送给服务器，响应回来时 `Encapsulated` 头同样描述封装布局，
//! 常见形式为 `Encapsulated: res-hdr=0, res-body=123`（偏移量相对于
//! ICAP 头结束之后的封装区起点）。

use atoi::FromRadix10;

use super::IcapRespmodParseError;

/// 封装后 HTTP 响应在 ICAP 消息体中的布局（RFC 3507 §4.2/§5）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcapRespmodResponsePayload {
    /// 没有封装的 HTTP 响应体（`null-body=0`），
    /// 例如纯 204 放行响应。
    NoPayload,
    /// 封装了"res-hdr + res-body"：值为 res-body 的字节偏移量，
    /// 也就是封装的 res-hdr 自身的长度；偏移之后是（可能被 ICAP
    /// 服务器改写过的）HTTP 响应体，其真实长度需按分块编码继续解析。
    HttpResponseWithBody(usize),
    /// 封装了"res-hdr + null-body"：只有响应头没有响应体，
    /// 值为 res-hdr 自身的长度（null-body 偏移量）。
    HttpResponseWithoutBody(usize),
}

impl IcapRespmodResponsePayload {
    /// 解析 `Encapsulated` 头的取值。
    ///
    /// 期望的合法形式：
    /// - `res-hdr=0, res-body=N`  → 带体的封装响应
    /// - `res-hdr=0, null-body=N` → 不带体的封装响应
    /// - `null-body=0`            → 无封装体
    ///
    /// 注意：本实现按约定只接受 res-hdr 偏移为 0、且恰好两段的形式，
    /// 其余布局（例如 res-hdr 前有填充）一律视为不支持。
    pub(crate) fn parse(value: &str) -> Result<IcapRespmodResponsePayload, IcapRespmodParseError> {
        // 按逗号拆成 "name=offset" 对，第一段必须是 res-hdr（或 null-body）
        let mut parts = value.split(',');
        let hdr_part = parts
            .next()
            .ok_or(IcapRespmodParseError::InvalidHeaderValue("Encapsulated"))?
            .trim();

        let (name, value) = hdr_part
            .split_once('=')
            .ok_or(IcapRespmodParseError::InvalidHeaderValue("Encapsulated"))?;
        // hdr 偏移必须为 0：封装的 HTTP 响应头必须紧贴 ICAP 头之后，
        // 否则前面的填充字节没有定义的含义，直接拒绝。
        if value.ne("0") {
            return Err(IcapRespmodParseError::UnsupportedBody(
                "invalid hdr byte-offsets value",
            ));
        }

        match name.to_lowercase().as_str() {
            "res-hdr" => {
                // 第二段声明体的类型：res-body（有 HTTP 响应体）
                // 或 null-body（无响应体）；其偏移值即封装头部长度。
                let body_part = parts
                    .next()
                    .ok_or(IcapRespmodParseError::UnsupportedBody(
                        "no body byte-offsets pair found",
                    ))?
                    .trim();
                let (name, value) =
                    body_part
                        .split_once('=')
                        .ok_or(IcapRespmodParseError::UnsupportedBody(
                            "invalid body byte-offsets pair",
                        ))?;
                // from_radix_10 返回 (解析值, 消费的字节数)：
                // 消费数不等于字符串长度说明夹杂了非数字字符，视为非法。
                let (hdr_len, offset) = u32::from_radix_10(value.as_bytes());
                let hdr_len = hdr_len as usize;
                if offset != value.len() {
                    return Err(IcapRespmodParseError::UnsupportedBody(
                        "invalid body byte-offsets value",
                    ));
                }
                match name.to_lowercase().as_str() {
                    "res-body" => Ok(IcapRespmodResponsePayload::HttpResponseWithBody(hdr_len)),
                    "null-body" => Ok(IcapRespmodResponsePayload::HttpResponseWithoutBody(hdr_len)),
                    _ => Err(IcapRespmodParseError::UnsupportedBody(
                        "invalid body byte-offsets name",
                    )),
                }
            }
            // 只有 null-body=0：ICAP 服务器没有回传任何封装内容
            "null-body" => Ok(IcapRespmodResponsePayload::NoPayload),
            // 首段既不是 res-hdr 也不是 null-body（如误用 req-* 语法）
            _ => Err(IcapRespmodParseError::UnsupportedBody(
                "invalid hdr byte-offsets value",
            )),
        }
    }
}
