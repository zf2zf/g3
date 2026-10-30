/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 响应 `Encapsulated` 头的解析。
//!
//! RFC 3507 规定：当 ICAP 响应需要返回改写后的报文时，通过 Encapsulated 头
//! 描述被封装的 HTTP 报文在响应 body 中的位置，格式为"头部偏移, body 偏移"对，例如：
//!
//! - `req-hdr=0, req-body=null-body` → 封装的是**改写后的请求**（转发给上游前替换原请求）
//! - `res-hdr=0, res-body=null-body` → 封装的是**替代响应**（不回源，直接回复客户端）
//! - `null-body=0` → 无封装载荷（仅头部信息生效）
//!
//! 本模块把该头解析为 [`IcapReqmodResponsePayload`] 枚举，其中携带的 usize 是
//! 封装 HTTP **头部**的字节长度（即 body 相对封装段起点的偏移量），
//! 后续流程据此决定读取多少头部、body 从哪里开始。
//! 注意：本客户端仅接受头部偏移为 0、且 body 为 null-body 形式的响应。

use atoi::FromRadix10;

use super::IcapReqmodParseError;

/// Encapsulated 头解析结果：ICAP 响应中封装的 HTTP 载荷类型。
///
/// 变体携带的 `usize` 为封装 HTTP 头部的字节长度（body 偏移量）。
///
/// - `NoPayload`：对应 `null-body=0`，响应不封装任何报文，原请求继续放行；
/// - `HttpRequestWithBody(偏移)`：对应 `req-hdr=0, req-body=N`，
///   封装的是改写后的请求（body 以 chunked 随后出现），替换原请求转发上游；
/// - `HttpRequestWithoutBody(偏移)`：对应 `req-hdr=0, null-body=N`，改写后的请求无 body；
/// - `HttpResponseWithBody(偏移)`：对应 `res-hdr=0, res-body=N`，
///   封装的是替代响应，不回源、直接回复客户端；
/// - `HttpResponseWithoutBody(偏移)`：对应 `res-hdr=0, null-body=N`，替代响应无 body。
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum IcapReqmodResponsePayload {
    NoPayload,
    HttpRequestWithBody(usize),
    HttpRequestWithoutBody(usize),
    HttpResponseWithBody(usize),
    HttpResponseWithoutBody(usize),
}

impl IcapReqmodResponsePayload {
    /// 解析 Encapsulated 头的取值（如 "req-hdr=0, req-body=null-body"）。
    ///
    /// 头部名与 body 名均**大小写不敏感**（先 to_lowercase 再匹配）；
    /// 任何不符合本客户端支持范围的组合都会返回明确错误：
    /// - 缺少 "," 分段或 "=" 分隔 → InvalidHeaderValue("Encapsulated")；
    /// - hdr 偏移非 0 / body 名不支持 → UnsupportedBody。
    pub(crate) fn parse(value: &str) -> Result<IcapReqmodResponsePayload, IcapReqmodParseError> {
        let mut parts = value.split(',');
        // 第一段必须是 "<hdr-name>=<offset>"，缺失则视为 Encapsulated 取值非法
        let hdr_part = parts
            .next()
            .ok_or(IcapReqmodParseError::InvalidHeaderValue("Encapsulated"))?
            .trim();

        let (name, value) = hdr_part
            .split_once('=')
            .ok_or(IcapReqmodParseError::InvalidHeaderValue("Encapsulated"))?;
        // 本客户端只支持封装头部从偏移 0 开始（即封装报文紧跟在 ICAP 空行之后）
        if value.ne("0") {
            return Err(IcapReqmodParseError::UnsupportedBody(
                "invalid hdr byte-offsets value",
            ));
        }

        // 头部名大小写不敏感匹配（RFC 3507 允许任意大小写）
        match name.to_lowercase().as_str() {
            "req-hdr" => {
                // req-hdr 之后必须跟一个 body 偏移对（req-body 或 null-body）
                let body_part = parts
                    .next()
                    .ok_or(IcapReqmodParseError::UnsupportedBody(
                        "no body byte-offsets pair found",
                    ))?
                    .trim();
                let (name, value) =
                    body_part
                        .split_once('=')
                        .ok_or(IcapReqmodParseError::UnsupportedBody(
                            "invalid body byte-offsets pair",
                        ))?;
                // 解析 body 偏移量：hdr_len 是数值，offset 是消费掉的字符数；
                // 二者相等（如 "512" → 数值 512、消费 3 字符 == 字符串长度）说明该段是纯数字，
                // 形如 "null-body" 的非数字取值也会在此处判定"未完全解析"而报错
                let (hdr_len, offset) = u32::from_radix_10(value.as_bytes());
                let hdr_len = hdr_len as usize;
                if offset != value.len() {
                    return Err(IcapReqmodParseError::UnsupportedBody(
                        "invalid body byte-offsets value",
                    ));
                }
                match name.to_lowercase().as_str() {
                    // req-body：HTTP 请求体随后以 chunked 编码出现在 ICAP body 中
                    "req-body" => Ok(IcapReqmodResponsePayload::HttpRequestWithBody(hdr_len)),
                    // null-body：请求没有 body
                    "null-body" => Ok(IcapReqmodResponsePayload::HttpRequestWithoutBody(hdr_len)),
                    _ => Err(IcapReqmodParseError::UnsupportedBody(
                        "invalid body byte-offsets name",
                    )),
                }
            }
            "res-hdr" => {
                // 与 req-hdr 分支同理，只是解析的是替代响应的封装偏移
                let body_part = parts
                    .next()
                    .ok_or(IcapReqmodParseError::UnsupportedBody(
                        "no body byte-offsets pair found",
                    ))?
                    .trim();
                let (name, value) =
                    body_part
                        .split_once('=')
                        .ok_or(IcapReqmodParseError::UnsupportedBody(
                            "invalid body byte-offsets pair",
                        ))?;
                // 同上：数值 + 消费字符数必须覆盖整个取值串，保证偏移量是合法十进制数
                let (hdr_len, offset) = u32::from_radix_10(value.as_bytes());
                let hdr_len = hdr_len as usize;
                if offset != value.len() {
                    return Err(IcapReqmodParseError::UnsupportedBody(
                        "invalid body byte-offsets value",
                    ));
                }
                match name.to_lowercase().as_str() {
                    // res-body：HTTP 响应体以 chunked 编码随后出现，直接回给客户端
                    "res-body" => Ok(IcapReqmodResponsePayload::HttpResponseWithBody(hdr_len)),
                    // null-body：替代响应没有 body（如仅有响应头的拦截页指令）
                    "null-body" => Ok(IcapReqmodResponsePayload::HttpResponseWithoutBody(hdr_len)),
                    _ => Err(IcapReqmodParseError::UnsupportedBody(
                        "invalid body byte-offsets name",
                    )),
                }
            }
            // null-body=0：响应不封装任何报文，对应 204/仅头部改写的放行场景
            "null-body" => Ok(IcapReqmodResponsePayload::NoPayload),
            _ => Err(IcapReqmodParseError::UnsupportedBody(
                "invalid hdr byte-offsets value",
            )),
        }
    }
}
