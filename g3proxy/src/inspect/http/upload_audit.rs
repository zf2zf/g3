/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP 上行请求体的 ICAP 送审判定。
//!
//! 三个送审点（拦截 H1、拦截 H2、标准 http_proxy 转发）共用这一条规则，
//! 免得同一份配置在三种承载方式下读出三种审计范围。判定结果同时就是
//! ICAP 扩展头 `X-Body-Framing` 的取值：审计服务看到它就知道封装区里的
//! 请求体字节是原始正文还是带着客户端分块帧的流。
//!
//! 规则（`req_hasbody: true`）：
//! 1. 无请求体 → 不审；
//! 2. `application/x-www-form-urlencoded` 且 [`req_skip_urlencoded_form`] 打开 → 不审；
//! 3. 长度无法预先得知（分块传输、H2 省略 `content-length`）→ 一律审；
//! 4. 声明了 `Content-Length` → 严格大于 `req_body_min_size` 才审。
//!
//! [`req_skip_urlencoded_form`]: g3_dpi::H1InterceptionConfig::req_skip_urlencoded_form

use g3_dpi::H1InterceptionConfig;
use g3_http::HttpBodyType;
use http::Version;

/// ICAP `X-Transformed-From` 的协议来源取值：客户端侧走 TLS 就是 `HTTPS`。
pub(crate) const fn scheme_tag(over_tls: bool) -> &'static str {
    if over_tls {
        "HTTPS"
    } else {
        "HTTP"
    }
}

/// ICAP `X-Http-Version` 的取值；无法识别的版本返回 `None`（不发这个头）。
pub(crate) fn http_version_tag(version: Version) -> Option<&'static str> {
    if version == Version::HTTP_09 {
        Some("0.9")
    } else if version == Version::HTTP_10 {
        Some("1.0")
    } else if version == Version::HTTP_11 {
        Some("1.1")
    } else if version == Version::HTTP_2 {
        Some("2.0")
    } else if version == Version::HTTP_3 {
        Some("3.0")
    } else {
        None
    }
}

/// 封装区请求体的成帧形态，即 ICAP `X-Body-Framing` 的取值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UploadBodyFraming {
    /// 定长请求体：旁路字节就是请求体本身。
    ContentLength,
    /// HTTP/1.x 分块传输：旁路字节带着客户端的原始分块帧
    /// （十六进制长度行 + CRLF + 数据 + CRLF），审计侧需自行解帧。
    Chunked,
    /// 长度未声明且没有分块帧（HTTP/2 省略 `content-length` 的流）：
    /// 旁路字节就是请求体本身，以 ICAP 的 `0\r\n\r\n` 终止。
    Stream,
}

impl UploadBodyFraming {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            UploadBodyFraming::ContentLength => "content-length",
            UploadBodyFraming::Chunked => "chunked",
            UploadBodyFraming::Stream => "stream",
        }
    }
}

/// `application/x-www-form-urlencoded` 表单：登录框、搜索框、埋点这类键值对。
///
/// 只认 MIME 本质，忽略 `; charset=...` 这类参数，并且不区分大小写。
/// 浏览器上传文件的 `multipart/form-data` 也是表单，但它正是审计目标，
/// 因此刻意不在这里匹配。
fn is_urlencoded_form(content_type: Option<&str>) -> bool {
    const FORM: &str = "application/x-www-form-urlencoded";

    content_type.is_some_and(|value| {
        let essence = value.split(';').next().unwrap_or(value).trim();
        essence.eq_ignore_ascii_case(FORM)
    })
}

/// 共用判定：`declared_size` 是客户端声明的请求体长度（没有就 `None`），
/// `framing` 是这一路请求体的成帧形态，`has_body` 表示确实带着请求体。
///
/// 返回 `Some(形态)` 即"这条请求送审"，`None` 即"直通、一个 ICAP 字节都不发"。
fn upload_audit_allowed(
    cfg: &H1InterceptionConfig,
    has_body: bool,
    declared_size: Option<u64>,
    framing: UploadBodyFraming,
    content_type: Option<&str>,
) -> Option<UploadBodyFraming> {
    if !has_body {
        return None;
    }

    if cfg.req_skip_urlencoded_form && is_urlencoded_form(content_type) {
        return None;
    }

    // 兼容模式：没有开启体过滤时，有体即审，不看阈值也不看长度是否可知
    if !cfg.req_hasbody {
        return Some(framing);
    }

    // 长度不可预先得知：这类请求现实里几乎都是流式上传，宁可多审不漏
    match declared_size {
        Some(size) => (size > cfg.req_body_min_size as u64).then_some(framing),
        None => Some(framing),
    }
}

/// H1 请求的送审判定：形态取自成帧方式，长度取自 `Content-Length`。
pub(crate) fn h1_upload_audit(
    cfg: &H1InterceptionConfig,
    body_type: Option<HttpBodyType>,
    content_type: Option<&str>,
) -> Option<UploadBodyFraming> {
    let (framing, declared_size) = match body_type? {
        HttpBodyType::Chunked => (UploadBodyFraming::Chunked, None),
        HttpBodyType::ContentLength(size) => (UploadBodyFraming::ContentLength, Some(size)),
        // 读到连接关闭为止：没有长度可言，也不属于这一路的正常请求体
        HttpBodyType::ReadUntilEnd => return None,
    };

    upload_audit_allowed(cfg, true, declared_size, framing, content_type)
}

/// H2 请求的送审判定：H2 没有分块帧，长度只在客户端发了 `content-length` 时可知。
pub(crate) fn h2_upload_audit(
    cfg: &H1InterceptionConfig,
    has_body: bool,
    content_length: Option<u64>,
    content_type: Option<&str>,
) -> Option<UploadBodyFraming> {
    let framing = match content_length {
        Some(_) => UploadBodyFraming::ContentLength,
        None => UploadBodyFraming::Stream,
    };

    upload_audit_allowed(cfg, has_body, content_length, framing, content_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(req_hasbody: bool, min_size: usize, skip_form: bool) -> H1InterceptionConfig {
        H1InterceptionConfig {
            req_hasbody,
            req_body_min_size: min_size,
            req_skip_urlencoded_form: skip_form,
            ..Default::default()
        }
    }

    fn cl(size: u64) -> Option<HttpBodyType> {
        Some(HttpBodyType::ContentLength(size))
    }

    #[test]
    fn h1_no_body_is_not_audited() {
        let cfg = config(true, 0, false);
        assert_eq!(h1_upload_audit(&cfg, None, None), None);
        // 关掉体过滤也一样：无体请求没有可审的内容
        let legacy = config(false, 0, false);
        assert_eq!(h1_upload_audit(&legacy, None, None), None);
    }

    #[test]
    fn h1_content_length_uses_strict_greater_than() {
        let cfg = config(true, 100, false);
        assert_eq!(
            h1_upload_audit(&cfg, cl(100), None),
            None,
            "等于阈值不送审，阈值以下是'小请求'"
        );
        assert_eq!(
            h1_upload_audit(&cfg, cl(101), None),
            Some(UploadBodyFraming::ContentLength)
        );
        assert_eq!(h1_upload_audit(&cfg, cl(1), None), None);
    }

    #[test]
    fn h1_chunked_is_always_audited() {
        let cfg = config(true, 1024 * 1024, false);
        assert_eq!(
            h1_upload_audit(&cfg, Some(HttpBodyType::Chunked), None),
            Some(UploadBodyFraming::Chunked),
            "分块请求没有可信长度，按'有体即审'处理"
        );
    }

    #[test]
    fn h1_read_until_end_is_not_audited() {
        let cfg = config(true, 0, false);
        assert_eq!(h1_upload_audit(&cfg, Some(HttpBodyType::ReadUntilEnd), None), None);
    }

    #[test]
    fn h1_legacy_mode_audits_any_body() {
        // req_hasbody: false（库默认）保持既有语义：有体即审，阈值不参与
        let legacy = config(false, 65536, false);
        assert_eq!(
            h1_upload_audit(&legacy, cl(1), None),
            Some(UploadBodyFraming::ContentLength)
        );
    }

    #[test]
    fn h1_urlencoded_form_skipped_only_when_configured() {
        let form = Some("application/x-www-form-urlencoded");
        let cfg = config(true, 0, true);
        assert_eq!(h1_upload_audit(&cfg, cl(1 << 20), form), None);

        let no_skip = config(true, 0, false);
        assert_eq!(
            h1_upload_audit(&no_skip, cl(1 << 20), form),
            Some(UploadBodyFraming::ContentLength)
        );
    }

    #[test]
    fn h1_form_detection_ignores_charset_and_case() {
        let cfg = config(true, 0, true);
        for value in [
            "application/x-www-form-urlencoded; charset=utf-8",
            "APPLICATION/X-WWW-FORM-URLENCODED",
            "  application/x-www-form-urlencoded  ",
        ] {
            assert_eq!(
                h1_upload_audit(&cfg, cl(1 << 20), Some(value)),
                None,
                "{value} 应识别为表单"
            );
        }
    }

    #[test]
    fn h1_multipart_upload_is_not_treated_as_form() {
        // 浏览器文件上传就是 multipart：它必须继续按阈值送审
        let cfg = config(true, 100, true);
        let multipart = Some("multipart/form-data; boundary=----WebKitFormBoundary");
        assert_eq!(
            h1_upload_audit(&cfg, cl(1 << 20), multipart),
            Some(UploadBodyFraming::ContentLength)
        );
        assert_eq!(h1_upload_audit(&cfg, cl(50), multipart), None);
    }

    #[test]
    fn h2_without_content_length_is_audited_as_stream() {
        let cfg = config(true, 1024 * 1024, true);
        assert_eq!(
            h2_upload_audit(&cfg, true, None, None),
            Some(UploadBodyFraming::Stream)
        );
        assert_eq!(h2_upload_audit(&cfg, false, None, None), None);
    }

    #[test]
    fn h2_with_content_length_uses_threshold() {
        let cfg = config(true, 100, true);
        assert_eq!(
            h2_upload_audit(&cfg, true, Some(101), None),
            Some(UploadBodyFraming::ContentLength)
        );
        assert_eq!(h2_upload_audit(&cfg, true, Some(100), None), None);
        assert_eq!(
            h2_upload_audit(&cfg, true, Some(1000), Some("application/x-www-form-urlencoded")),
            None
        );
    }

    #[test]
    fn framing_tag_values() {
        assert_eq!(UploadBodyFraming::ContentLength.as_str(), "content-length");
        assert_eq!(UploadBodyFraming::Chunked.as_str(), "chunked");
        assert_eq!(UploadBodyFraming::Stream.as_str(), "stream");
    }

    #[test]
    fn protocol_tags_are_uppercase_scheme_and_dotted_version() {
        assert_eq!(scheme_tag(false), "HTTP");
        assert_eq!(scheme_tag(true), "HTTPS");
        assert_eq!(http_version_tag(Version::HTTP_10), Some("1.0"));
        assert_eq!(http_version_tag(Version::HTTP_11), Some("1.1"));
        assert_eq!(http_version_tag(Version::HTTP_2), Some("2.0"));
    }
}
