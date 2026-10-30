/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! IMAP 扩展能力（CAPABILITY）白名单。
//!
//! [`Capability::check_supported`] 是逐行的能力名过滤器：识别的扩展原样放行
//! （Some），未知或本机明确不支持的扩展被丢弃（None）。用于改写问候行、
//! `* CAPABILITY`/`* ENABLED` 响应及 ENABLE 请求，使客户端只会看到代理能
//! 正确中继/改写的扩展，避免未检测路径泄漏。

#[derive(Default)]
pub(super) struct Capability {
    /// 服务器声明支持 IMAP4rev1（RFC 3501 基线）
    imap4_rev1: bool,
    /// 仅在 ENABLE 阶段确认的 IMAP4rev2（RFC 9051）
    imap4_rev2: bool,
    /// 出现过 LITERAL+/LITERAL- 任一非同步字面量扩展（RFC 7888）
    has_non_sync_literal: bool,
    /// 服务器声明 LOGINDISABLED：禁止明文 LOGIN，只允许 SASL/STARTTLS
    login_disabled: bool,
}

impl Capability {
    /// 判断能力名 `cap` 是否放行。放行返回 Some(原样字符串)，同时把有状态含义
    /// 的项记录进 self；不认识的、以及 COMPRESS/CATENATE/URL-PARTIAL/
    /// UNAUTHENTICATE 等明确不支持的项返回 None（调用方据此从行中剔除）。
    /// `from_enable` 为 true 表示该项来自 `* ENABLED` 响应——IMAP4rev2 只有
    /// 在 ENABLE 确认后才记录（CAPABILITY 列表里出现不代表已启用）
    pub(super) fn check_supported<'a>(
        &mut self,
        cap: &'a str,
        from_enable: bool,
    ) -> Option<&'a str> {
        // NAME=VALUE 形式的参数化能力（RFC 5255 等）：只按前缀判断合法性，
        // 参数值原样透传
        if let Some(p) = memchr::memchr(b'=', cap.as_bytes()) {
            let name = &cap[..p];
            match name.as_bytes() {
                b"AUTH" => {}
                b"CONTEXT" => {}            // rfc5267
                b"I18NLEVEL" => {}          // rfc5255
                b"STATUS" => {}             // rfc8438
                b"QUOTA" => {}              // rfc9208
                b"RIGHTS" => {}             // rfc4314
                b"APPENDLIMIT" => {}        // rfc7889
                b"COMPRESS" => return None, // rfc4978, no support
                b"IMAPSIEVE" => {}          // rfc6785
                b"SEARCH" => {}             // rfc6203
                b"SORT" => {}               // rfc5957
                b"URLAUTH" => {}            // rfc5524
                b"UTF8" => {}               // rfc6855
                _ => return None,
            }
        } else {
            let name = cap;

            match name.as_bytes() {
                b"IMAP4" => {}
                b"IMAP4rev1" => self.imap4_rev1 = true,
                b"IMAP4rev2" => {
                    if from_enable {
                        self.imap4_rev2 = true;
                    }
                }
                b"LOGINDISABLED" => self.login_disabled = true,
                b"STARTTLS" => {}
                b"UIDPLUS" => {}   // rfc4315, rev2
                b"SASL-IR" => {}   // rfc4959, rev2
                b"MOVE" => {}      // rfc6851, rev2
                b"ID" => {}        // rfc2971, rev2
                b"UNSELECT" => {}  // rfc3691, rev2
                b"CHILDREN" => {}  // rfc3348, rev2
                b"IDLE" => {}      // rfc2177, rev2
                b"NAMESPACE" => {} // rfc2342, rev2
                b"ESEARCH" => {}
                b"SEARCHRES" => {}                           // rfc5182, rev2
                b"ENABLE" => {}                              // rfc5161, rev2
                b"LIST-EXTENDED" => {}                       // rfc5258, rev2
                b"LIST-STATUS" => {}                         // rfc5819, rev2
                b"CREATE-SPECIAL-USE" | b"SPECIAL-USE" => {} // rfc6154, rev2
                b"LITERAL+" if !self.has_non_sync_literal => {
                    // rfc7888
                    self.has_non_sync_literal = true;
                }
                b"LITERAL-" if !self.has_non_sync_literal => {
                    // rfc7888, rev2
                    self.has_non_sync_literal = true;
                }
                b"BINARY" => {}                 // rfc3516, partially merged into rev2
                b"CONVERT" => {}                // rfc5259, require "BINARY"
                b"PARTIAL" => {}                // rfc9394
                b"ESORT" => {}                  // rfc5267
                b"SORT" | b"THREAD" => {}       // rfc5256
                b"LANGUAGE" => {}               // rfc5255
                b"MULTISEARCH" => {}            // rfc7377
                b"MULTIAPPEND" => {}            // rfc3502
                b"CONDSTORE" | b"QRESYNC" => {} // rfc7162
                b"QUOTA" | b"QUOTASET" => {}    // rfc9208
                b"ACL" => {}                    // rfc4314
                b"APPENDLIMIT" => {}            // rfc7889
                b"CATENATE" => return None,     // rfc4469, let's skip it
                b"URL-PARTIAL" => return None,  // rfc5550
                b"FILTERS" => {}                // rfc5466
                b"INPROGRESS" => {}             // rfc9585
                b"LIST-METADATA" => {}          // rfc9590
                b"LIST-MYRIGHTS" => {}          // rfc8440
                b"LOGIN-REFERRALS" => {}        // rfc2221
                b"MAILBOX-REFERRALS" => {}      // rfc2193
                b"METADATA" | b"METADATA-SERVER" => {} // rfc5464
                b"NOTIFY" => {}                 // rfc5465
                b"OBJECTID" => {}               // rfc8474
                b"PREVIEW" => {}                // rfc8970
                b"REPLACE" => {}                // rfc8508
                b"SAVEDATE" => {}               // rfc8514
                b"UIDONLY" => {}                // rfc9586
                b"UNAUTHENTICATE" => return None, // rfc8437, let's skip it
                b"URLAUTH" => {}                // rfc4467
                b"WITHIN" => {}                 // rfc5032
                _ => return None,
            }
        }

        Some(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal() {
        let mut cap = Capability::default();
        let s = cap.check_supported("LITERAL+", false).unwrap();
        assert_eq!(s, "LITERAL+")
    }
}
