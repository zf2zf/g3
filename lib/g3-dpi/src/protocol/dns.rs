/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! TCP 上 DNS 报文的识别。
//!
//! DNS over TCP 与 UDP 的差别只在于报文前多了一个 **2 字节大端长度前缀**：
//!
//! ```text
//! 长度前缀(2)            DNS 报文头(12)
//! +--------------+-----------------------------------------------+
//! | message_len  | ID(2) | flags(2) | QDCOUNT(2) | ANCOUNT(2) |
//! | (be16)       |       | QR@bit15 | NSCOUNT(2) | ARCOUNT(2) |
//! +--------------+-----------------------------------------------+
//! ```
//!
//! 判定只看三处，不解析任何域名（QNAME）：
//! 1. 长度前缀自洽：声明的报文长度不小于固定头 12 字节。
//! 2. `flags` 的 QR 位为 0 —— 只认**请求**方向；响应（QR=1）由上层按会话方向处理。
//! 3. ANCOUNT / NSCOUNT / ARCOUNT 全为 0 —— 客户端发出的首个查询不会携带答案资源记录。
//!
//! 难点在于 DNS 头没有魔数，ID 与 flags 都是任意取值，因此只能靠上述结构性约束
//! 排除随机数据；本函数位于客户端方向的分派表里，服务端 greeting 不参与 DNS 判定。

use super::{Protocol, ProtocolInspectError, ProtocolInspectState};

/// DNS 固定报文头长度：ID(2) + flags(2) + 四个计数各 2 字节。
const DNS_MESSAGE_HEADER_LEN: usize = 12;

impl ProtocolInspectState {
    /// 识别 TCP 上带 2 字节大端长度前缀的 DNS 查询报文。
    pub(crate) fn check_dns_tcp_request_message(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        // 2 Byte Length + Header
        // 至少要读到长度前缀加完整固定头，才有足够信息下结论
        const MINIMUM_DATA_LEN: usize = 2 + DNS_MESSAGE_HEADER_LEN;

        let data_len = data.len();
        if data_len < MINIMUM_DATA_LEN {
            return Err(ProtocolInspectError::NeedMoreData(
                MINIMUM_DATA_LEN - data_len,
            ));
        }

        // data[0..2] 为大端长度前缀，自述其后 DNS 报文的字节数
        let message_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if message_len < DNS_MESSAGE_HEADER_LEN {
            // 声明长度连固定头都装不下，自相矛盾，必不是 DNS
            self.exclude_current();
            return Ok(None);
        }

        // 跳过 2 字节长度前缀，从 DNS 报文头起始处做结构性校验
        if self.check_dns_request_message_header(&data[2..]).is_err() {
            self.exclude_current();
            return Ok(None);
        }

        Ok(Some(Protocol::Dns))
    }

    /// 校验 DNS 固定头（`hdr` 已去掉长度前缀）。
    ///
    /// 只做两处判断：QR 位必须是查询、答案/权威/附加三段计数必须全为 0。
    /// 返回 `Err(())` 仅表示“这批字节不符合 DNS 查询头”，由调用方负责排除候选。
    fn check_dns_request_message_header(&mut self, hdr: &[u8]) -> Result<(), ()> {
        // hdr[0..2] 为报文 ID，hdr[2..4] 为 flags；QR 位于 flags 高位字节（hdr[2]）的最高位
        if hdr[2] & 0b1000_0000 != 0 {
            // QR bit is not query
            // QR=1 是响应，本方向只识别客户端发起的查询
            return Err(());
        }

        // hdr[6..12] 依次是 ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)；
        // QDCOUNT(hdr[4..6]) 不校验，因为查询至少要带一个问题、取值不固定
        if hdr[6..DNS_MESSAGE_HEADER_LEN] != [0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
            // there should be no any an / ns / ar count
            // 新建查询不应携带任何答案/权威/附加记录
            return Err(());
        }

        Ok(())
    }
}
