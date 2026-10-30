/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use g3_io_ext::{ArcLimitedReaderStats, LimitedReaderStats};

use super::HttpProxyServerStats;

/// 客户端读取器（LimitedBufReader）的字节统计回调：
/// 把排空非可信请求体时读到的字节数累计到服务器的 untrusted 上行流量指标。
pub(super) struct UntrustedCltReadWrapperStats {
    server: Arc<HttpProxyServerStats>,
}

impl UntrustedCltReadWrapperStats {
    /// 构造并装箱为读取器可持有的 Arc 统计对象
    pub(super) fn new_obj(server: &Arc<HttpProxyServerStats>) -> ArcLimitedReaderStats {
        let stats = UntrustedCltReadWrapperStats {
            server: Arc::clone(server),
        };
        Arc::new(stats)
    }
}

// 实现 io-ext 的读取统计 trait，供限速读取器在每次读取后回报字节数
impl LimitedReaderStats for UntrustedCltReadWrapperStats {
    fn add_read_bytes(&self, size: usize) {
        self.server.io_untrusted.add_in_bytes(size as u64);
    }
}
