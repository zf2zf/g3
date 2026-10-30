/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 流水线在途请求计数。
//!
//! [`PipelineStats`] 由请求解析任务与主循环共享：解析任务每送出一个请求就
//! `add_task`，主循环处理完一个再 `del_task`。解析任务依据存活任务数决定
//! 空闲超时时是否直接终止连接（还有在途请求时不能算客户端已死）。

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// 流水线统计（原子计数，Relaxed 序即可：只用于粗粒度判断，无需严格同步点）。
pub(crate) struct PipelineStats {
    total_task: AtomicU64,
    alive_task: AtomicI32,
}

impl Default for PipelineStats {
    fn default() -> Self {
        PipelineStats {
            total_task: AtomicU64::new(0),
            alive_task: AtomicI32::new(0),
        }
    }
}

impl PipelineStats {
    /// 新请求进入流水线：累计总数并递增在途计数
    pub(super) fn add_task(&self) {
        self.total_task.fetch_add(1, Ordering::Relaxed);
        self.alive_task.fetch_add(1, Ordering::Relaxed);
    }

    /// 请求处理完毕：递减在途计数（total 保留供日后排查使用）
    pub(crate) fn del_task(&self) {
        self.alive_task.fetch_sub(1, Ordering::Relaxed);
    }

    /// 当前在途（已解析未完结）的请求数
    pub(super) fn get_alive_task(&self) -> i32 {
        self.alive_task.load(Ordering::Relaxed)
    }
}
