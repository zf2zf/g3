/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! H2 连接逻辑流并发计数。
//!
//! [`H2ConcurrencyStats`] 被连接状态机与所有流子任务共享（Arc 引用计数），
//! 用于：连接空闲判定（存活子任务为 0 才累加空闲次数）以及审计日志中的
//! 流统计字段。

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// 一条 H2 连接上的子任务（逻辑流）计数，跨任务线程安全共享。
pub(crate) struct H2ConcurrencyStats {
    /// 累计创建过的子任务总数，只增不减
    total_task: AtomicU64,
    /// 当前存活的子任务数，流启动时加一、结束时减一
    alive_task: AtomicI32,
}

impl Default for H2ConcurrencyStats {
    fn default() -> Self {
        H2ConcurrencyStats {
            total_task: AtomicU64::new(0),
            alive_task: AtomicI32::new(0),
        }
    }
}

impl H2ConcurrencyStats {
    /// 新流任务启动时登记：总数与存活数各加一。
    pub(super) fn add_task(&self) {
        self.total_task.fetch_add(1, Ordering::Relaxed);
        self.alive_task.fetch_add(1, Ordering::Release);
    }

    /// 流任务结束时注销：仅存活数减一（总数保留用于统计）。
    pub(super) fn del_task(&self) {
        self.alive_task.fetch_sub(1, Ordering::Release);
    }

    /// 读取累计子任务总数（仅用于日志，Relaxed 足够）。
    pub(super) fn get_total_task(&self) -> u64 {
        self.total_task.load(Ordering::Relaxed)
    }

    /// 读取当前存活子任务数；空闲判定据此判断连接是否无在途流。
    /// Acquire 与 add/del 的 Release 配对，保证跨任务的可见性顺序。
    pub(super) fn get_alive_task(&self) -> i32 {
        self.alive_task.load(Ordering::Acquire)
    }
}
