/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use foldhash::fast::FixedState;

use g3_types::metrics::NodeName;

use super::Auditor;
use crate::audit::AuditorConfig;

// auditor 名字 -> 运行时实例 的全局注册表。
//
// 配置里可以定义多个 auditor 节点，服务器通过 auditor 名字引用其中之一。
// 热加载时先在注册表里查旧配置以决定"新建"还是"替换"，替换后由 ops 模块通知依赖方。
static RUNTIME_AUDITOR_REGISTRY: Mutex<HashMap<NodeName, Arc<Auditor>, FixedState>> =
    Mutex::new(HashMap::with_hasher(FixedState::with_seed(0)));

/// 写入一个审计节点；同名节点已存在则直接替换，
/// 旧实例在无人引用后释放，已派生并在使用中的任务句柄不受影响。
pub(super) fn add(name: NodeName, auditor: Arc<Auditor>) {
    let mut ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    if let Some(_old_group) = ht.insert(name, auditor) {}
}

/// 按名取实例，用于热加载时以旧实例为参照构造新实例。
pub(super) fn get(name: &NodeName) -> Option<Arc<Auditor>> {
    let ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    ht.get(name).cloned()
}

/// 删除一个审计节点（配置里已不再定义该名字时调用）。
/// 已派生的任务句柄持有 Arc，因此不会因删除而失效。
pub(super) fn del(name: &NodeName) {
    let mut ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    if let Some(_old_auditor) = ht.remove(name) {}
}

/// 当前所有已装载的审计节点名，用于 load_all 里找出被删除的节点。
pub(crate) fn get_names() -> HashSet<NodeName> {
    let mut names = HashSet::new();
    let ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    for key in ht.keys() {
        names.insert(key.clone());
    }
    names
}

/// 取出节点配置的副本，用于判断节点是否已存在（以及取回其 YAML 位置供热加载定位）。
pub(super) fn get_config(name: &NodeName) -> Option<AuditorConfig> {
    let ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    ht.get(name).map(|a| a.config.as_ref().clone())
}

/// 按名取节点；不存在时插入一个空配置的占位节点并返回。
///
/// 服务器引用了未定义的 auditor 名时走这条路径，等价于"该服务器不做审计"，
/// 从而避免每处引用都要处理 None。
pub(crate) fn get_or_insert_default(name: &NodeName) -> Arc<Auditor> {
    let mut ht = RUNTIME_AUDITOR_REGISTRY.lock().unwrap();
    ht.entry(name.clone())
        .or_insert_with(|| Auditor::new_no_config(name))
        .clone()
}
