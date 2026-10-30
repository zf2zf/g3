/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::collections::HashSet;

use anyhow::{Context, anyhow};
use log::debug;
use tokio::sync::Mutex;

use g3_types::metrics::NodeName;
use g3_yaml::YamlDocPosition;

use super::registry;
use crate::audit::Auditor;
use crate::config::audit::AuditorConfig;

// 审计节点的生命周期管理：把配置文件里的 auditor 定义同步进 registry（新建 / 替换 / 删除），
// 并在每次变更后通知依赖这些节点的模块（serve 各服务器、escape 逃逸任务）刷新其审计句柄。

/// 串行化所有审计节点的装载与热加载动作。
/// 避免并发的全量重载与单节点重载交叉执行，导致"读旧配置 -> 写注册表"之间出现不一致。
static AUDITOR_OPS_LOCK: Mutex<()> = Mutex::const_new(());

/// 全量同步：让注册表内容与当前配置中的 auditor 定义完全一致。
///
/// 分两步：
/// 1. 遍历配置里的每个 auditor —— 已存在则替换（reload），不存在则新建（spawn）；
/// 2. 遍历注册表里剩余的节点，凡不在 new_names（本次配置出现的名字）中的即删除。
///
/// 任一节点处理失败都会立即返回 Err，本次同步的剩余节点不再继续。
pub async fn load_all() -> anyhow::Result<()> {
    let _guard = AUDITOR_OPS_LOCK.lock().await;

    let mut new_names = HashSet::<NodeName>::new();

    let all_config = crate::config::audit::get_all();
    for config in all_config {
        let name = config.name();
        new_names.insert(name.clone());
        match registry::get_config(name) {
            Some(old) => {
                debug!("reloading auditor {name}");
                reload_old_unlocked(old, config.as_ref().clone()).await?;
                debug!("auditor {name} reload OK");
            }
            None => {
                debug!("creating auditor {name}");
                spawn_new_unlocked(config.as_ref().clone()).await?;
                debug!("auditor {name} create OK");
            }
        }
    }

    // 配置中已不再定义的节点：删除并通知依赖方。
    // 依赖方（引用该 auditor 的服务器/逃逸任务）收到通知后会重新获取审计句柄，
    // 此时走 get_or_insert_default 回落到空配置节点，等价于停止审计。
    for name in &registry::get_names() {
        if !new_names.contains(name) {
            debug!("deleting auditor {name}");
            registry::del(name);
            crate::serve::update_dependency_to_auditor(name, "deleted").await;
            crate::escape::update_dependency_to_auditor(name, "deleted").await;
            debug!("auditor {name} deleted");
        }
    }

    Ok(())
}

/// 单节点热加载：按名字从 YAML 原始位置重新读取该 auditor 的配置并替换注册表中的实例。
///
/// position 为 None 时回落到旧配置里记录的文档位置；若旧实例是空配置兜底创建的
/// （没有来源位置），则无法定位配置文本，直接报错而不支持热加载。
pub(crate) async fn reload(
    name: &NodeName,
    position: Option<YamlDocPosition>,
) -> anyhow::Result<()> {
    let _guard = AUDITOR_OPS_LOCK.lock().await;

    let old_config = match registry::get_config(name) {
        Some(config) => config,
        None => return Err(anyhow!("no auditor with name {name} found")),
    };

    let position = match position {
        Some(position) => position,
        None => match old_config.position() {
            Some(position) => position,
            None => {
                return Err(anyhow!(
                    "no config position for auditor {name} found, reload is not supported"
                ));
            }
        },
    };

    // 解析 YAML 是阻塞 IO，放到 blocking 线程池执行，避免卡住当前 runtime worker
    let position2 = position.clone();
    let config =
        tokio::task::spawn_blocking(move || crate::config::audit::load_at_position(&position2))
            .await
            .map_err(|e| anyhow!("unable to join conf load task: {e}"))?
            .context(format!("unload to load conf at position {position}"))?;
    // 文档可能在 reload 期间被编辑过，位置对应的节点已改名；此时必须拒绝，否则会误替换别的节点
    if name != config.name() {
        return Err(anyhow!(
            "auditor at position {position} has name {}, while we expect {name}",
            config.name()
        ));
    }

    debug!("reloading auditor {name} from position {position}");
    reload_old_unlocked(old_config, config).await?;
    debug!("auditor {name} reload OK");
    Ok(())
}

/// 用新配置替换已有节点，并通知依赖方。
/// 名字后缀 _unlocked 表示"假定调用方已持有 AUDITOR_OPS_LOCK"，本函数自身不再加锁。
async fn reload_old_unlocked(old: AuditorConfig, new: AuditorConfig) -> anyhow::Result<()> {
    let name = old.name();
    let Some(old_auditor) = registry::get(name) else {
        return Err(anyhow!("no auditor with name {name} found"));
    };
    // 旧实例只作为"如何构造新实例"的参照（如密钥轮转器能否复用），替换后不再被使用
    let new_auditor = old_auditor.reload(new)?;
    registry::add(name.clone(), new_auditor);
    crate::serve::update_dependency_to_auditor(name, "reloaded").await;
    crate::escape::update_dependency_to_auditor(name, "reloaded").await;
    Ok(())
}

/// 首次创建节点并通知依赖方；同样要求调用方已持有 AUDITOR_OPS_LOCK。
async fn spawn_new_unlocked(config: AuditorConfig) -> anyhow::Result<()> {
    let name = config.name().clone();
    let auditor = Auditor::new_with_config(config)?;
    registry::add(name.clone(), auditor);
    crate::serve::update_dependency_to_auditor(&name, "spawned").await;
    crate::escape::update_dependency_to_auditor(&name, "spawned").await;
    Ok(())
}
