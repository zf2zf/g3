/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 拦截策略与首包读取参数。
//!
//! 本目录提供两类配置，服务两个不同的问题：
//!
//! - **“这条连接要不要拆？”** —— [`ProtocolInspectPolicy`]，按目标主机名 / 网段
//!   给出 [`ProtocolInspectAction`]（放行 / 拦截 / 旁路 / 分流）。这是按目的地址做的
//!   准入决策，与识别算法无关。
//! - **“拆的时候要读多少、等多久？”** —— [`ProtocolInspectionConfig`]，
//!   含 [`ProtocolInspectionSizeLimit`] 与各协议专属的
//!   [`H1InterceptionConfig`] / [`SmtpInterceptionConfig`] / [`ImapInterceptionConfig`]。
//!
//! 注意 `H1InterceptionConfig` 等虽然定义在本 crate，但 DPI 自身的识别逻辑并不读它们；
//! 它们放在这里是为了让上层（g3proxy）的拦截配置有统一的定义处和默认值。

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use g3_types::acl::{
    AclChildDomainRule, AclChildDomainRuleBuilder, AclExactHostRule, AclNetworkRule,
    AclNetworkRuleBuilder, ActionContract,
};
use g3_types::net::Host;

mod size_limit;

pub use size_limit::ProtocolInspectionSizeLimit;

mod http;
pub use http::{H1InterceptionConfig, H2InterceptionConfig};

mod smtp;
pub use smtp::SmtpInterceptionConfig;

mod imap;
pub use imap::ImapInterceptionConfig;

/// [`ProtocolInspectPolicy`] 的可变构造器。
///
/// 三类规则各自独立可选，按“配置了就参与匹配”处理。
/// 之所以用 builder 而不是直接构造：规则类型（exact / child / subnet）来自
/// `g3_types::acl`，其中 `child` 与 `subnet` 需要先累积条目再 `build()`，
/// 中间态不适合放进最终的策略对象里。
#[derive(Clone)]
pub struct ProtocolInspectPolicyBuilder {
    /// 所有规则都未命中时采取的动作。
    missed_action: ProtocolInspectAction,
    /// 精确主机名 / IP 规则。
    pub exact: Option<AclExactHostRule<ProtocolInspectAction>>,
    /// 子域名规则（匹配 `example.com` 及其所有子域）。
    pub child: Option<AclChildDomainRuleBuilder<ProtocolInspectAction>>,
    /// 网段规则（CIDR 匹配 IP 型目标）。
    pub subnet: Option<AclNetworkRuleBuilder<ProtocolInspectAction>>,
}

impl Default for ProtocolInspectPolicyBuilder {
    /// 默认全部拦截：漏配规则时倾向于“宁可多拆”，符合 DPI 组件的安全预期。
    fn default() -> Self {
        Self::new(ProtocolInspectAction::Intercept)
    }
}

impl ProtocolInspectPolicyBuilder {
    /// 指定未命中时的默认动作，规则集合为空。
    pub fn new(missed_action: ProtocolInspectAction) -> Self {
        ProtocolInspectPolicyBuilder {
            missed_action,
            exact: None,
            child: None,
            subnet: None,
        }
    }

    /// 修改未命中时的默认动作。
    pub fn set_missed_action(&mut self, missed_action: ProtocolInspectAction) {
        self.missed_action = missed_action;
    }

    /// 冻结成只读策略对象。
    ///
    /// 会 clone 已累积的规则，因此之后继续改 builder 不影响已生成的策略；
    /// 反过来也意味着应当在配置加载阶段一次建好，别在连接路径上反复调用。
    pub fn build(&self) -> ProtocolInspectPolicy {
        ProtocolInspectPolicy {
            exact: self.exact.clone(),
            child: self.child.as_ref().map(|b| b.build()),
            subnet: self.subnet.as_ref().map(|b| b.build()),
            missed_action: self.missed_action,
        }
    }
}

/// 按目标地址决定是否拦截的策略表（只读）。
///
/// IP 型目标查 `exact` + `subnet`，域名型目标查 `exact` + `child`；
/// 二者的 `exact` 是同一张表，只是分别按 IP / 域名匹配。
/// 这种按地址类型分流的做法避免了把域名规则和网段规则混在一个 map 里查找。
pub struct ProtocolInspectPolicy {
    exact: Option<AclExactHostRule<ProtocolInspectAction>>,
    child: Option<AclChildDomainRule<ProtocolInspectAction>>,
    subnet: Option<AclNetworkRule<ProtocolInspectAction>>,
    missed_action: ProtocolInspectAction,
}

impl ProtocolInspectPolicy {
    /// 查询目标地址对应的动作。
    ///
    /// 返回 `(found, action)`：`found` 表示是否命中了显式规则，
    /// `action` 在 `found` 为 `false` 时是 `missed_action`。
    /// 调用方需要区分这两类情况——“显式允许”和“配置没提到所以默认允许”
    /// 在审计与排障时含义完全不同，所以不能只看 `action`。
    ///
    /// 匹配顺序为「精确优先，再泛化规则」：同一目标上精确主机规则会覆盖
    /// 子域 / 网段规则，让例外条款可以写在通配规则之后。
    pub fn check(&self, upstream: &Host) -> (bool, ProtocolInspectAction) {
        match upstream {
            Host::Ip(ip) => {
                if let Some(rule) = &self.exact {
                    let (found, action) = rule.check_ip(ip);
                    if found {
                        return (true, action);
                    }
                }

                // 精确 IP 未命中才落到网段规则
                if let Some(rule) = &self.subnet {
                    let (found, action) = rule.check(*ip);
                    if found {
                        return (true, action);
                    }
                }
            }
            Host::Domain(domain) => {
                if let Some(rule) = &self.exact {
                    let (found, action) = rule.check_domain(domain);
                    if found {
                        return (true, action);
                    }
                }

                // 精确域名未命中才落到子域规则
                if let Some(rule) = &self.child {
                    let (found, action) = rule.check(domain);
                    if found {
                        return (true, action);
                    }
                }
            }
        }

        (false, self.missed_action)
    }
}

/// 对一条连接的处置动作。
///
/// 这是策略层的结论，不涉及如何识别；默认值是 [`ProtocolInspectAction::Intercept`]，
/// 即未显式配置时倾向于拆开看。
#[derive(Clone, Copy, Debug, Default)]
pub enum ProtocolInspectAction {
    /// 直接拒绝连接，不建立到上游的转发。
    Block,
    /// 做 DPI 识别并按识别结果接管（这是正常路径，也是 `#[default]`）。
    #[default]
    Intercept,
    /// 原样隧道转发，不识别也不解析。
    Bypass,
    /// 转交给其他检测通道处理（仅在启用 `quic` feature 时可用）。
    #[cfg(feature = "quic")]
    Detour,
}

impl ProtocolInspectAction {
    /// 配置字符串形式，同时用于日志输出。
    fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Intercept => "intercept",
            Self::Bypass => "bypass",
            #[cfg(feature = "quic")]
            Self::Detour => "detour",
        }
    }

    /// 是否为拒绝动作。
    ///
    /// 上层在建立上游连接之前要单独判断这一项：`Block` 必须在连接上游之前生效，
    /// 而其他动作都是先连再处置。
    pub fn is_block(&self) -> bool {
        matches!(self, ProtocolInspectAction::Block)
    }
}

impl fmt::Display for ProtocolInspectAction {
    /// 输出 `as_str` 的形式，用于日志与审计字段。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProtocolInspectAction {
    type Err = ();

    /// 从配置字符串解析动作，大小写不敏感。
    ///
    /// `Detour` 只在启用 `quic` feature 时才解析得出来：未启用时配置里写
    /// `detour` 会被当作非法值报错，从而在加载阶段就暴露配置与二进制能力不匹配。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block" => Ok(ProtocolInspectAction::Block),
            "intercept" => Ok(ProtocolInspectAction::Intercept),
            "bypass" => Ok(ProtocolInspectAction::Bypass),
            #[cfg(feature = "quic")]
            "detour" => Ok(ProtocolInspectAction::Detour),
            _ => Err(()),
        }
    }
}

// 让本动作类型能装进 g3_types::acl 的泛型规则容器
impl ActionContract for ProtocolInspectAction {}

/// 首包读取参数。
///
/// 这些值决定识别阶段能读多少数据、能花多久——识别必须在
/// `data0_wait_timeout` 与 `data0_read_timeout` 之内结束，
/// 否则一条卡住的连接会一直占着资源。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolInspectionConfig {
    /// 最多尝试几轮“补数据后再识别”。
    ///
    /// 每一轮对应一次 [`ProtocolInspectError::NeedMoreData`](crate::ProtocolInspectError::NeedMoreData)
    /// 往返。设上限是为了防止对端持续挤牙膏式发送零碎字节、把识别阶段无限拉长。
    inspect_max_depth: usize,
    /// 首包累计读取的缓冲区大小，即识别阶段最多能拿到多少字节做判断。
    data0_buffer_size: usize,
    /// 等待首包就绪的总时长上限，超时则得到 [`Protocol::Timeout`](crate::Protocol::Timeout)。
    data0_wait_timeout: Duration,
    /// 单次读取操作的超时。
    data0_read_timeout: Duration,
    /// 各协议变长字段的扫描上限。
    data0_size_limit: ProtocolInspectionSizeLimit,
}

impl Default for ProtocolInspectionConfig {
    /// 默认值取向：宁可多等、多读，也要尽量给出确定结论——
    /// 识别失败的连接会退化为不拦截的隧道，因此准确率优先于延迟。
    /// 其中 4 秒的单次读超时是为了让卡死的对端不至于占满 60 秒的总等待窗口。
    fn default() -> Self {
        ProtocolInspectionConfig {
            inspect_max_depth: 4,
            data0_buffer_size: 4096,
            data0_wait_timeout: Duration::from_secs(60),
            data0_read_timeout: Duration::from_secs(4),
            data0_size_limit: Default::default(),
        }
    }
}

impl ProtocolInspectionConfig {
    // 以下均为成对的读写方法：setter 供配置加载阶段调用，
    // getter 供识别主循环每轮读取，因此 getter 都加 #[inline]。

    /// 设置最多尝试几轮补数据识别。
    pub fn set_max_depth(&mut self, depth: usize) {
        self.inspect_max_depth = depth;
    }

    /// 读取补数据识别的最大轮数。
    #[inline]
    pub fn max_depth(&self) -> usize {
        self.inspect_max_depth
    }

    /// 设置首包缓冲区大小（识别阶段可读的最大字节数）。
    pub fn set_data0_buffer_size(&mut self, size: usize) {
        self.data0_buffer_size = size;
    }

    /// 读取首包缓冲区大小。
    #[inline]
    pub fn data0_buffer_size(&self) -> usize {
        self.data0_buffer_size
    }

    /// 设置等待首包就绪的总时长上限。
    #[inline]
    pub fn set_data0_wait_timeout(&mut self, value: Duration) {
        self.data0_wait_timeout = value;
    }

    /// 读取等待首包就绪的总时长上限。
    #[inline]
    pub fn data0_wait_timeout(&self) -> Duration {
        self.data0_wait_timeout
    }

    /// 设置单次读取操作的超时。
    #[inline]
    pub fn set_data0_read_timeout(&mut self, value: Duration) {
        self.data0_read_timeout = value;
    }

    /// 读取单次读取操作的超时。
    #[inline]
    pub fn data0_read_timeout(&self) -> Duration {
        self.data0_read_timeout
    }

    /// 只读访问各协议的扫描字节上限，供探测器在热路径上取用。
    #[inline]
    pub fn size_limit(&self) -> &ProtocolInspectionSizeLimit {
        &self.data0_size_limit
    }

    /// 可变访问扫描字节上限，供配置加载阶段逐项覆盖默认值。
    #[inline]
    pub fn size_limit_mut(&mut self) -> &mut ProtocolInspectionSizeLimit {
        &mut self.data0_size_limit
    }
}
