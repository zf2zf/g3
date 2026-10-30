/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! [`ProtocolInspector`]：协议识别的驱动状态机。
//!
//! # 识别顺序
//!
//! 每批首包数据按以下优先级依次尝试，任一探测器给出 `Some(Protocol)` 即定论返回：
//!
//! 1. `state.current` —— 上一轮因数据不足而挂起的那个候选（延续上下文，避免重头猜）。
//! 2. `next_check_protocol` 队列 —— 上层显式塞入的候选，例如 ALPN 结果
//!    （[`ProtocolInspector::push_alpn_protocol`]）。
//! 3. 端口表命中 —— `server_portmap.get(server_port)` 给出的该端口常用协议。
//! 4. 全局猜测表 —— [`GUESS_PROTOCOL_FOR_CLIENT_INITIAL_DATA`] /
//!    [`GUESS_PROTOCOL_FOR_SERVER_INITIAL_DATA`]，覆盖端口不在表里的情况。
//!
//! 第 3、4 步合起来只执行一次（由 `guess_protocols` 标志控制）：因为首包数据一旦
//! 不足以定论，下一轮再重复同样的猜测只是浪费，此时应聚焦于已挂起的那个候选。
//!
//! # 排除机制
//!
//! 各协议的特征首字节集合大多互斥。例如某个载荷被确认为 TLS 记录（`data[0] == 0x16`），
//! 就永远不可能是 SSH（以 `SSH-` 开头）或 HTTP（以方法名 ASCII 开头）。探测器据此调用
//! [`ProtocolInspectState::exclude_other`] 把互斥候选一次性剔除，
//! 这样后续轮次不必重复试错，也避免半截数据被误判成别的协议。
//!
//! # 数据不足（NeedMoreData）
//!
//! 探测器若判断“这看着像我，但字节还不够”，返回
//! [`ProtocolInspectError::NeedMoreData(n)`]，`n` 是还需要读的字节数。
//! 这些挂起项进入 `read_pending_set`；全部候选尝试完后由
//! [`ProtocolInspector::handle_read_pending`] 汇总：取所需字节数的最小值作为下一次
//! 读取目标（一次 I/O 尽量同时满足多个候选），并把其余候选退回
//! `next_check_protocol` 队列留待下轮。

use std::collections::VecDeque;
use std::sync::Arc;

use fixedbitset::FixedBitSet;

use g3_types::net::AlpnProtocol;

use super::{MaybeProtocol, Protocol, ProtocolPortMap};
use crate::{ProtocolInspectionConfig, ProtocolInspectionSizeLimit};

/// 客户端先说话时值得猜测的协议。
///
/// 只列“客户端首包就自带足够特征”的协议：TLS ClientHello、HTTP 请求行、
/// SSH 版本协商、SMPP PDU、BitTorrent 握手。
/// 反过来 FTP / SMTP / POP3 / IMAP / NNTP / NATS 是服务端先发 greeting，
/// 拿客户端数据去猜它们没有意义，因此不在这里出现。
const GUESS_PROTOCOL_FOR_CLIENT_INITIAL_DATA: &[MaybeProtocol] = &[
    MaybeProtocol::Ssl,
    MaybeProtocol::Http,
    MaybeProtocol::Ssh,
    MaybeProtocol::Smpp,
    MaybeProtocol::BitTorrent,
];
/// 服务端先说话时值得猜测的协议。
///
/// 这组以文本 greeting 类协议为主。`Ssh` 与 `BitTorrent` 同时出现在两张表里，
/// 因为这两个协议在**两个方向上的首包格式完全相同**：SSH 双方都发
/// `SSH-x.y-...` 版本行，BitTorrent 双方都发 `19 + "BitTorrent protocol" + ...`
/// 握手，所以同一份探测器在任一方向上都能用。
const GUESS_PROTOCOL_FOR_SERVER_INITIAL_DATA: &[MaybeProtocol] = &[
    MaybeProtocol::Ssh,
    MaybeProtocol::Ftp,
    MaybeProtocol::Nats,
    MaybeProtocol::BitTorrent,
];

#[derive(Debug)]
pub enum ProtocolInspectError {
    /// 当前载荷仍可能是某协议，但需要再多读 `n` 字节才能定论。
    ///
    /// 这是正常路径而非失败：调用方应读满 `n` 字节后重新调用同一个 check 方法。
    NeedMoreData(usize),
}

/// 单条连接的识别进度。
///
/// 每个连接一个实例，随连接生命周期销毁；不含任何跨连接状态。
pub(crate) struct ProtocolInspectState {
    /// 上一轮判定“数据不足”而挂起的候选协议。
    /// 每轮 check 开头会被取出并优先重试；`None` 表示没有挂起项。
    current: Option<MaybeProtocol>,
    /// 已确定不可能的候选集合，按 `MaybeProtocol as usize` 作下标。
    /// 用位图是因为检查极频繁而候选总数只有 `_MaxSize`（约 30）个。
    excluded: FixedBitSet,
}

impl Default for ProtocolInspectState {
    fn default() -> Self {
        ProtocolInspectState {
            current: None,
            // 按候选总数预分配，避免识别过程中位图扩容
            excluded: FixedBitSet::with_capacity(MaybeProtocol::_MaxSize as usize),
        }
    }
}

impl ProtocolInspectState {
    /// 把某个候选标记为不可能。
    ///
    /// 由各协议探测器在确认自身特征后调用，用于剔除首字节集合互斥的其他协议。
    pub(crate) fn exclude_other(&mut self, protocol: MaybeProtocol) {
        self.excluded.insert(protocol as usize);
    }

    fn excluded(&self, protocol: MaybeProtocol) -> bool {
        self.excluded.contains(protocol as usize)
    }

    /// 把**当前挂起的候选自己**标记为不可能并清空 `current`。
    ///
    /// 用于两种情形：载荷已明确不符（如版本号非法），以及该协议在此方向上
    /// 本就不该被尝试（见分派表里的文本协议分支）。
    /// 之所以必须同时写入 `excluded`，是因为调用方还会把数据继续喂给同一候选，
    /// 若不记录排除原因就会导致反复试错。
    pub(crate) fn exclude_current(&mut self) {
        if let Some(p) = self.current.take() {
            self.excluded.insert(p as usize);
        }
    }

    #[inline]
    fn take_current(&mut self) -> Option<MaybeProtocol> {
        self.current.take()
    }

    #[inline]
    fn set_current(&mut self, protocol: MaybeProtocol) {
        self.current = Some(protocol);
    }

    /// 清空识别进度，回到“尚未开始猜”的状态。
    ///
    /// 由上层在协议协商重置时调用（例如 STARTTLS 升级完成后要按内层协议重识别）。
    fn reset_state(&mut self) {
        self.current = None;
        self.excluded.clear();
    }

    /// 客户端方向的分派表：按 `proto` 调用对应的载荷探测器。
    ///
    /// 返回值语义：`Ok(Some(p))` 已确认；`Ok(None)` 判定不是它（已自行排除）；
    /// `Err(NeedMoreData)` 需要更多数据。
    ///
    /// 注意函数先无条件 `self.current = Some(proto)` 再分派：因为探测器内部会用
    /// [`ProtocolInspectState::exclude_current`]，而它依赖 `current` 指向刚检查的这个候选。
    fn check_client_initial_data_for_protocol(
        &mut self,
        proto: MaybeProtocol,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        if self.excluded(proto) {
            return Ok(None);
        }
        self.current = Some(proto);
        match proto {
            MaybeProtocol::Ssh => self.check_ssh_client_protocol_version_exchange(data),
            MaybeProtocol::Dns => self.check_dns_tcp_request_message(data),
            MaybeProtocol::Ldap => self.check_ldap_tcp_request_message(data, size_limit),
            MaybeProtocol::Http => self.check_http_request(data, size_limit),
            MaybeProtocol::Ssl => self.check_ssl_client_hello(data),
            MaybeProtocol::Rtsp => self.check_rtsp_client_setup_request(data),
            MaybeProtocol::Mqtt => self.check_mqtt_client_connect_request(data),
            MaybeProtocol::Stomp => self.check_stomp_client_connect_request(data),
            MaybeProtocol::Smpp => self.check_smpp_session_request(data),
            MaybeProtocol::Rtmp => self.check_rtmp_tcp_client_handshake(data),
            MaybeProtocol::BitTorrent => self.check_bittorrent_tcp_handshake(data),
            // 这些协议由服务端先发 greeting，客户端首包不含可判定特征，
            // 直接排除本候选而不是误判。
            MaybeProtocol::Ftp
            | MaybeProtocol::Smtp
            | MaybeProtocol::Odmr
            | MaybeProtocol::Pop3
            | MaybeProtocol::Nntp
            | MaybeProtocol::Nnsp
            | MaybeProtocol::Imap
            | MaybeProtocol::Nats => {
                self.exclude_current();
                Ok(None)
            }
            // 带 s 后缀的“X over TLS”候选只是端口表里的语义标记，
            // 真正进入载荷检测前会被 portmap 拆成 Ssl + 明文协议，
            // 因此这里不可能出现；命中即调用方用法有误。
            MaybeProtocol::Https
            | MaybeProtocol::Submissions
            | MaybeProtocol::Pop3s
            | MaybeProtocol::Nntps
            | MaybeProtocol::Imaps
            | MaybeProtocol::Rtsps
            | MaybeProtocol::SecureMqtt
            | MaybeProtocol::Ssmpp
            | MaybeProtocol::Rtmps
            | MaybeProtocol::DnsOverTls
            | MaybeProtocol::Ldaps
            | MaybeProtocol::_MaxSize => {
                unreachable!()
            }
        }
    }

    /// 服务端方向的分派表：按 `proto` 检查 greeting / banner。
    ///
    /// 与客户端分派表互为镜像：这里能判定的正是“服务端先发言”的那批文本协议，
    /// 而 HTTP / MQTT / LDAP 等由客户端先开口的协议直接排除。
    /// SMTP 与 ODMR 共用一个探测器——二者 greeting 相同（`220 `）。
    fn check_server_initial_data_for_protocol(
        &mut self,
        proto: MaybeProtocol,
        data: &[u8],
        size_limit: &ProtocolInspectionSizeLimit,
    ) -> Result<Option<Protocol>, ProtocolInspectError> {
        if self.excluded(proto) {
            return Ok(None);
        }
        self.current = Some(proto);
        match proto {
            MaybeProtocol::Ftp => self.check_ftp_server_greeting(data, size_limit),
            MaybeProtocol::Ssh => self.check_ssh_server_protocol_version_exchange(data),
            MaybeProtocol::Smtp | MaybeProtocol::Odmr => self.check_smtp_server_greeting(data),
            MaybeProtocol::Pop3 => self.check_pop3_server_greeting(data),
            MaybeProtocol::Nntp | MaybeProtocol::Nnsp => self.check_nntp_server_greeting(data),
            MaybeProtocol::Imap => self.check_imap_server_greeting(data, size_limit),
            MaybeProtocol::Nats => self.check_nats_server_info_msg(data, size_limit),
            MaybeProtocol::BitTorrent => self.check_bittorrent_tcp_handshake(data),
            MaybeProtocol::Dns
            | MaybeProtocol::Ldap
            | MaybeProtocol::Ssl
            | MaybeProtocol::Http
            | MaybeProtocol::Rtsp
            | MaybeProtocol::Mqtt
            | MaybeProtocol::Stomp
            | MaybeProtocol::Smpp
            | MaybeProtocol::Rtmp => {
                self.exclude_current();
                Ok(None)
            }
            // 同客户端分派表：`X over TLS` 候选不会走到载荷检测
            MaybeProtocol::Https
            | MaybeProtocol::Submissions
            | MaybeProtocol::Pop3s
            | MaybeProtocol::Nntps
            | MaybeProtocol::Imaps
            | MaybeProtocol::Rtsps
            | MaybeProtocol::SecureMqtt
            | MaybeProtocol::Ssmpp
            | MaybeProtocol::Rtmps
            | MaybeProtocol::DnsOverTls
            | MaybeProtocol::Ldaps
            | MaybeProtocol::_MaxSize => {
                unreachable!()
            }
        }
    }
}

/// 一条因数据不足而挂起的候选协议。
struct ReadPendingProtocol {
    /// 还需要读取的字节数，用于向调用方回报下一次读取目标。
    size: usize,
    protocol: MaybeProtocol,
}

/// 协议识别器：一条连接一个实例。
///
/// 使用方式见本模块的模块级文档。它不持有 socket，也不自己读数据——
/// 每次调用喂入的是调用方已读到的**全部**首包缓冲（`data` 必须是从连接开始
/// 累积的完整前缀，而不是每次只喂新增的切片），因为多数探测器要从固定偏移
/// 解析报文头。
pub struct ProtocolInspector {
    /// 目标端口 -> 候选协议的表，用于猜测阶段缩小范围。
    ///
    /// 只用到 server 方向：识别的是“这条连接在对端跑什么协议”，
    /// 而判定依据是服务监听端口惯例。
    server_portmap: Arc<ProtocolPortMap>,
    state: ProtocolInspectState,
    /// 待检查候选队列。上层用 [`ProtocolInspector::push_protocol`]
    /// 把强证据（ALPN 等）插到队首，使其优先于端口表与猜测表。
    next_check_protocol: VecDeque<MaybeProtocol>,
    /// 禁止按 TLS 猜测：用于已经确定这条连接不会走 TLS 的场景
    /// （例如明文代理、或已完成 TLS 终结后要重内层协议）。
    no_explicit_ssl: bool,
    /// 本轮所有“需要更多数据”的挂起候选。
    read_pending_set: VecDeque<ReadPendingProtocol>,
    /// 是否还允许做端口表 / 猜测表推断。整条连接只在第一轮放开，
    /// 之后聚焦于已挂起的候选，见模块级文档。
    guess_protocols: bool,
}

impl Default for ProtocolInspector {
    fn default() -> Self {
        ProtocolInspector {
            server_portmap: Arc::new(ProtocolPortMap::tcp_server()),
            state: ProtocolInspectState::default(),
            next_check_protocol: VecDeque::with_capacity(4),
            no_explicit_ssl: false,
            read_pending_set: VecDeque::with_capacity(4),
            guess_protocols: true,
        }
    }
}

impl ProtocolInspector {
    /// 用给定的服务端端口表创建识别器。
    ///
    /// `_client_portmap` 目前未被使用：识别只看服务端端口惯例，
    /// 客户端源端口（临时端口）对判断协议没有信息量。保留该参数是为了
    /// 兼容上层已有的调用形态与配置结构。
    pub fn new(
        server_portmap: Arc<ProtocolPortMap>,
        _client_portmap: Arc<ProtocolPortMap>,
    ) -> Self {
        ProtocolInspector {
            server_portmap,
            state: ProtocolInspectState::default(),
            next_check_protocol: VecDeque::with_capacity(4),
            no_explicit_ssl: false,
            read_pending_set: VecDeque::with_capacity(4),
            guess_protocols: true,
        }
    }

    /// 把候选协议插入待检查队列**队首**，使其优先于其他候选被尝试。
    ///
    /// 多次调用时最后插入的最先被检查，符合“越新的证据越可信”的直觉。
    pub fn push_protocol(&mut self, p: MaybeProtocol) {
        self.next_check_protocol.push_front(p);
    }

    /// 把 TLS ALPN 协商结果作为高可信候选插入队首。
    pub fn push_alpn_protocol(&mut self, p: AlpnProtocol) {
        self.push_protocol(p.into());
    }

    /// 重置识别进度：清空当前候选与排除集合，并重新允许猜测。
    ///
    /// 典型时机是 TLS 握手完成后——外层 `Tls*` 已确定，需要对内层明文协议
    /// 从头识别，此时旧的排除结论不再适用。
    pub fn reset_state(&mut self) {
        self.state.reset_state();
        self.guess_protocols = true;
    }

    /// 关闭按 TLS 猜测，对应 `no_explicit_ssl` 标志。
    pub fn set_no_explicit_ssl(&mut self) {
        self.no_explicit_ssl = true;
    }

    /// 恢复按 TLS 猜测。
    pub fn unset_no_explicit_ssl(&mut self) {
        self.no_explicit_ssl = false;
    }

    /// 用客户端首包数据尝试识别协议。
    ///
    /// `server_port` 是目标服务端口，仅在猜测阶段用于查端口表缩小候选范围。
    /// `data` 必须是从连接起始累积的完整字节前缀。
    ///
    /// 返回 [`Protocol::Unknown`] 表示这批数据已把所有候选试完且无定论；
    /// 返回 [`ProtocolInspectError::NeedMoreData`] 表示按其中给出的字节数再读一次后重调本函数。
    pub fn check_client_initial_data(
        &mut self,
        config: &ProtocolInspectionConfig,
        server_port: u16,
        data: &[u8],
    ) -> Result<Protocol, ProtocolInspectError> {
        // 单个候选的检查结果统一按三分支处理：
        // - 定论 -> 直接返回，不再尝试其他候选
        // - 明确不是 -> 继续下一个
        // - 数据不足 -> 记入挂起队列，继续下一个（不要提前返回，
        //   否则会把本可定论的其他候选漏掉）
        macro_rules! check_protocol {
            ($p:expr) => {
                match self.state.check_client_initial_data_for_protocol(
                    $p,
                    data,
                    config.size_limit(),
                ) {
                    Ok(Some(p)) => return Ok(p),
                    Ok(None) => {}
                    Err(ProtocolInspectError::NeedMoreData(len)) => {
                        self.read_pending_set.push_back(ReadPendingProtocol {
                            size: len,
                            protocol: $p,
                        });
                    }
                }
            };
        }

        // 1) 优先延续上一轮挂起的候选
        if let Some(proto) = self.state.take_current() {
            check_protocol!(proto);
        }

        // 2) 上层显式指定的候选（ALPN 等强证据）
        while let Some(proto) = self.next_check_protocol.pop_front() {
            check_protocol!(proto);
        }

        // 3) + 4) 猜测阶段，整条连接只走一次
        if self.guess_protocols {
            if let Some(v) = self.server_portmap.get(server_port) {
                // 该端口被登记为 TLS 端口时先试 TLS：明文文本协议的端口
                // 不会置 check_ssl，所以这个分支只在 443/993 等端口触发
                if !self.no_explicit_ssl && v.check_ssl() {
                    check_protocol!(MaybeProtocol::Ssl);
                }

                for proto in v.protocols() {
                    check_protocol!(*proto);
                }
            }

            // 端口不在表里（或表内候选都不符）时，退回到通用的客户端首包猜测表
            for proto in GUESS_PROTOCOL_FOR_CLIENT_INITIAL_DATA {
                check_protocol!(*proto);
            }

            self.guess_protocols = false;
        }

        // 所有候选都没定论：若有挂起项则要求补数据，否则承认为 Unknown
        self.handle_read_pending()?;
        Ok(Protocol::Unknown)
    }

    /// 用服务端首包（greeting / banner）数据尝试识别协议。
    ///
    /// 与 [`ProtocolInspector::check_client_initial_data`] 结构相同，差别有两处：
    /// 猜测阶段不单独试 TLS（服务端首包不是 ClientHello），
    /// 以及使用服务端方向这份以文本协议为主的候选表。
    pub fn check_server_initial_data(
        &mut self,
        config: &ProtocolInspectionConfig,
        server_port: u16,
        data: &[u8],
    ) -> Result<Protocol, ProtocolInspectError> {
        macro_rules! check_protocol {
            ($p:expr) => {
                match self.state.check_server_initial_data_for_protocol(
                    $p,
                    data,
                    config.size_limit(),
                ) {
                    Ok(Some(p)) => return Ok(p),
                    Ok(None) => {}
                    Err(ProtocolInspectError::NeedMoreData(len)) => {
                        self.read_pending_set.push_back(ReadPendingProtocol {
                            size: len,
                            protocol: $p,
                        });
                    }
                }
            };
        }

        if let Some(proto) = self.state.take_current() {
            check_protocol!(proto);
        }

        while let Some(proto) = self.next_check_protocol.pop_front() {
            check_protocol!(proto);
        }

        if self.guess_protocols {
            if let Some(v) = self.server_portmap.get(server_port) {
                for proto in v.protocols() {
                    check_protocol!(*proto);
                }
            }

            for proto in GUESS_PROTOCOL_FOR_SERVER_INITIAL_DATA {
                check_protocol!(*proto);
            }

            self.guess_protocols = false;
        }

        self.handle_read_pending()?;
        Ok(Protocol::Unknown)
    }

    /// 汇总本轮所有“数据不足”的挂起候选，决定下一次要读多少字节。
    ///
    /// 策略：
    /// - 队首那个候选被设为 `state.current`，下一轮开头会被优先重试；
    ///   选择队首是因为它在本轮最先被尝试，通常也是证据最强的那个。
    /// - 所需字节数取所有挂起候选的**最小值**：尽量少读就能推进，
    ///   避免为了一个冷僻候选而要求过长前缀。
    /// - 其余候选退回 `next_check_protocol` 队列，等下一次调用时继续尝试，
    ///   不因一个候选挂起而丢掉其他候选。
    ///
    /// 返回 `Err(NeedMoreData(n))`；无挂起项时返回 `Ok(())`，
    /// 由调用方接着返回 `Protocol::Unknown`。
    fn handle_read_pending(&mut self) -> Result<(), ProtocolInspectError> {
        let Some(v) = self.read_pending_set.pop_front() else {
            return Ok(());
        };

        self.state.set_current(v.protocol);
        let mut pending_len = v.size;

        while let Some(v) = self.read_pending_set.pop_front() {
            if v.size < pending_len {
                pending_len = v.size;
            }
            self.next_check_protocol.push_front(v.protocol);
        }
        Err(ProtocolInspectError::NeedMoreData(pending_len))
    }
}
