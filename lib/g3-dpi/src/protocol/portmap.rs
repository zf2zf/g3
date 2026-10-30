/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 端口到候选协议的映射表。
//!
//! 这是识别过程里“先验知识”的来源：在猜测阶段，[`ProtocolInspector`] 会用目标
//! 服务端口查这张表，只尝试表里登记的协议，而不是把所有候选都试一遍。
//! 表的作用是**缩小范围与排序**，不是下结论——命中端口仍要靠载荷确认，
//! 未命中也只是退回通用猜测表。
//!
//! 用 `FnvHashMap` 而非标准 `HashMap`：键是小整数端口、查找极频繁，
//! FNV-1a 在这种形态下明显更快。

use fnv::FnvHashMap;

use super::MaybeProtocol;

/// 某个端口上登记的候选协议集合。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolPortMapValue {
    /// 该端口是否应先尝试按 TLS 记录解析。
    ///
    /// 单独用一个 bool 而不是把 [`MaybeProtocol::Ssl`] 放进 `protocols`，
    /// 是因为识别器需要在 TLS 猜测之外单独受
    /// [`no_explicit_ssl`](crate::ProtocolInspector::set_no_explicit_ssl) 控制。
    check_ssl: bool,
    /// 该端口上的明文候选协议，保持插入顺序（顺序即尝试优先级）。
    protocols: Vec<MaybeProtocol>,
}

impl Default for ProtocolPortMapValue {
    fn default() -> Self {
        ProtocolPortMapValue {
            check_ssl: false,
            // 一个端口通常只有一两个候选，预分配避免首次插入就扩容
            protocols: Vec::with_capacity(2),
        }
    }
}

impl ProtocolPortMapValue {
    pub(crate) fn check_ssl(&self) -> bool {
        self.check_ssl
    }

    #[inline]
    pub(crate) fn protocols(&self) -> &[MaybeProtocol] {
        self.protocols.as_slice()
    }

    /// 插入一个候选协议，并把“X over TLS”形态拆分成两个独立信息。
    ///
    /// [`MaybeProtocol::Https`] 这类带 `s` 后缀的变体是端口层面的语义标记，
    /// 载荷层面它等于「先按 TLS 解析，内层再按 HTTP 解析」。所以这里统一拆成
    /// `check_ssl = true` 加上内层明文协议；[`MaybeProtocol::Ssl`] 本身则只置标志位。
    ///
    /// 拆分后 [`MaybeProtocol::Https`] 等变体不会再进入识别器的分派表
    /// （那里的对应分支是 `unreachable!()`）。
    fn insert(&mut self, protocol: MaybeProtocol) {
        let p = match protocol {
            MaybeProtocol::Ssl => {
                self.check_ssl = true;
                return;
            }
            MaybeProtocol::Https => {
                self.check_ssl = true;
                MaybeProtocol::Http
            }
            MaybeProtocol::Submissions => {
                self.check_ssl = true;
                MaybeProtocol::Smtp
            }
            MaybeProtocol::Pop3s => {
                self.check_ssl = true;
                MaybeProtocol::Pop3
            }
            MaybeProtocol::Nntps => {
                self.check_ssl = true;
                MaybeProtocol::Nntp
            }
            MaybeProtocol::Imaps => {
                self.check_ssl = true;
                MaybeProtocol::Imap
            }
            MaybeProtocol::Rtsps => {
                self.check_ssl = true;
                MaybeProtocol::Rtsp
            }
            MaybeProtocol::SecureMqtt => {
                self.check_ssl = true;
                MaybeProtocol::Mqtt
            }
            MaybeProtocol::Ssmpp => {
                self.check_ssl = true;
                MaybeProtocol::Smpp
            }
            MaybeProtocol::Rtmps => {
                self.check_ssl = true;
                MaybeProtocol::Rtmp
            }
            MaybeProtocol::DnsOverTls => {
                self.check_ssl = true;
                MaybeProtocol::Dns
            }
            MaybeProtocol::Ldaps => {
                self.check_ssl = true;
                MaybeProtocol::Ldap
            }
            p => p,
        };
        if !self.protocols.contains(&p) {
            self.protocols.push(p);
        }
    }
}

/// 端口 -> 候选协议集合。
///
/// 该类型不可变使用（识别器只持有 `Arc`），配置加载阶段构造完毕后不再修改。
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProtocolPortMap {
    inner: FnvHashMap<u16, ProtocolPortMapValue>,
}

impl ProtocolPortMap {
    /// 空表：不携带任何端口先验，识别完全依赖上层推入的候选与通用猜测表。
    pub fn empty() -> Self {
        ProtocolPortMap {
            inner: FnvHashMap::default(),
        }
    }

    /// 一次性为某端口登记多个候选协议。
    ///
    /// 切片顺序即尝试顺序，可用于表达“这个端口优先当 HTTP，不行再当 RTSP”这类偏好。
    pub fn insert_batch(&mut self, port: u16, protocols: &[MaybeProtocol]) {
        let node = self.inner.entry(port).or_default();
        for protocol in protocols {
            node.insert(*protocol);
        }
    }

    /// 为某端口登记单个候选协议。
    pub fn insert(&mut self, port: u16, protocol: MaybeProtocol) {
        let node = self.inner.entry(port).or_default();
        node.insert(protocol);
    }

    /// 内置的 TCP 服务端口默认表（按 IANA 与业界惯例）。
    ///
    /// 上层配置未显式指定端口映射时的兜底，也是文档里对外说明“默认识别哪些端口”的依据。
    /// 值得注意的几项：
    /// - 587 登记为明文 [`MaybeProtocol::Smtp`]（submission 走 STARTTLS），
    ///   而 465 登记为 [`MaybeProtocol::Submissions`]（隐式 TLS）。
    /// - 8080 与 80 同样登记为 HTTP，8554 与 554 同样登记为 RTSP，
    ///   是因为这两个端口在实际部署里几乎总是明文服务。
    /// - 未登记端口不代表无法识别，识别器仍会退回通用猜测表。
    pub fn tcp_server() -> Self {
        let mut map = ProtocolPortMap::empty();
        map.insert(21, MaybeProtocol::Ftp);
        map.insert(22, MaybeProtocol::Ssh);
        map.insert(25, MaybeProtocol::Smtp);
        map.insert(53, MaybeProtocol::Dns);
        map.insert(80, MaybeProtocol::Http);
        map.insert(110, MaybeProtocol::Pop3);
        map.insert(119, MaybeProtocol::Nntp);
        map.insert(143, MaybeProtocol::Imap);
        map.insert(322, MaybeProtocol::Rtsps);
        map.insert(366, MaybeProtocol::Odmr);
        map.insert(389, MaybeProtocol::Ldap);
        map.insert(433, MaybeProtocol::Nnsp);
        map.insert(443, MaybeProtocol::Https);
        map.insert(465, MaybeProtocol::Submissions);
        map.insert(554, MaybeProtocol::Rtsp);
        map.insert(563, MaybeProtocol::Nntps);
        map.insert(587, MaybeProtocol::Smtp);
        map.insert(636, MaybeProtocol::Ldaps);
        map.insert(853, MaybeProtocol::DnsOverTls);
        map.insert(993, MaybeProtocol::Imaps);
        map.insert(995, MaybeProtocol::Pop3s);
        map.insert(1883, MaybeProtocol::Mqtt);
        map.insert(1935, MaybeProtocol::Rtmp);
        map.insert(2775, MaybeProtocol::Smpp);
        map.insert(3550, MaybeProtocol::Ssmpp);
        map.insert(4222, MaybeProtocol::Nats);
        map.insert(6881, MaybeProtocol::BitTorrent);
        map.insert(8080, MaybeProtocol::Http);
        map.insert(8554, MaybeProtocol::Rtsp);
        map.insert(8883, MaybeProtocol::SecureMqtt);
        map
    }

    /// 客户端侧（源端口）默认表。
    ///
    /// 目前只有 6881：BitTorrent 客户端在能直接回连（无 NAT）时会用固定端口监听，
    /// 对端反向发起连接时源端口即为 6881，这是少见的、源端口带信息的场景。
    /// 其余协议的源端口都是临时端口，没有识别价值，因此
    /// [`ProtocolInspector::new`](crate::ProtocolInspector::new) 实际并不使用这张表。
    pub fn tcp_client() -> Self {
        let mut map = ProtocolPortMap::empty();
        map.insert(6881, MaybeProtocol::BitTorrent);
        map
    }

    /// 查询端口上的候选协议集合；未登记返回 `None`。
    #[inline]
    pub fn get(&self, port: u16) -> Option<&ProtocolPortMapValue> {
        self.inner.get(&port)
    }
}
