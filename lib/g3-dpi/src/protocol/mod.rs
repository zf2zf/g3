/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 协议枚举与识别引擎的装配层。
//!
//! 这里有两个容易混淆的枚举，方向性正好相反：
//!
//! - [`MaybeProtocol`]：**输入**，表示“这条连接可能是哪种协议”，是候选集合。
//!   名字里的 Maybe 即“尚未确认”，主要来源是端口表与 ALPN。
//! - [`Protocol`]：**输出**，表示“已确认的协议及其具体变体”，
//!   例如区分 `TlsModern` 与 `TlsLegacy`、`Http1` 与 `Http2`。
//!
//! 两者的粒度不同：`MaybeProtocol::Https` 确认后可能是 `Protocol::Http1` /
//! `Http2` / `Http3`；而 `MaybeProtocol::Ssl` 确认后是 `Protocol::Tls*` 之一。

use std::fmt;
use std::str::FromStr;

use g3_types::net::{AlpnProtocol, WebSocketSubProtocol};

mod inspect;
use inspect::ProtocolInspectState;
pub use inspect::{ProtocolInspectError, ProtocolInspector};

mod portmap;
pub use portmap::{ProtocolPortMap, ProtocolPortMapValue};

/// 候选协议：尚未通过载荷确认，仅表示“值得按这个协议去试一下”。
///
/// 显式列出各协议的 TLS 版本（如 [`MaybeProtocol::Https`]），
/// 是因为端口表与 ALPN 给出的是“带加密的某协议”这种语义；
/// 一旦按 TLS 解析，载荷本身仍是内层协议（HTTP），所以端口表在插入时
/// 会把这类变体拆成“检查 SSL” + 内层协议两项（见 `ProtocolPortMapValue::insert`）。
///
/// `#[repr(usize)]` 与末尾的 [`MaybeProtocol::_MaxSize`] 是为了能把枚举值
/// 直接当作 `FixedBitSet` 的下标使用（见 `ProtocolInspectState::excluded`）。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(usize)]
pub enum MaybeProtocol {
    /// 明文 HTTP（各版本共用一个候选值，确认后由 [`Protocol`] 区分版本）。
    Http,
    /// SMTP（RFC 5321）明文 / STARTTLS 形态。
    Smtp,
    /// 按需邮件中继（ODMR），SMTP 的受限子集。
    Odmr, // On-Demand Mail Relay, a restricted profile of SMTP
    /// SSH 协议族，确认后按版本区分 [`Protocol::Ssh`] 与 [`Protocol::SshLegacy`]。
    Ssh,
    /// FTP 控制连接（载荷检测的是服务端 220 greeting）。
    Ftp,
    /// 明文 DNS；TCP 上做首包检测时带 2 字节长度前缀。
    Dns,
    /// LDAP（RFC 4511），TCP 上为 ASN.1 BER 编码的 BindRequest。
    Ldap,
    /// POP3（RFC 1957）。
    Pop3,
    /// NNTP（RFC 9595），读新闻协议。
    Nntp,
    /// NNSP — 用 NNTP 承载 NEWS 转发，报文格式与 NNTP 基本一致。
    Nnsp,
    /// IMAP4rev1（RFC 3501）。
    Imap,
    /// RTSP 实时流控制协议，报文外形像 HTTP 但方法集不同。
    Rtsp,
    /// MQTT（ISO/IEC 20922），首包固定为 CONNECT。
    Mqtt,
    /// STOMP 文本消息协议，常见于 WebSocket 子协议协商。
    Stomp,
    /// SMPP（短消息点对点协议），运营商短信网关使用。
    Smpp,
    /// RTMP（Adobe 消息协议），可裸跑 TCP 也可封装在 HTTP 里。
    Rtmp,
    /// NATS，服务端会先推 INFO 消息。
    Nats,
    /// BitTorrent（BEP 3），确认后按传输层区分 TCP / uTP。
    BitTorrent,

    // 以下变体表示“某协议跑在 TLS 之上”，插入端口表时会展开为
    // check_ssl=true 加上内层明文协议。
    /// HTTPS，即 HTTP over TLS。
    Https,
    /// RFC 6409 submissions：提交邮件用的 TLS 端口上的 SMTP。
    Submissions,
    /// POP3 over TLS。
    Pop3s,
    /// NNTP over TLS。
    Nntps,
    /// IMAP over TLS。
    Imaps,
    /// RTSP over TLS。
    Rtsps,
    /// MQTT over TLS（惯例上用 8883）。
    SecureMqtt,
    /// SMPP over TLS。
    Ssmpp,
    /// RTMP over TLS。
    Rtmps,
    /// DoT — RFC 7858，DNS over TLS。
    DnsOverTls,
    /// LDAP over TLS。
    Ldaps,

    /// 纯 TLS/SSL，不预设内层协议（典型如 HTTPS 只做隧道转发时）。
    Ssl,

    /// 哨兵值：候选协议的总数，用于给 `FixedBitSet` 预分配容量。
    /// 不是真实协议，任何匹配分支里命中它都属于程序缺陷。
    _MaxSize,
}

impl MaybeProtocol {
    /// 该候选是否隐含“需要先按 TLS 处理”。
    ///
    /// 用于让上层判断识别结果是加密隧道还是明文协议，
    /// 从而决定要不要插入 TLS 终结层。
    pub const fn is_ssl(&self) -> bool {
        matches!(
            self,
            MaybeProtocol::Ssl
                | MaybeProtocol::Https
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
        )
    }
}

impl FromStr for MaybeProtocol {
    type Err = ();

    /// 从配置文件里的协议名解析候选协议。
    ///
    /// 统一转小写后匹配，因此 YAML 中大小写不敏感；同一变体可有多个别名
    /// （如 `https` / `http+tls`、`bittorrent` / `bt`），以兼容历史配置写法。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(MaybeProtocol::Http),
            "smtp" => Ok(MaybeProtocol::Smtp),
            "odmr" => Ok(MaybeProtocol::Odmr),
            "ssh" => Ok(MaybeProtocol::Ssh),
            "ftp" => Ok(MaybeProtocol::Ftp),
            "dns" => Ok(MaybeProtocol::Dns),
            "ldap" => Ok(MaybeProtocol::Ldap),
            "pop3" => Ok(MaybeProtocol::Pop3),
            "nntp" => Ok(MaybeProtocol::Nntp),
            "nnsp" => Ok(MaybeProtocol::Nnsp),
            "imap" => Ok(MaybeProtocol::Imap),
            "rtsp" => Ok(MaybeProtocol::Rtsp),
            "mqtt" => Ok(MaybeProtocol::Mqtt),
            "stomp" => Ok(MaybeProtocol::Stomp),
            "smpp" => Ok(MaybeProtocol::Smpp),
            "rtmp" => Ok(MaybeProtocol::Rtmp),
            "nats" => Ok(MaybeProtocol::Nats),
            "bittorrent" | "bt" => Ok(MaybeProtocol::BitTorrent),
            "https" | "http+tls" => Ok(MaybeProtocol::Https),
            "submissions" | "smtps" => Ok(MaybeProtocol::Submissions),
            "pop3s" | "pop3+tls" => Ok(MaybeProtocol::Pop3s),
            "nntps" | "nntp+tls" | "snntp" => Ok(MaybeProtocol::Nntps),
            "imaps" | "imap+tls" => Ok(MaybeProtocol::Imaps),
            "rtsps" | "rtsp+tls" => Ok(MaybeProtocol::Rtsps),
            "secure-mqtt" => Ok(MaybeProtocol::SecureMqtt),
            "ssmpp" | "smpps" | "secure smpp" => Ok(MaybeProtocol::Ssmpp),
            "rtmps" | "rtmp+tls" => Ok(MaybeProtocol::Rtmps),
            "dot" | "dnsovertls" | "dns-over-tls" => Ok(MaybeProtocol::DnsOverTls),
            "ldaps" => Ok(MaybeProtocol::Ldaps),
            "ssl" | "tls" => Ok(MaybeProtocol::Ssl),
            _ => Err(()),
        }
    }
}

impl From<AlpnProtocol> for MaybeProtocol {
    /// 由 TLS ALPN 协商结果映射到候选协议。
    ///
    /// ALPN 是在 TLS 握手里达成的共识，属于强证据，识别器会把它插到
    /// 待检查队列队首优先采信。注意 `DnsOverTls` / `DnsOverQuic` 在这里
    /// 归一成 [`MaybeProtocol::Dns`]：加密层已确定，不必再猜 TLS。
    fn from(p: AlpnProtocol) -> Self {
        match p {
            AlpnProtocol::Http10
            | AlpnProtocol::Http11
            | AlpnProtocol::Http2
            | AlpnProtocol::Http3 => MaybeProtocol::Http,
            AlpnProtocol::Ftp => MaybeProtocol::Ftp,
            AlpnProtocol::Smtp => MaybeProtocol::Smtp,
            AlpnProtocol::Imap => MaybeProtocol::Imap,
            AlpnProtocol::Pop3 => MaybeProtocol::Pop3,
            AlpnProtocol::Nntp => MaybeProtocol::Nntp,
            AlpnProtocol::Nnsp => MaybeProtocol::Nnsp,
            AlpnProtocol::Mqtt => MaybeProtocol::Mqtt,
            AlpnProtocol::DnsOverTls => MaybeProtocol::Dns,
            AlpnProtocol::DnsOverQuic => MaybeProtocol::Dns,
        }
    }
}

impl From<WebSocketSubProtocol> for MaybeProtocol {
    /// 由 WebSocket 子协议协商结果映射到候选协议。
    ///
    /// MQTT 与 STOMP 都定义了 over WebSocket 的标准子协议名，
    /// 握手阶段即可确定内层协议，无需再做字节级探测。
    fn from(p: WebSocketSubProtocol) -> Self {
        match p {
            WebSocketSubProtocol::Mqtt => MaybeProtocol::Mqtt,
            WebSocketSubProtocol::StompV10
            | WebSocketSubProtocol::StompV11
            | WebSocketSubProtocol::StompV12 => MaybeProtocol::Stomp,
        }
    }
}

/// 已确认的应用层协议。
///
/// 与 [`MaybeProtocol`] 的取舍不同：这里把“TLS 版本代际”“SSH 版本代际”
/// “HTTP 版本”“RTMP / BitTorrent 的承载方式”拆成独立变体，因为上层需要据此
/// 选择不同的处理分支；而 `Smtp` / `Pop3` 等文本协议不必再区分子类。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// 首包数据不足以定论，或所有候选都已被排除。
    Unknown,
    /// 等待首包超时（见 `ProtocolInspectionConfig::data0_wait_timeout`）。
    Timeout,
    /// SSLv2 / SSLv3 时代的记录层版本（0x0200 / 0x0300），已不安全。
    SslLegacy,
    /// TLS 1.0 / 1.1（0x0301 / 0x0302）。
    TlsLegacy,
    /// TLS 1.2 / 1.3（0x0303 / 0x0304）。
    TlsModern,
    /// TLCP / GM/T 0024 国密双证书体系，记录层版本号为 0x0101。
    TlsTlcp,
    /// HTTP/1.0 或 1.1（识别阶段二者共用一个变体）。
    Http1,
    /// HTTP/2 明文（h2c），依据 24 字节连接前缀判定。
    Http2,
    /// HTTP/3（QUIC 承载），通常来自 ALPN 而非载荷探测。
    Http3,
    /// SMTP 命令集。
    Smtp,
    /// SSH 协议版本 1.x（`SSH-1.99` 之前的旧版本）。
    SshLegacy,
    /// SSH 协议版本 2.0。
    Ssh,
    /// FTP 控制连接；数据连接是另一条独立 TCP，不在此识别。
    FtpControl,
    /// POP3 命令集。
    Pop3,
    /// NNTP 命令集。
    Nntp,
    /// NNTP 转发（NNTPFEED / NNSP）。
    Nnsp,
    /// IMAP4rev1 命令集。
    Imap,
    /// RTSP 请求 / 响应。
    Rtsp,
    /// MQTT 报文。
    Mqtt,
    /// STOMP 帧。
    Stomp,
    /// SMPP PDU。
    Smpp,
    /// RTMP 裸跑 TCP（含握手后的连续_chunk_形态）。
    RtmpOverTcp,
    /// RTMP 封装在 HTTP POST 里（mms:// over HTTP 隧道）。
    RtmpOverHttp,
    /// NATS 协议。
    Nats,
    /// BitTorrent over TCP。
    BitTorrentOverTcp,
    /// BitTorrent over uTP（BEP 29），UDP 上的可靠传输。
    BitTorrentOverUtp,
    /// WebSocket 升级成功后的帧协议。
    Websocket,
    /// DNS 报文（TCP / UDP 共用）。
    Dns,
    /// LDAP BER 报文。
    Ldap,
}

impl Protocol {
    /// 用于日志、指标标签与审计记录的稳定字符串名。
    ///
    /// 以 `_` 开头的 `"_unknown"` / `"_timeout"` 是刻意排在前面的非协议状态，
    /// 便于在按名字排序的报表里与真实协议区分开。
    /// 返回值必须是 `'static` 且不可变——它会被直接写进指标标签。
    pub const fn as_str(&self) -> &'static str {
        match self {
            Protocol::Unknown => "_unknown",
            Protocol::Timeout => "_timeout",
            Protocol::SslLegacy => "ssl_legacy",
            Protocol::TlsLegacy => "tls_legacy",
            Protocol::TlsModern => "tls_modern",
            Protocol::TlsTlcp => "tls_tlcp",
            Protocol::Http1 => "http_1",
            Protocol::Http2 => "http_2",
            Protocol::Http3 => "http_3",
            Protocol::Smtp => "smtp",
            Protocol::SshLegacy => "ssh_legacy",
            Protocol::Ssh => "ssh",
            Protocol::FtpControl => "ftp_control",
            Protocol::Pop3 => "pop3",
            Protocol::Nntp => "nntp",
            Protocol::Nnsp => "nnsp",
            Protocol::Imap => "imap",
            Protocol::Rtsp => "rtsp",
            Protocol::Mqtt => "mqtt",
            Protocol::Stomp => "stomp",
            Protocol::Smpp => "smpp",
            Protocol::RtmpOverTcp | Protocol::RtmpOverHttp => "rtmp",
            Protocol::Nats => "nats",
            Protocol::BitTorrentOverTcp | Protocol::BitTorrentOverUtp => "bittorrent",
            Protocol::Websocket => "websocket",
            Protocol::Dns => "dns",
            Protocol::Ldap => "ldap",
        }
    }

    /// 对应的 Wireshark dissector 名，用于把识别结果导出成 pcap 标注。
    ///
    /// 与 [`Protocol::wireshark_protocol`] 的区别：dissector 名要精确到承载方式
    /// （`rtmpt.tcp` / `bittorrent.utp`），proto 名只到协议族一级。
    /// `Unknown` / `Timeout` 返回空串表示无法标注。
    pub const fn wireshark_dissector(&self) -> &'static str {
        // wireshark register_dissector()
        match self {
            Protocol::Unknown | Protocol::Timeout => "",
            Protocol::SslLegacy | Protocol::TlsLegacy | Protocol::TlsModern => "tls",
            Protocol::TlsTlcp => "tls",
            Protocol::Http1 => "http",
            Protocol::Http2 => "http2",
            Protocol::Http3 => "http3",
            Protocol::Smtp => "smtp",
            Protocol::SshLegacy | Protocol::Ssh => "ssh",
            Protocol::FtpControl => "ftp",
            Protocol::Pop3 => "pop",
            Protocol::Nntp | Protocol::Nnsp => "nntp",
            Protocol::Imap => "imap",
            Protocol::Rtsp => "rtsp",
            Protocol::Mqtt => "mqtt",
            Protocol::Stomp => "stomp", // not officially supported
            Protocol::Smpp => "smpp",
            Protocol::RtmpOverTcp => "rtmpt.tcp",
            Protocol::RtmpOverHttp => "rtmpt.http",
            Protocol::Nats => "nats", // not officially supported
            Protocol::BitTorrentOverTcp => "bittorrent.tcp",
            Protocol::BitTorrentOverUtp => "bittorrent.utp",
            Protocol::Websocket => "websocket",
            Protocol::Dns => "dns",
            Protocol::Ldap => "ldap",
        }
    }

    /// 对应的 Wireshark 协议（proto 套件）名，用于在 tshark / Lua 里做协议级过滤。
    ///
    /// 这里把 `RtmpOverTcp` 与 `RtmpOverHttp` 合并成 `rtmpt`、
    /// 把两种 BitTorrent 承载合并成 `bittorrent`：Wireshark 的 proto 注册是
    /// 按协议族而非按 dissector 划分的。`stomp` / `nats` 标注为
    /// not officially supported——Wireshark 没有官方 dissector，靠第三方插件。
    pub const fn wireshark_protocol(&self) -> &'static str {
        // wireshark proto_register_protocol()
        match self {
            Protocol::Unknown | Protocol::Timeout => "",
            Protocol::SslLegacy | Protocol::TlsLegacy | Protocol::TlsModern => "tls",
            Protocol::TlsTlcp => "tls",
            Protocol::Http1 => "http",
            Protocol::Http2 => "http2",
            Protocol::Http3 => "http3",
            Protocol::Smtp => "smtp",
            Protocol::SshLegacy | Protocol::Ssh => "ssh",
            Protocol::FtpControl => "ftp",
            Protocol::Pop3 => "pop",
            Protocol::Nntp | Protocol::Nnsp => "nntp",
            Protocol::Imap => "imap",
            Protocol::Rtsp => "rtsp",
            Protocol::Mqtt => "mqtt",
            Protocol::Stomp => "stomp", // not officially supported
            Protocol::Smpp => "smpp",
            Protocol::RtmpOverTcp | Protocol::RtmpOverHttp => "rtmpt",
            Protocol::Nats => "nats", // not officially supported
            Protocol::BitTorrentOverTcp | Protocol::BitTorrentOverUtp => "bittorrent",
            Protocol::Websocket => "websocket",
            Protocol::Dns => "dns",
            Protocol::Ldap => "ldap",
        }
    }
}

impl From<AlpnProtocol> for Protocol {
    /// 由 TLS ALPN 协商结果直接得出确认协议。
    ///
    /// 走这条路径时不需要看载荷：ALPN 已是双方协商的定论。
    /// 与 [`MaybeProtocol`] 版本的关键差别是这里会区分
    /// [`Protocol::Http1`] 与 [`Protocol::Http2`]（`Http10` / `Http11` 归为 `Http1`）。
    fn from(p: AlpnProtocol) -> Self {
        match p {
            AlpnProtocol::Http10 | AlpnProtocol::Http11 => Protocol::Http1,
            AlpnProtocol::Http2 => Protocol::Http2,
            AlpnProtocol::Http3 => Protocol::Http3,
            AlpnProtocol::Ftp => Protocol::FtpControl,
            AlpnProtocol::Smtp => Protocol::Smtp,
            AlpnProtocol::Imap => Protocol::Imap,
            AlpnProtocol::Pop3 => Protocol::Pop3,
            AlpnProtocol::Nntp => Protocol::Nntp,
            AlpnProtocol::Nnsp => Protocol::Nnsp,
            AlpnProtocol::Mqtt => Protocol::Mqtt,
            // DoT / DoQ 的载荷就是 DNS 报文，TLS 层已由 ALPN 说明
            AlpnProtocol::DnsOverTls => Protocol::Dns,
            AlpnProtocol::DnsOverQuic => Protocol::Dns,
        }
    }
}

impl fmt::Display for Protocol {
    /// 输出 [`Protocol::as_str`] 的稳定名称，供日志与错误信息直接使用。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// 各协议的载荷探测器：每个文件都以 `impl ProtocolInspectState` 的形式
// 挂上自己的 check_xxx 方法，由 inspect.rs 里的分派表按方向调用。
mod bittorrent;
mod dns;
mod ftp;
mod http;
mod imap;
mod ldap;
mod mqtt;
mod nats;
mod nntp;
mod pop3;
mod rtmp;
mod rtsp;
mod smpp;
mod smtp;
mod ssh;
mod ssl;
mod stomp;
