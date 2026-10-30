/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! FTP upload state sharing across HTTP CONNECT connections.
//!
//! In HTTP CONNECT mode, control channel and data channel are separate TCP connections.
//! This module provides a mechanism to share state between them:
//! - Control channel detects STOR/APPE command and marks the pending upload
//! - Data channel checks the mark and only performs ICAP audit if marked as upload
//!
//! 跨 HTTP CONNECT 连接共享的 FTP 上传状态。
//!
//! 在 HTTP CONNECT 模式下，控制通道与数据通道是两条独立的 TCP 连接，
//! 因此需要一个旁路机制在两者之间传递信息：
//! - 控制通道识别到 STOR/APPE 命令后，登记一条“待审计上传”标记；
//! - 数据通道建立时查询该标记，只有被标记为上传的流量才走 ICAP 审计。

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 状态表的键：(客户端地址, FTP 服务器地址)。
/// 用地址对而非连接 ID，是因为两条 CONNECT 隧道之间没有其它共同标识。
type ClientServerPair = (IpAddr, IpAddr);

/// Information about a pending upload operation
/// 一次待处理上传操作的信息
#[derive(Clone, Debug)]
pub(crate) struct PendingUploadInfo {
    /// FTP command (STOR, APPE, STOU) —— FTP 命令名
    pub(crate) ftp_command: String,
    /// File path being uploaded —— 正在上传的文件路径
    pub(crate) ftp_path: String,
    /// When this entry was created (for cleanup) —— 创建时间，用于过期清理
    created_at: Instant,
}

/// 已确认为 FTPS 的服务器域名，带创建时间用于 TTL 过期
struct FtpsDomainEntry {
    domain: String,
    created_at: Instant,
}

/// 控制通道协商出的 TLS 会话，供数据通道复用（vsftpd 的 require_ssl_reuse）
struct TlsSessionEntry {
    session_der: Vec<u8>,
    created_at: Instant,
}

/// Global state for tracking pending FTP uploads across connections
/// 跨连接追踪 FTP 上传/FTPS 状态的全局表。
///
/// 三张表都由 `Mutex<HashMap>` 保护，并为每类条目设置了 TTL 与容量上限，
/// 避免客户端异常断开后标记永久残留、或被恶意刷爆内存。
pub(crate) struct FtpUploadState {
    /// Per (client, server) pair FIFO queue of pending uploads.
    /// Supports concurrent uploads from the same client.
    /// 每个 (客户端, 服务器) 对应的待审计上传队列，先进先出。
    /// 用队列而非单值，以支持同一客户端的并发上传。
    pending_uploads: Mutex<HashMap<ClientServerPair, VecDeque<PendingUploadInfo>>>,
    /// FTPS server domains with creation time for TTL-based expiry —— FTPS 域名表
    ftps_domains: Mutex<HashMap<ClientServerPair, FtpsDomainEntry>>,
    /// TLS sessions for FTPS data channel reuse (vsftpd require_ssl_reuse) —— TLS 会话表
    tls_sessions: Mutex<HashMap<ClientServerPair, TlsSessionEntry>>,
    /// TTL for pending upload entries —— 上传标记的存活时间
    upload_ttl: Duration,
    /// TTL for FTPS domain entries —— FTPS 域名条目的存活时间
    domain_ttl: Duration,
    /// TTL for TLS session entries —— TLS 会话条目的存活时间
    session_ttl: Duration,
    /// Maximum pending uploads per (client, server) pair (DoS protection) —— 单对最多待审计上传数
    max_pending_per_pair: usize,
    /// Maximum number of FTPS domain entries (DoS protection) —— FTPS 域名条目总数上限
    max_domains: usize,
    /// Maximum number of TLS session entries (DoS protection) —— TLS 会话条目总数上限
    max_sessions: usize,
    /// Approximate counter for lazy cleanup trigger —— 操作计数，用于惰性触发清理
    ops_since_cleanup: Mutex<u32>,
    /// Cleanup interval in number of operations —— 每多少次操作清理一次过期条目
    cleanup_interval: u32,
}

impl FtpUploadState {
    /// 创建状态表，使用内置的默认 TTL 与容量上限。
    pub(crate) fn new() -> Self {
        FtpUploadState {
            pending_uploads: Mutex::new(HashMap::new()),
            ftps_domains: Mutex::new(HashMap::new()),
            tls_sessions: Mutex::new(HashMap::new()),
            upload_ttl: Duration::from_secs(3600),
            domain_ttl: Duration::from_secs(3600),
            session_ttl: Duration::from_secs(3600),
            max_pending_per_pair: 16,
            max_domains: 4096,
            max_sessions: 4096,
            ops_since_cleanup: Mutex::new(0),
            cleanup_interval: 1000,
        }
    }

    /// 清理已超时的上传标记：从队首逐个弹出，遇到首个未超时的条目即停止；
    /// 队列清空后连同键一起移除，避免键无限累积。
    /// （注意：同文件重复 STOR 只刷新时间戳，队首未必严格最早，
    /// 因此这里可能提前停下，剩余的过期条目留待下次清理。）
    fn cleanup_expired_uploads(
        map: &mut HashMap<ClientServerPair, VecDeque<PendingUploadInfo>>,
        now: Instant,
        ttl: Duration,
    ) {
        map.retain(|_, queue| {
            while let Some(front) = queue.front() {
                if now.saturating_duration_since(front.created_at) >= ttl {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
    }

    /// 清理已超时的 FTPS 域名条目
    fn cleanup_expired_domains(
        map: &mut HashMap<ClientServerPair, FtpsDomainEntry>,
        now: Instant,
        ttl: Duration,
    ) {
        map.retain(|_, entry| now.saturating_duration_since(entry.created_at) < ttl);
    }

    /// 清理已超时的 TLS 会话条目
    fn cleanup_expired_sessions(
        map: &mut HashMap<ClientServerPair, TlsSessionEntry>,
        now: Instant,
        ttl: Duration,
    ) {
        map.retain(|_, entry| now.saturating_duration_since(entry.created_at) < ttl);
    }

    /// 惰性清理：每 `cleanup_interval` 次操作才真正扫描一次过期条目，
    /// 借助调用路径摊薄清理开销，而不额外起定时任务。
    /// 锁被 poisoned（返回 `Err`）时跳过本次清理，不影响主流程。
    fn maybe_trigger_cleanup(&self) {
        let should_cleanup = if let Ok(mut count) = self.ops_since_cleanup.lock() {
            *count = count.saturating_add(1);
            if *count >= self.cleanup_interval {
                *count = 0;
                true
            } else {
                false
            }
        } else {
            false
        };

        if should_cleanup {
            let now = Instant::now();
            if let Ok(mut uploads) = self.pending_uploads.lock() {
                Self::cleanup_expired_uploads(&mut uploads, now, self.upload_ttl);
            }
            if let Ok(mut domains) = self.ftps_domains.lock() {
                Self::cleanup_expired_domains(&mut domains, now, self.domain_ttl);
            }
            if let Ok(mut sessions) = self.tls_sessions.lock() {
                Self::cleanup_expired_sessions(&mut sessions, now, self.session_ttl);
            }
        }
    }

    /// Mark a pending upload for a data channel.
    /// Called when control channel detects STOR/APPE command.
    /// Deduplicates by (command, path): repeated STOR for the same file
    /// refreshes the TTL rather than appending a new entry.
    /// 为数据通道登记一条待审计上传，由控制通道在识别到 STOR/APPE 时调用。
    /// 按 (命令, 路径) 去重：同一文件重复 STOR 只刷新有效期，不追加新条目。
    /// `_pasv_port` 当前未参与键或匹配，仅作为调用方保留的参数。
    pub(crate) fn mark_upload(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
        ftp_command: &str,
        ftp_path: &str,
        _pasv_port: u16,
    ) {
        let key = (client_ip, ftp_server_ip);
        let cmd = ftp_command.to_string();
        let path = ftp_path.to_string();

        if let Ok(mut map) = self.pending_uploads.lock() {
            let queue = map.entry(key).or_default();

            // 已存在同一文件的标记：刷新时间戳后返回
            if let Some(existing) = queue
                .iter_mut()
                .find(|e| e.ftp_command == cmd && e.ftp_path == path)
            {
                existing.created_at = Instant::now();
                log::debug!(
                    "FTP upload refreshed: cmd={}, path={}, queue_len={}",
                    ftp_command,
                    ftp_path,
                    queue.len()
                );
                return;
            }

            // 队列已满：丢弃本次标记，数据通道将退化为不审计（DoS 保护）
            if queue.len() >= self.max_pending_per_pair {
                log::debug!(
                    "FTP upload mark dropped (queue full): cmd={}, path={}",
                    ftp_command,
                    ftp_path
                );
                return;
            }

            let info = PendingUploadInfo {
                ftp_command: cmd,
                ftp_path: path,
                created_at: Instant::now(),
            };
            log::debug!(
                "FTP upload marked: cmd={}, path={}, queue_len={}",
                ftp_command,
                ftp_path,
                queue.len() + 1
            );
            queue.push_back(info);
        }

        self.maybe_trigger_cleanup();
    }

    /// Consume and return the oldest pending upload info for a (client, server) pair.
    /// FIFO order: first upload command marked is first consumed by data channel.
    /// 取出并移除该 (客户端, 服务器) 最古老的一条待审计上传信息。
    /// 按先进先出消费：最先登记的上传命令最先被数据通道取走。
    /// 取出时会顺带跳过已超时的队首条目。
    pub(crate) fn consume_upload(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
    ) -> Option<PendingUploadInfo> {
        let key = (client_ip, ftp_server_ip);
        let result = if let Ok(mut map) = self.pending_uploads.lock() {
            if let Some(queue) = map.get_mut(&key) {
                let now = Instant::now();

                // 丢弃超时条目，避免拿到早已失效的上传标记
                while let Some(front) = queue.front() {
                    if now.saturating_duration_since(front.created_at) >= self.upload_ttl {
                        queue.pop_front();
                    } else {
                        break;
                    }
                }

                let info = queue.pop_front();
                // 队列空了就删除键，防止 HashMap 随客户端数量增长
                if info.is_some() && queue.is_empty() {
                    map.remove(&key);
                }
                info
            } else {
                None
            }
        } else {
            None
        };

        self.maybe_trigger_cleanup();
        result
    }

    /// Mark a server as FTPS server with its domain.
    /// Called when FTPS control channel is established.
    /// 记录某台 FTP 服务器是 FTPS 及其域名，在 FTPS 控制通道建立时调用。
    /// 数据通道随后据此判断是否需要 TLS，以及用哪个域名做证书校验。
    pub(crate) fn mark_ftps_domain(&self, client_ip: IpAddr, ftp_server_ip: IpAddr, domain: &str) {
        let key = (client_ip, ftp_server_ip);
        if let Ok(mut map) = self.ftps_domains.lock() {
            // 新键且表已满则拒绝写入（DoS 保护），已有键则允许覆盖刷新
            if !map.contains_key(&key) && map.len() >= self.max_domains {
                return;
            }
            map.insert(
                key,
                FtpsDomainEntry {
                    domain: domain.to_string(),
                    created_at: Instant::now(),
                },
            );
        }

        self.maybe_trigger_cleanup();
    }

    /// Get the FTPS server domain, or None if expired or not found.
    /// 查询 FTPS 服务器域名；条目不存在或已超时返回 None。
    pub(crate) fn get_ftps_domain(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
    ) -> Option<String> {
        let key = (client_ip, ftp_server_ip);
        let result = if let Ok(map) = self.ftps_domains.lock() {
            let entry = map.get(&key)?;
            if Instant::now().saturating_duration_since(entry.created_at) >= self.domain_ttl {
                None
            } else {
                Some(entry.domain.clone())
            }
        } else {
            None
        };

        self.maybe_trigger_cleanup();
        result
    }

    /// Save a TLS session for FTPS data channel reuse.
    /// Called when FTPS control channel TLS handshake succeeds.
    /// 保存控制通道的 TLS 会话，供 FTPS 数据通道复用。
    /// 在 FTPS 控制通道握手成功后调用。
    pub(crate) fn save_tls_session(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
        session_der: Vec<u8>,
    ) {
        let key = (client_ip, ftp_server_ip);
        if let Ok(mut map) = self.tls_sessions.lock() {
            // 会话表已满且是新键则丢弃（DoS 保护）
            if !map.contains_key(&key) && map.len() >= self.max_sessions {
                return;
            }
            map.insert(
                key,
                TlsSessionEntry {
                    session_der,
                    created_at: Instant::now(),
                },
            );
        }
        self.maybe_trigger_cleanup();
    }

    /// Get a TLS session DER for FTPS data channel reuse.
    /// Called when FTPS data channel TLS handshake starts.
    /// 取出用于数据通道复用的 TLS 会话 DER。
    /// 在 FTPS 数据通道开始握手时调用；不存在或已超时返回 None。
    pub(crate) fn get_tls_session(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
    ) -> Option<Vec<u8>> {
        let key = (client_ip, ftp_server_ip);
        let result = if let Ok(map) = self.tls_sessions.lock() {
            let entry = map.get(&key)?;
            if Instant::now().saturating_duration_since(entry.created_at) >= self.session_ttl {
                None
            } else {
                Some(entry.session_der.clone())
            }
        } else {
            None
        };

        self.maybe_trigger_cleanup();
        result
    }
}

/// Global shared state instance —— 进程内唯一的状态表实例
static FTP_UPLOAD_STATE: OnceLock<Arc<FtpUploadState>> = OnceLock::new();

/// Get the global FTP upload state —— 获取全局 FTP 上传状态表（首次调用时初始化）
pub(crate) fn get_ftp_upload_state() -> Arc<FtpUploadState> {
    FTP_UPLOAD_STATE
        .get_or_init(|| Arc::new(FtpUploadState::new()))
        .clone()
}
