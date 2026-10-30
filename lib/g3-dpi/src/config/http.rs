/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP 拦截（拆解重组）配置。
//!
//! 与 `protocol/http.rs` 的**识别**逻辑无关：识别只用首包判断是不是 HTTP，
//! 而这里的配置决定识别成 HTTP 之后代理怎么承载它——每连接复用多少请求、
//! 头部允许多大、超时多久。定义在本 crate 是为了让上层有统一的默认值来源。
//!
//! `H1` 指 HTTP/1.x（文本、单工管道），`H2` 指 HTTP/2（二进制分帧、多路复用），
//! 两者的可调项几乎不重叠，所以拆成两个结构而不是共享一份。

use std::num::NonZeroUsize;
use std::time::Duration;

/// HTTP/1.x 拦截配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H1InterceptionConfig {
    /// 单连接上允许并行在途的管道请求数。`NonZeroUsize` 从类型上排除 0。
    pub pipeline_size: NonZeroUsize,
    /// 管道空闲多久后关闭连接。
    pub pipeline_read_idle_timeout: Duration,
    /// 等待客户端请求头的超时。
    pub req_head_recv_timeout: Duration,
    /// 等待上游响应头的超时。
    pub rsp_head_recv_timeout: Duration,
    /// 请求头总字节上限，超出即判定为非法/超大请求。
    pub req_head_max_size: usize,
    /// 响应头总字节上限。
    pub rsp_head_max_size: usize,
    /// 正文读取时的单行长度上限：`HttpBodyReader` 按行解析分块传输的
    /// chunk-size 行与 trailer 行，这是单行的最大字节数。
    pub body_line_max_len: usize,
    /// 是否剥离客户端自带的 `Forwarded` 与 `X-Forwarded-For` 请求头，
    /// 防止内部拓扑经由客户端伪造的转发头泄露。
    pub steal_forwarded_for: bool,
    /* added by wming for repid audit */
    /// 是否只处理带请求体的请求（供 repid 审计场景过滤掉无体请求）。
    pub req_hasbody: bool,
    /// 请求体大小的下限阈值，小于它的请求不按体审计处理。
    pub req_body_min_size: usize,
}

impl Default for H1InterceptionConfig {
    /// 默认值取向：响应头比请求头宽松（响应可能有 Set-Cookie），
    /// 而管道空闲 300 秒远长于请求头 30 秒——前者是有意的 keep-alive 复用窗口，
    /// 后者是活跃客户端的行为约束，慢客户端不该被无限等待。
    fn default() -> Self {
        H1InterceptionConfig {
            pipeline_size: NonZeroUsize::new(10).unwrap(),
            pipeline_read_idle_timeout: Duration::from_secs(300),
            req_head_recv_timeout: Duration::from_secs(30),
            rsp_head_recv_timeout: Duration::from_secs(60),
            req_head_max_size: 65536,
            rsp_head_max_size: 65536,
            body_line_max_len: 8192,
            steal_forwarded_for: false,
            /* added by wming for repid audit */
            req_hasbody: false,
            req_body_min_size: 0,
        }
    }
}

/// HTTP/2 拦截配置。
///
/// 混合了两类参数：一部分会写进 SETTINGS 帧公告给对端
/// （`max_header_list_size`、`max_concurrent_streams`、`max_frame_size`、窗口大小），
/// 另一部分只是本地行为（各类超时、`silent_drop_expect_header`）。
/// 前者刻意设为私有并提供带校验的 setter，避免配置出对端无法接受的值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2InterceptionConfig {
    /// 公告给对端的单个头部块列表字节上限。
    pub max_header_list_size: u32,
    /// 公告给对端的单连接最大并发流数。
    pub max_concurrent_streams: u32,
    /// 单流流控窗口；getter 有 `#[inline]` 且在帧路径上调用，故为私有。
    stream_window_size: u32,
    /// 连接级流控窗口，必须是所有流窗口的上界关系由对端维护。
    connection_window_size: u32,
    /// 单帧载荷上限，写入 SETTINGS 的 `MAX_FRAME_SIZE`。
    max_frame_size: u32,
    /// 本地发送缓冲上限。
    pub max_send_buffer_size: usize,
    /// 等待上游完成 HTTP/2 握手（preface + SETTINGS）的超时。
    pub upstream_handshake_timeout: Duration,
    /// 等待上游新开流的超时。
    pub upstream_stream_open_timeout: Duration,
    /// 等待客户端完成握手的超时——比上游侧短得多，因为客户端更可能被闲置占用。
    pub client_handshake_timeout: Duration,
    /// 周期性 PING 间隔，用于保活与检测死连接。
    pub ping_interval: Duration,
    /// 等待响应头的超时。
    pub rsp_head_recv_timeout: Duration,
    /// 是否静默丢弃 `Expect: 100-continue` 头而不回 100 中间响应。
    pub silent_drop_expect_header: bool,
}

impl Default for H2InterceptionConfig {
    /// 默认值取向：窗口大小（1MiB 流 / 2MiB 连接）明显高于协议最小值 64KiB，
    /// 以便在高带宽延迟积链路上不成为瓶颈；帧大小 256KiB 处于协议允许区间的低位，
    /// 兼顾单帧内存占用。
    fn default() -> Self {
        H2InterceptionConfig {
            max_header_list_size: 64 * 1024, // 64KB
            max_concurrent_streams: 128,
            stream_window_size: 1024 * 1024,         // 1MiB
            connection_window_size: 2 * 1024 * 1024, // 2MiB
            max_frame_size: 256 * 1024,              // 256KiB
            max_send_buffer_size: 8 * 1024 * 1024,   // 8MiB
            upstream_handshake_timeout: Duration::from_secs(10),
            upstream_stream_open_timeout: Duration::from_secs(10),
            client_handshake_timeout: Duration::from_secs(4),
            ping_interval: Duration::from_secs(60),
            rsp_head_recv_timeout: Duration::from_secs(60),
            silent_drop_expect_header: false,
        }
    }
}

impl H2InterceptionConfig {
    /// 读取单帧载荷上限。
    #[inline]
    pub fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// 设置单帧载荷上限，强制夹到协议规定的合法区间。
    ///
    /// 下界 2^14 = 16384 是 HTTP/2 强制的最小帧长；上界 2^24 - 1 是协议允许的最大值。
    /// 越界值被**静默夹取**而不是报错，因此这里不校验“是否夹过”——配了 100 实际会用 16384，
    /// 排障时要以 getter 的返回值为准，而不是回显原始配置。
    pub fn set_max_frame_size(&mut self, size: u32) {
        self.max_frame_size = size.clamp(1 << 14, (1 << 24) - 1);
    }

    /// 读取单流流控窗口。
    #[inline]
    pub fn stream_window_size(&self) -> u32 {
        self.stream_window_size
    }

    /// 设置单流流控窗口，低于协议最小值 65536 会被抬到 65536。
    ///
    /// 同样静默修正；窗口过小会让对端反复等待 WINDOW_UPDATE，实测表现为吞吐骤降而非报错。
    pub fn set_stream_window_size(&mut self, size: u32) {
        self.stream_window_size = size.max(65536);
    }

    /// 读取连接级流控窗口。
    #[inline]
    pub fn connection_window_size(&self) -> u32 {
        self.connection_window_size
    }

    /// 设置连接级流控窗口，低于协议最小值 65536 会被抬到 65536。
    pub fn set_connection_window_size(&mut self, size: u32) {
        self.connection_window_size = size.max(65536);
    }
}
