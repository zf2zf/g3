/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! SMTP/IMAP 协议 REQMOD 适配器共用的运行状态与结束状态。
//!
//! 邮件协议（SMTP 的 DATA 阶段、IMAP 的 APPEND 命令）的请求体是大块二进制内容，
//! 适配器以"客户端 → ICAP → 上游"的单向/双向搬运任务运行。本模块提供：
//!
//! - [`ReqmodAdaptationRunState`]：搬运过程中的计时与完成标志（供日志与审计）；
//! - [`ReqmodAdaptationEndState`]：搬运任务结束时 ICAP 侧做出的最终决定；
//! - [`ReqmodRecvHttpResponseBody`]：当 ICAP 响应为 `res-hdr + res-body`（替代响应）时，
//!   从 ICAP 连接上以 chunked 编码读取封装 HTTP 响应 body 的读取器。
//!   对应决策表中"200 + res-hdr/res-body → 不回源，直接用 ICAP 响应回复客户端"的分支。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncBufRead;
use tokio::time::Instant;

use g3_http::HttpBodyDecodeReader;

use crate::IcapServiceClient;
use crate::reqmod::h1::HttpAdapterErrorResponse;
use crate::service::IcapClientConnection;

/// 一次 REQMOD 适配搬运任务的运行状态（跨"读客户端 / 写 ICAP / 写上游"多个任务共享）。
pub struct ReqmodAdaptationRunState {
    // 任务创建时刻，用于计算各阶段耗时
    task_create_instant: Instant,
    /// 上游（ICAP 或邮件服务器）收到全部数据所经历的耗时；None 表示尚未完成发送
    pub dur_ups_send_all: Option<Duration>,
    /// 是否已读完客户端侧的全部数据
    pub clt_read_finished: bool,
    /// 是否已向上游写完全部数据
    pub ups_write_finished: bool,
}

impl ReqmodAdaptationRunState {
    /// 以任务创建时刻 `task_create_instant` 初始化一个全未完成的状态。
    pub fn new(task_create_instant: Instant) -> Self {
        ReqmodAdaptationRunState {
            task_create_instant,
            dur_ups_send_all: None,
            clt_read_finished: false,
            ups_write_finished: false,
        }
    }

    /// 标记"上游已收到全部数据"：记录从任务创建到此刻的耗时，并置完成标志。
    pub(crate) fn mark_ups_send_all(&mut self) {
        self.dur_ups_send_all = Some(self.task_create_instant.elapsed());
        self.ups_write_finished = true;
    }
}

/// REQMOD 适配任务结束时 ICAP 服务做出的决定。
pub enum ReqmodAdaptationEndState {
    /// ICAP 未改写内容（如 204），原始报文已原样传输给上游
    OriginalTransferred,
    /// ICAP 返回了改写后的报文（200 + req-hdr/req-body），已替换原报文传输
    AdaptedTransferred,
    /// ICAP 返回替代响应（200 + res-hdr/res-body）：`HttpAdapterErrorResponse`
    /// 描述要回复给客户端的 HTTP 响应头部；若其携带 body，则附一个
    /// [`ReqmodRecvHttpResponseBody`] 供调用方从 ICAP 连接继续读取 chunked body
    HttpErrResponse(HttpAdapterErrorResponse, Option<ReqmodRecvHttpResponseBody>),
}

/// 持有 ICAP 连接的 body 读取句柄：用于读取 ICAP 替代响应中封装的 HTTP 响应 body。
///
/// 使用完毕后必须调用 [`ReqmodRecvHttpResponseBody::save_connection`]，
/// 以便按 keep-alive 情况归还或关闭底层 ICAP 连接。
pub struct ReqmodRecvHttpResponseBody {
    pub(crate) icap_client: Arc<IcapServiceClient>,
    pub(crate) icap_keepalive: bool,
    pub(crate) icap_connection: IcapClientConnection,
}

impl ReqmodRecvHttpResponseBody {
    /// 创建一个 chunked 解码读取器（初始缓冲 1024 字节），
    /// 从当前 ICAP 连接上读出封装的 HTTP 响应 body，直到 chunked 结束标记（0 长度块）。
    pub fn body_reader(&mut self) -> HttpBodyDecodeReader<'_, impl AsyncBufRead + use<>> {
        HttpBodyDecodeReader::new_chunked(&mut self.icap_connection.reader, 1024)
    }

    /// 读取完毕后收尾：标记 reader 已读完（校验连接数据边界干净），
    /// 仅当 ICAP 响应 Connection 头允许复用时才把连接归还连接池，否则随 Drop 关闭。
    pub async fn save_connection(mut self) {
        self.icap_connection.mark_reader_finished();
        if self.icap_keepalive {
            self.icap_client.save_connection(self.icap_connection);
        }
    }
}
