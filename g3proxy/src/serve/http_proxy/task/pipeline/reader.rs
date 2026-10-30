/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use log::trace;
use tokio::io::AsyncRead;
use tokio::sync::mpsc;

use g3_io_ext::{GlobalLimitGroup, LimitedBufReadExt, LimitedBufReader, NilLimitedReaderStats};

use super::protocol::{HttpClientReader, HttpProxyRequest};
use super::{CommonTaskContext, HttpProxyCltWrapperStats, HttpProxyPipelineStats};
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::ServerStats;

/// 流水线读端任务：持续从客户端 socket 解析 HTTP 请求，
/// 将解析结果（或解析错误对应的响应）经 `task_queue` 交给 writer 任务。
pub(crate) struct HttpProxyPipelineReaderTask<CDR> {
    ctx: Arc<CommonTaskContext>,
    // 投递给 writer 的队列：Ok 为解析出的请求，Err 为需要直接回给客户端的错误响应
    task_queue: mpsc::Sender<Result<HttpProxyRequest<CDR>, HttpProxyClientResponse>>,
    // 当前可用的 socket 读端；当读端被移交给 writer（请求体需要被 body_reader 消费）时为 None
    stream_reader: Option<HttpClientReader<CDR>>,
    pipeline_stats: Arc<HttpProxyPipelineStats>,
}

/// 读端任务的构建与主循环。泛型 `CDR` 是客户端 socket 的读半部。
impl<CDR> HttpProxyPipelineReaderTask<CDR>
where
    CDR: AsyncRead + Send + Unpin + 'static,
{
    /// 创建读端任务：用限速的 [LimitedBufReader] 包裹原始读半部，读字节数经
    /// [HttpProxyCltWrapperStats] 计入服务器统计。
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        task_sender: mpsc::Sender<Result<HttpProxyRequest<CDR>, HttpProxyClientResponse>>,
        read_half: CDR,
        pipeline_stats: &Arc<HttpProxyPipelineStats>,
    ) -> Self {
        let clt_r_stats = HttpProxyCltWrapperStats::new_for_reader(&ctx.server_stats);
        let limit_config = &ctx.server_config.tcp_sock_speed_limit;
        let clt_r = LimitedBufReader::new(
            read_half,
            limit_config.shift_millis,
            limit_config.max_north,
            clt_r_stats,
            Arc::new(NilLimitedReaderStats::default()),
        );
        HttpProxyPipelineReaderTask {
            ctx: Arc::clone(ctx),
            task_queue: task_sender,
            stream_reader: Some(clt_r),
            pipeline_stats: Arc::clone(pipeline_stats),
        }
    }

    /// 进入运行状态，消耗本任务的所有权。同时监听 `task_queue` 的关闭事件：
    /// 一旦 writer 端关闭（例如前一个请求出错后不再处理），立即停止继续读取。
    pub(crate) async fn into_running(mut self) {
        // NOTE the receiver end should not be cloned, as the closed events is bounding to each
        let task_queue = self.task_queue.clone(); // to avoid ref self
        tokio::select! {
            biased;

            // writer 端已关闭：优先退出，不再解析新请求
            _ = task_queue.closed() => {
                trace!("write end has closed for previous request");
            }
            _ = self.run() => {}
        }
    }

    /// 读取主循环。两种状态交替：
    /// 1. 持有读端：等待并解析下一条请求，然后把请求交给 writer；
    /// 2. 未持有读端（读端随请求体一起移交给了 writer 任务）：等待 writer 通过
    ///    `stream_receiver` 把读端归还回来（管道背压点：请求体未被消费完前不读下一条）。
    /// 循环结束即丢弃读端，由 writer 负责善后。
    async fn run(&mut self) {
        // 容量为 1 的 channel：writer 用其归还（或丢弃）被移交给请求体的读端
        let (stream_sender, mut stream_receiver) = mpsc::channel(1);
        loop {
            if let Some(mut reader) = self.stream_reader.take() {
                // 存活任务数为 0 说明 writer 已不再处理任何请求（可能遭攻击/异常），
                // 空闲超时后直接放弃这条连接
                let quit_after_timeout = self.pipeline_stats.get_alive_task() <= 0;

                // 先等待 socket 上有数据（管道整体的空闲超时，用于 keep-alive 复用）
                match tokio::time::timeout(
                    self.ctx.server_config.pipeline_read_idle_timeout,
                    reader.fill_wait_data(),
                )
                .await
                {
                    Ok(Ok(true)) => {} // 有数据，继续解析请求头
                    Ok(Ok(false)) => {
                        // 客户端正常关闭连接（EOF）
                        trace!("client {} closed", self.ctx.client_addr());
                        break;
                    }
                    Ok(Err(e)) => {
                        // socket 读错误，放弃连接
                        trace!("client {} closed with error {e:?}", self.ctx.client_addr());
                        break;
                    }
                    Err(_) => {
                        // timeout
                        // 空闲超时：归还读端；若已无存活任务则视为异常，直接退出
                        self.stream_reader = Some(reader);
                        if quit_after_timeout {
                            // TODO may be attack
                            break;
                        }
                        continue;
                    }
                }

                // HTTP 版本先按 1.1 假定，parse 过程中若识别为 1.0 会被改写
                // （1.0 与 1.1 的差异主要体现在 keep-alive 默认值，由解析层处理）
                let mut version: http::Version = http::Version::HTTP_11; // default to 1.1
                // 解析一条完整请求头；这是每条请求的独立超时，与上面的空闲超时不同
                match tokio::time::timeout(
                    self.ctx.server_config.timeout.recv_req_header,
                    HttpProxyRequest::parse(
                        &self.ctx.server_config,
                        &mut reader,
                        stream_sender.clone(),
                        &mut version,
                    ),
                )
                .await
                {
                    Ok(Ok((mut req, send_reader))) => {
                        // send_reader=true：该请求携带消息体或需要独占连接（如 CONNECT），
                        // 读端随请求一起交给 writer；否则 reader 留在本地继续读下一条请求
                        if send_reader {
                            req.body_reader = Some(reader);
                        } else {
                            self.stream_reader = Some(reader);
                        }

                        let server_is_online = self.ctx.server_stats.is_online();
                        if !server_is_online {
                            // According to https://datatracker.ietf.org/doc/html/rfc7230#section-6.3.2
                            // A client that pipelines requests SHOULD retry unanswered requests if
                            // the connection closes before it receives all of the corresponding
                            // responses.
                            // 服务器已下线：禁用 keep-alive，告知客户端不要继续管道化请求
                            req.inner.disable_keep_alive();
                        }

                        // 投递请求给 writer；writer 关闭则退出
                        if self.task_queue.send(Ok(req)).await.is_err() {
                            trace!(
                                "write end has closed for previous request while sending new request"
                            );
                            break;
                        }
                        self.pipeline_stats.add_task();

                        // 下线时处理完这一条就收尾
                        if !server_is_online {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        // 请求头解析失败：读端保留在本地（协议已失步），并尽力回一个错误响应
                        self.stream_reader = Some(reader);
                        if let Some(response) =
                            HttpProxyClientResponse::from_request_error(&e, version)
                            && self.task_queue.send(Err(response)).await.is_err()
                        {
                            trace!(
                                "write end has closed for previous request while sending error response"
                            );
                        }
                        trace!("Error handling client {}: {e:?}", self.ctx.client_addr());
                        // TODO handle error, negotiation failed, may be attack
                        break;
                    }
                    Err(_) => {
                        // 请求头在 recv_req_header 超时内未读完，放弃连接
                        trace!("timeout to read in a complete request header");
                        // TODO handle timeout, may be attack
                        break;
                    }
                }
            } else {
                // 读端已随某条请求移交给 writer，等待其归还
                match stream_receiver.recv().await.flatten() {
                    Some(mut reader) => {
                        // we can now read the next request
                        // 归还的读端可能带有限速统计/旧限额设置，先重置再继续使用
                        reader.reset_buffer_stats(Arc::new(NilLimitedReaderStats::default()));
                        let limit_config = &self.ctx.server_config.tcp_sock_speed_limit;
                        reader.reset_local_limit(limit_config.shift_millis, limit_config.max_north);
                        reader.retain_global_limiter_by_group(GlobalLimitGroup::Server);
                        self.stream_reader = Some(reader);
                    }
                    None => {
                        // write end closed normally, task done
                        break;
                    }
                }
            }
        }
    }
}
