/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 流水线请求的解析与传递。
//!
//! [`HttpRequestForwarder`] 在后台任务里循环：空闲等待→解析请求头→按请求是否需要
//! 独占读端（ICAP 送检 / 带体 / 非幂等）决定是发送 [`HttpRecvRequest::RequestWithIO`]
//! （读端随请求一起移交，处理完经 io_sender 归还）还是 [`HttpRecvRequest::RequestWithoutIo`]
//! （读端留在本任务，继续解析下一个请求）。[`HttpRequestAcceptor`] 是主循环一侧的接收端。

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tokio::time::Instant;

use g3_http::server::{HttpRequestParseError, HttpTransparentRequest};
use g3_io_ext::LimitedBufReadExt;

use super::{H1InterceptionError, HttpRequestIo, PipelineStats};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;

/// 已解析的请求及其到达时刻（单调钟 + 墙钟），用于流水线排队等耗时统计。
pub(crate) struct HttpRequest {
    pub(crate) inner: HttpTransparentRequest,
    pub(crate) time_received: Instant,
    pub(crate) datetime_received: DateTime<Utc>,
}

/// 流水线向前台主循环交付的事件：连接关闭、连接级错误、请求解析错误，
/// 或一个成功解析的请求。`RequestWithIO` 变体携带请求读端与归还 channel，
/// 消费方处理完毕必须把 IO 发回（或放弃从而终结连接）。
pub(crate) enum HttpRecvRequest<R: AsyncRead> {
    /// 客户端正常关闭连接（EOF）
    ClientConnectionClosed,
    /// 连接级错误（底层 IO 失败、应用层空闲/读取超时）
    ClientConnectionError(H1InterceptionError),
    /// 单个请求的请求行/请求头解析错误（连接本身未必坏，但主循环会终止检测）
    ClientRequestError(HttpRequestParseError),
    /// 带读端的请求：读端随请求移交，body/ICAP 消费后经 sender 归还
    RequestWithIO(
        HttpRequest,
        HttpRequestIo<R>,
        mpsc::Sender<HttpRequestIo<R>>,
    ),
    /// 无请求体的幂等请求：读端留在解析任务中继续读下一个请求
    RequestWithoutIo(HttpRequest),
}

/// 主循环一侧的请求接收端。close() 后 forwarder 观察到 channel 关闭并停止读请求。
pub(crate) struct HttpRequestAcceptor<R: AsyncRead> {
    recv_request: mpsc::Receiver<HttpRecvRequest<R>>,
}

impl<R> HttpRequestAcceptor<R>
where
    R: AsyncRead,
{
    pub(crate) fn new(recv_request: mpsc::Receiver<HttpRecvRequest<R>>) -> Self {
        HttpRequestAcceptor { recv_request }
    }

    /// 等待下一个请求/事件；channel 关闭（解析任务退出）时返回 None。
    pub(crate) async fn accept(&mut self) -> Option<HttpRecvRequest<R>> {
        self.recv_request.recv().await
    }

    /// 阻止 channel 再收到新请求（连接即将关闭时调用，防止继续从客户端读数据）
    pub(crate) fn close(&mut self) {
        self.recv_request.close();
    }
}

/// 后台请求解析任务：持有客户端读端，循环解析请求并经 channel 送出。
pub(crate) struct HttpRequestForwarder<SC: ServerConfig, R: AsyncRead> {
    ctx: StreamInspectContext<SC>,
    // 当前持有的读端；移交给 RequestWithIO 后为 None，需等 io_receiver 归还
    io: Option<HttpRequestIo<R>>,
    send_request: mpsc::Sender<HttpRecvRequest<R>>,
    stats: Arc<PipelineStats>,
}

impl<SC, R> HttpRequestForwarder<SC, R>
where
    SC: ServerConfig,
    R: AsyncRead + Unpin,
{
    /// 创建解析任务；初始持有客户端读端，channel 发送端与共享统计由流水线入口注入。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        req_io: HttpRequestIo<R>,
        send_request: mpsc::Sender<HttpRecvRequest<R>>,
        stats: Arc<PipelineStats>,
    ) -> Self {
        HttpRequestForwarder {
            ctx,
            io: Some(req_io),
            send_request,
            stats,
        }
    }

    /// 运行到结束：要么前台关闭了接收端（send_request.closed()），
    /// 要么解析循环自身退出。供 spawn 后作为一次性后台任务使用。
    pub(crate) async fn into_running(mut self) {
        let send_request = self.send_request.clone();
        tokio::select! {
            biased;

            _ = send_request.closed() => {}
            _ = self.run() => {}
        }
    }

    /// 解析主循环。两种状态交替：
    /// 1) 持有读端：先带空闲超时地等数据（超时仅在"无在途任务"时才判死，
    ///    否则说明还有请求未处理完，继续等待），再带超时地解析请求头；
    ///    按是否需要移交读端决定发送 WithIO/WithoutIo 变体。
    /// 2) 读端已移交：只能阻塞等待 io_receiver 归还读端后继续解析下一个请求。
    /// 任何连接级错误/EOF/解析错误都会结束循环。
    async fn run(&mut self) {
        // 归还读端的通道：容量 1，恰好覆盖"移交中的唯一读端"
        let (io_sender, mut io_receiver) = mpsc::channel(1);
        let http_config = self.ctx.h1_interception();
        loop {
            if let Some(mut io) = self.io.take() {
                // 在途任务数为 0 时才允许把空闲超时视为客户端已死
                let quit_after_timeout = self.stats.get_alive_task() <= 0;

                match tokio::time::timeout(
                    http_config.pipeline_read_idle_timeout,
                    io.clt_r.fill_wait_data(),
                )
                .await
                {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => {
                        let _ = self
                            .send_request
                            .send(HttpRecvRequest::ClientConnectionClosed)
                            .await;
                        break;
                    }
                    Ok(Err(e)) => {
                        let connection_error = H1InterceptionError::ClientReadFailed(e);
                        let _ = self
                            .send_request
                            .send(HttpRecvRequest::ClientConnectionError(connection_error))
                            .await;
                        break;
                    }
                    Err(_) => {
                        if quit_after_timeout {
                            // 无在途请求还空闲超时：判定客户端应用层超时，终止连接
                            let connection_error = H1InterceptionError::ClientAppTimeout(
                                "pipeline wait request timeout",
                            );
                            let _ = self
                                .send_request
                                .send(HttpRecvRequest::ClientConnectionError(connection_error))
                                .await;
                            break;
                        } else {
                            // 还有请求在途：超时不算错误，放回读端继续等
                            self.io = Some(io);
                            continue;
                        }
                    }
                }

                match tokio::time::timeout(
                    http_config.req_head_recv_timeout,
                    HttpTransparentRequest::parse(
                        &mut io.clt_r,
                        http_config.req_head_max_size,
                        http_config.steal_forwarded_for,
                    ),
                )
                .await
                {
                    Ok(Ok((mut req, _head_bytes))) => {
                        let datetime_received = Utc::now();
                        let time_received = Instant::now();

                        if self.ctx.server_offline() {
                            // According to https://datatracker.ietf.org/doc/html/rfc7230#section-6.3.2
                            // A client that pipelines requests SHOULD retry unanswered requests if
                            // the connection closes before it receives all the corresponding
                            // responses.
                            //（服务端正在下线：禁用 keep-alive 促使客户端尽快断开，
                            //  按 RFC 7230 流水线客户端会自行重试未获应答的请求）
                            req.disable_keep_alive();
                        }

                        // 决定是否移交读端：需要 ICAP 送检或请求不适合流水线
                        // （带体/非幂等/Upgrade）时移交；否则本任务继续解析下一个请求，
                        // 实现真正的流水线并行读取
                        let recv_req = if self.ctx.audit_handle.icap_reqmod_client().is_some() {
                            HttpRecvRequest::RequestWithIO(
                                HttpRequest {
                                    inner: req,
                                    time_received,
                                    datetime_received,
                                },
                                io,
                                io_sender.clone(),
                            )
                        } else if req.pipeline_safe() {
                            self.io = Some(io);
                            HttpRecvRequest::RequestWithoutIo(HttpRequest {
                                inner: req,
                                time_received,
                                datetime_received,
                            })
                        } else {
                            HttpRecvRequest::RequestWithIO(
                                HttpRequest {
                                    inner: req,
                                    time_received,
                                    datetime_received,
                                },
                                io,
                                io_sender.clone(),
                            )
                        };

                        let _ = self.send_request.send(recv_req).await;
                        self.stats.add_task();
                    }
                    Ok(Err(e)) => {
                        // 请求解析失败：作为请求错误上报，主循环会回复错误并终止
                        let _ = self
                            .send_request
                            .send(HttpRecvRequest::ClientRequestError(e))
                            .await;
                        break;
                    }
                    Err(_) => {
                        // 已有数据但请求头在超时内未收齐：客户端应用层超时
                        let connection_error =
                            H1InterceptionError::ClientAppTimeout("pipeline read request timeout");
                        let _ = self
                            .send_request
                            .send(HttpRecvRequest::ClientConnectionError(connection_error))
                            .await;
                        break;
                    }
                }
            } else {
                match io_receiver.recv().await {
                    Some(io) => {
                        // we can now read the next request（读端已归还，继续解析）
                        self.io = Some(io);
                    }
                    None => {
                        // write end closed normally, task done
                        //（所有 sender 已释放：连接处理完毕，正常退出）
                        break;
                    }
                }
            }
        }
    }
}
