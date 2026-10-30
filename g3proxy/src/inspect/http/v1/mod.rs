/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! HTTP/1.1 源站内容拦截检测的主入口与状态机骨架。
//!
//! [`H1InterceptObject`] 是 `StreamInspection` 枚举中 HTTP/1 检测阶段的载体：
//! 它从已判定为 HTTP/1 的客户端/上游双向流中逐请求读取（借助 pipeline 子模块），
//! 再按请求语义分派给三个子任务：CONNECT 隧道（[connect]）、Upgrade 协议切换
//! （[upgrade]）、普通方法转发（[forward]）。当某个请求需要升级为下一层协议
//! 检测（TCP 隧道、HTTP/2、WebSocket）时，返回新的 `StreamInspection` 对象，
//! 否则持续在同一连接上循环处理流水线中的后续请求。

use std::sync::Arc;

use async_recursion::async_recursion;
use http::{Method, Version};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_dpi::Protocol;
use g3_io_ext::{FlexBufReader, LimitedBufReadExt};
use g3_slog_types::LtUuid;
use g3_types::net::TlsKeyLogBuffer;

use crate::config::server::ServerConfig;
use crate::inspect::{
    BoxAsyncRead, BoxAsyncWrite, InterceptionError, StreamInspectContext, StreamInspection,
};
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::ServerTaskResult;

mod error;
pub(crate) use error::H1InterceptionError;

mod pipeline;
use pipeline::{HttpRecvRequest, HttpRequest, PipelineStats};

mod connect;
use connect::H1ConnectTask;

mod forward;
use forward::H1ForwardTask;

mod upgrade;
use upgrade::H1UpgradeTask;

/* added by wming for repid audit */
use g3_http::HttpBodyType;

/// 请求侧 IO：仅持有客户端读端（带缓冲，请求体需按 body_type 逐块读取）。
pub(crate) struct HttpRequestIo<CR: AsyncRead> {
    clt_r: FlexBufReader<CR>,
}

/// 响应侧 IO：写回客户端、读上游响应头/体、以及向上游发送请求写端。
/// 在同一个检测循环内被复用，因此与 [`HttpRequestIo`] 分开建模，
/// 便于把请求读端交给流水线任务而响应写端留在主循环。
pub(crate) struct HttpResponseIo<CW: AsyncWrite, UR: AsyncRead, UW: AsyncWrite> {
    clt_w: CW,
    ups_r: FlexBufReader<UR>,
    ups_w: UW,
}

/// 进入检测前暂存的原始四向 IO；在 `do_intercept` 开始时被拆分为
/// 请求侧/响应侧两个 IO 结构（`Option` 便于一次性 take 走所有权）。
struct H1InterceptIo {
    clt_r: FlexBufReader<BoxAsyncRead>,
    clt_w: BoxAsyncWrite,
    ups_r: BoxAsyncRead,
    ups_w: BoxAsyncWrite,
}

/// HTTP/1 拦截检测主状态机对象：持有双向 IO、检测上下文、
/// 本连接内递增的请求序号 req_id，以及用于 keylog 导出 TLS 密钥的缓冲。
pub(crate) struct H1InterceptObject<SC: ServerConfig> {
    io: Option<H1InterceptIo>,
    ctx: StreamInspectContext<SC>,
    req_id: usize,
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<SC: ServerConfig> H1InterceptObject<SC> {
    /// 创建检测对象；此时 IO 尚未注入（io 为 None），req_id 从 0 起计。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
    ) -> Self {
        H1InterceptObject {
            io: None,
            ctx,
            req_id: 0,
            keylog_buffer,
        }
    }

    /// 注入客户端/上游的四向 IO，之后才能调用 [`Self::intercept`]。
    pub(crate) fn set_io(
        &mut self,
        clt_r: FlexBufReader<BoxAsyncRead>,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = H1InterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }
}

// 拦截审计日志宏：统一附带拦截类型、任务 ID、检测深度与当前请求序号，
// 仅当服务端配置了 intercept logger 时才输出。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H1Connection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "current_req_id" => $obj.req_id,
            );
        }
    };
}

impl<SC> H1InterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 拦截入口：驱动整个 HTTP/1 检测循环。
    /// 返回 `Ok(Some(..))` 表示流量需转入下一层协议检测状态（如隧道/H2/WebSocket）；
    /// `Ok(None)` 表示连接正常终结；错误会被记录并转换为带 Http1 协议标签的任务错误。
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        match self.do_intercept().await {
            Ok(v) => {
                intercept_log!(self, "finished");
                Ok(v)
            }
            Err(e) => {
                intercept_log!(self, "{e}");
                Err(InterceptionError::H1(e).into_server_task_error(Protocol::Http1))
            }
        }
    }

    /// 检测主循环：读请求与写响应解耦——请求由独立的转发任务（pipeline）解析并经
    /// channel 送回来，本函数按请求语义分派给 CONNECT/Upgrade/Forward 子任务；
    /// 遇到需要协议切换的请求就提前 return 新的 `StreamInspection`。
    /// `#[async_recursion]` 是因为上游可能把 CONNECT/Upgrade 的后续流再交回本状态机。
    #[async_recursion]
    async fn do_intercept(&mut self) -> Result<Option<StreamInspection<SC>>, H1InterceptionError> {
        let H1InterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();
        // 流水线统计：alive 任务数用于判断"是否允许在空闲超时时直接终止连接"
        let pipeline_stats = Arc::new(PipelineStats::default());

        let mut rsp_io = HttpResponseIo {
            clt_w,
            ups_r: FlexBufReader::new(ups_r),
            ups_w,
        };
        let req_io = HttpRequestIo { clt_r };
        // 启动后台请求解析任务：解析出的请求经 mpsc channel 交给下面的 accept 循环
        let (req_forwarder, mut req_acceptor) =
            pipeline::new_request_handler(self.ctx.clone(), req_io, pipeline_stats.clone());
        tokio::spawn(req_forwarder.into_running());

        loop {
            let r = tokio::select! {
                biased;

                r = req_acceptor.accept() => match r {
                    Some(r) => r,
                    None => {
                        // channel 关闭且无排队请求：两端优雅关闭，连接正常结束
                        let _ = rsp_io.ups_w.shutdown().await;
                        let _ = rsp_io.clt_w.shutdown().await;
                        return Ok(None);
                    }
                },
                r = rsp_io.ups_r.fill_wait_data() => {
                    // 无请求在途时上游却先发了数据或关闭连接，均视为异常终止
                    req_acceptor.close();
                    return match r {
                        Ok(true) => Err(H1InterceptionError::UnexpectedUpstreamData),
                        Ok(false) => Err(H1InterceptionError::ClosedByUpstream),
                        Err(e) => Err(H1InterceptionError::UpstreamClosedWithError(e)),
                    };
                }
            };

            self.req_id += 1;
            match r {
                HttpRecvRequest::ClientConnectionClosed => {
                    // 客户端 EOF：关闭上游写端即可结束整个连接
                    let _ = rsp_io.ups_w.shutdown().await;
                    return Ok(None);
                }
                HttpRecvRequest::ClientConnectionError(e) => return Err(e),
                HttpRecvRequest::ClientRequestError(e) => {
                    // 请求行/请求头解析失败：若该错误可映射为 HTTP 错误响应（如 400），
                    // 先回复客户端再终止检测
                    if let Some(rsp) =
                        HttpProxyClientResponse::from_request_error(&e, Version::HTTP_11)
                    {
                        let _ = rsp.reply_err_to_request(&mut rsp_io.clt_w).await;
                    }
                    return Err(e.into());
                }
                HttpRecvRequest::RequestWithoutIo(r) => {
                    // 幂等且无请求体的请求：读端仍留在解析任务手中，这里只处理响应
                    let mut forward_task = H1ForwardTask::new(
                        self.ctx.clone(),
                        &r,
                        self.req_id,
                        self.keylog_buffer.clone(),
                    );
                    // not ICAP in this case
                    //（无请求体可送检，ICAP reqmod 不适用，直接原样转发）
                    forward_task.forward_without_body(&mut rsp_io).await;
                    pipeline_stats.del_task();
                    if forward_task.should_close() {
                        req_acceptor.close();
                    }
                }
                HttpRecvRequest::RequestWithIO(r, mut req_io, io_sender) => {
                    if r.inner.method == Method::CONNECT {
                        // CONNECT：建立隧道。成功时返回目标地址，转入逐流检测
                        let mut connect_task = H1ConnectTask::new(self.ctx.clone(), r, self.req_id);
                        let r = if let Some(reqmod_client) =
                            self.ctx.audit_handle.icap_reqmod_client()
                        {
                            connect_task.forward_icap(&mut rsp_io, reqmod_client).await
                        } else {
                            connect_task.forward_original(&mut rsp_io).await
                        };
                        if let Some(upstream) = r {
                            pipeline_stats.del_task();

                            // 隧道已建好：把裸 IO 交给 StreamInspectObject 继续检测
                            let next_obj = connect_task.into_connect(req_io, rsp_io, upstream);
                            return Ok(Some(next_obj));
                        } else if connect_task.should_close() {
                            pipeline_stats.del_task();

                            req_acceptor.close();
                        } else {
                            // 建隧道失败但连接仍可复用（如鉴权 407），继续处理后续请求
                            pipeline_stats.del_task();
                        }
                    } else if r.inner.upgrade {
                        // 含 Upgrade 头的请求：协议切换（WebSocket、h2、extended connect 等）
                        let mut upgrade_task = H1UpgradeTask::new(
                            self.ctx.clone(),
                            r,
                            self.req_id,
                            self.keylog_buffer.clone(),
                        );
                        let r = if let Some(reqmod_client) =
                            self.ctx.audit_handle.icap_reqmod_client()
                        {
                            upgrade_task.forward_icap(&mut rsp_io, reqmod_client).await
                        } else {
                            upgrade_task.forward_original(&mut rsp_io).await
                        };
                        if let Some((protocol, upstream)) = r {
                            pipeline_stats.del_task();

                            // 收到 101 响应：按切换后的协议创建下一个检测状态机
                            let next_obj =
                                upgrade_task.into_upgrade(req_io, rsp_io, protocol, upstream)?;
                            return Ok(Some(next_obj));
                        } else if upgrade_task.should_close() {
                            pipeline_stats.del_task();

                            req_acceptor.close();
                        } else {
                            pipeline_stats.del_task();
                        }
                    } else {
                        /* added by wming for repid audit */
                        // 普通方法（GET/POST 等）：走 forward 转发路径
                        let mut forward_task = H1ForwardTask::new(
                            self.ctx.clone(),
                            &r,
                            self.req_id,
                            self.keylog_buffer.clone(),
                        );

                        let cfg = self.ctx.h1_interception();

                        // 判断请求体是否"值得"送 ICAP 检测：chunked 一律待定，
                        // 定长体则要求超过 req_body_min_size 阈值
                        let body_pending = match r.inner.body_type() {
                            Some(HttpBodyType::Chunked) => true,
                            Some(HttpBodyType::ContentLength(v)) => {
                                v > cfg.req_body_min_size as u64
                            }
                            _ => false,
                        };

                        // req_hasbody 开关决定是否允许无请求体请求绕过 ICAP 直转
                        let use_icap = if cfg.req_hasbody { body_pending } else { true };

                        if use_icap {
                            if let Some(reqmod_client) = self.ctx.audit_handle.icap_reqmod_client()
                            {
                                // 请求体流经 ICAP reqmod 改写后再转发
                                forward_task
                                    .adapt_with_io(&mut req_io, &mut rsp_io, reqmod_client)
                                    .await;
                            } else {
                                forward_task.forward_with_io(&mut req_io, &mut rsp_io).await;
                            }
                        } else {
                            forward_task.forward_with_io(&mut req_io, &mut rsp_io).await;
                        }

                        pipeline_stats.del_task();
                        if forward_task.should_close() {
                            req_acceptor.close();
                        } else {
                            // 连接可复用：把请求读端归还给流水线任务，继续读下一个请求
                            let _ = io_sender.send(req_io).await;
                        }
                    }
                }
            }
        }
    }
}

/// 把请求侧/响应侧 IO 结构还原为四个裸 IO，供下一层检测状态机
/// （隧道/H2/WebSocket）使用。读端缓冲若非空则保留 FlexBufReader 包装，
/// 避免已预读的字节丢失。
fn convert_io(
    req_io: HttpRequestIo<BoxAsyncRead>,
    rsp_io: HttpResponseIo<BoxAsyncWrite, BoxAsyncRead, BoxAsyncWrite>,
) -> (BoxAsyncRead, BoxAsyncWrite, BoxAsyncRead, BoxAsyncWrite) {
    let HttpRequestIo { clt_r } = req_io;
    let HttpResponseIo {
        clt_w,
        ups_r,
        ups_w,
    } = rsp_io;

    let clt_r = if clt_r.buffer().is_empty() {
        clt_r.into_inner()
    } else {
        Box::new(clt_r) as BoxAsyncRead
    };

    let ups_r = if ups_r.buffer().is_empty() {
        ups_r.into_inner()
    } else {
        Box::new(ups_r) as BoxAsyncRead
    };

    (clt_r, clt_w, ups_r, ups_w)
}
