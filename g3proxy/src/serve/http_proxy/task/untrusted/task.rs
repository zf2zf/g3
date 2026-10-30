/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use g3_http::HttpBodyReader;
use g3_http::server::HttpProxyClientRequest;
use g3_io_ext::{StreamCopy, StreamCopyError};

use super::protocol::{HttpClientReader, HttpClientWriter, HttpProxyRequest};
use super::{CommonTaskContext, UntrustedCltReadWrapperStats};
use crate::module::http_forward::HttpProxyClientResponse;
use crate::serve::http_proxy::HttpUntrustedTaskAliveGuard;
use crate::serve::{ServerTaskError, ServerTaskResult};

/// 非可信 HTTP 请求任务：客户端请求没有（或通过）代理认证、且来源不属于可信网段时，
/// 不进行转发，而是回复 407 代理认证错误；若服务器允许受限的"untrusted 上传"，
/// 则在限速下把请求体排空丢弃（drain），以便连接上后续的合法请求继续被处理。
pub(crate) struct HttpProxyUntrustedTask<'a> {
    ctx: Arc<CommonTaskContext>,
    /// 借用自 pipeline 的已解析客户端请求（仅读取其方法/body 类型等信息）
    req: &'a HttpProxyClientRequest,
    /// 本次交互结束后是否需要关闭客户端连接（keep-alive 判定结果）
    should_close: bool,
    /// 任务是否已正式计入统计并开始运行（决定 Drop 时是否执行 post_stop）
    started: bool,
    /// 存活哨兵：持有期间服务器统计中记有一个运行中的 untrusted 任务
    _alive_guard: Option<HttpUntrustedTaskAliveGuard>,
}

// 任务被丢弃时补做停止钩子，保证统计/日志不会漏记
impl Drop for HttpProxyUntrustedTask<'_> {
    fn drop(&mut self) {
        if self.started {
            self.post_stop();
            self.started = false;
        }
    }
}

impl<'a> HttpProxyUntrustedTask<'a> {
    /// 从已解析的非可信请求创建任务；请求未声明 keep-alive 则标记需要关闭连接
    pub(crate) fn new(
        ctx: &Arc<CommonTaskContext>,
        req: &'a HttpProxyRequest<impl AsyncRead>,
    ) -> Self {
        HttpProxyUntrustedTask {
            ctx: Arc::clone(ctx),
            req: &req.inner,
            should_close: !req.inner.keep_alive(),
            started: false,
            _alive_guard: None,
        }
    }

    /// 开始排空请求体前调用：向服务器统计注册一个运行中的 untrusted 任务
    fn pre_start(&mut self) {
        self._alive_guard = Some(self.ctx.server_stats.add_http_untrusted_task());

        self.started = true;
    }

    /// 任务结束钩子；当前无额外收尾动作（与其它任务类型保持对称的结构）
    fn post_stop(&self) {}

    /// pipeline 据此决定处理完本请求后是否关闭客户端连接
    #[inline]
    pub(crate) fn should_close(&self) -> bool {
        self.should_close
    }

    /// 任务主流程：
    /// 1. 无请求体（如 GET）：仅回复 407 认证错误；
    /// 2. 有请求体：先回复 407（响应先于请求体发送），再视配置决定是否
    ///    在限速下排空请求体（允许客户端随后在同一连接上发送合法认证请求）；
    /// 3. 全程根据结果维护 should_close。
    pub(crate) async fn run<CDR, CDW>(
        &mut self,
        clt_r: &mut Option<HttpClientReader<CDR>>,
        clt_w: &mut HttpClientWriter<CDW>,
    ) where
        CDR: AsyncRead + Unpin,
        CDW: AsyncWrite + Unpin,
    {
        if self.req.body_type().is_none() {
            self.reply_auth_error(clt_w).await;
        } else if let Some(br) = clt_r {
            if self.req.has_auth_info() || self.ctx.server_config.untrusted_read_limit.is_none() {
                // untrusted read is not permitted, we should close the connection
                // 携带认证信息或未配置限速时，不允许继续接收该请求体，回复后断开
                self.should_close = true;
            }

            self.reply_auth_error(clt_w).await;

            if !self.should_close
                && let Some(limit_config) = &self.ctx.server_config.untrusted_read_limit
            {
                // 对客户端读取器套上限速，防止非可信客户端借大请求体占用带宽
                br.reset_local_limit(limit_config.shift_millis, limit_config.max_north);
                // 读取字节数计入 untrusted 上行流量统计
                let buffer_stats = UntrustedCltReadWrapperStats::new_obj(&self.ctx.server_stats);
                br.reset_buffer_stats(buffer_stats);

                self.pre_start();
                if self.drain_body(br).await.is_err() {
                    self.should_close = true;
                }
            }
        } else {
            // should be impossible
            // 有 body 却没有读取器：属于内部状态异常，直接断开
            self.should_close = true;
        }
    }

    /// 向客户端回复 407 Proxy Authentication Required；回复失败则标记关闭连接
    async fn reply_auth_error<CDW>(&mut self, clt_w: &mut HttpClientWriter<CDW>)
    where
        CDW: AsyncWrite + Unpin,
    {
        let result = HttpProxyClientResponse::reply_proxy_auth_err(
            self.req.version,
            clt_w,
            &self.ctx.server_config.auth_realm,
            self.should_close,
        )
        .await;
        if result.is_err() {
            self.should_close = true;
        }
    }

    /// 在限速下把请求体完整读出并丢弃（写入 sink），期间做空闲检测与服务器退出感知
    async fn drain_body<CDR>(&mut self, clt_r: &mut HttpClientReader<CDR>) -> ServerTaskResult<()>
    where
        CDR: AsyncRead + Unpin,
    {
        let mut body_reader = HttpBodyReader::new(
            clt_r,
            self.req.body_type().unwrap(),
            self.ctx.server_config.body_line_max_len,
        );
        let mut sink_w = tokio::io::sink();
        let mut clt_to_sink = StreamCopy::new(
            &mut body_reader,
            &mut sink_w,
            &self.ctx.server_config.tcp_copy,
        );

        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count = 0;
        loop {
            tokio::select! {
                biased;

                r = &mut clt_to_sink => {
                    // 搬运结束：写入目标恒为 sink，写失败只可能是内部异常
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(ServerTaskError::ClientTcpReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(_)) => Err(ServerTaskError::InternalServerError("write to sinking failed")),
                    };
                }
                n = idle_interval.tick() => {
                    if clt_to_sink.is_idle() {
                        idle_count += n;

                        // 连续空闲超限：读方向停滞视为客户端超时，写方向停滞视为内部错误
                        if idle_count >= self.ctx.server_config.task_idle_max_count {
                            return if clt_to_sink.no_cached_data() {
                                Err(ServerTaskError::ClientAppTimeout("idle while reading request body"))
                            } else {
                                Err(ServerTaskError::InternalServerError("idle while writing to sinking"))
                            };
                        }
                    } else {
                        idle_count = 0;

                        clt_to_sink.reset_active();
                    }

                    // 服务器要求强制退出时放弃本任务
                    if self.ctx.server_quit_policy.force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }
    }
}
