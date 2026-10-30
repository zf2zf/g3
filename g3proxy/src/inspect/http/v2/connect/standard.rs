/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 标准 HTTP/2 CONNECT（RFC 7540 §8.3）的隧道任务。
//!
//! [`H2ConnectTask`] 从 CONNECT 请求的 :authority 解析出目的地址，经
//! [`ExchangeHead`] 完成与源站的头部交换；隧道建立（2xx）成功后把该流的
//! 四条半流包装成 TCP 式的读写句柄，交给通用的
//! `inspect::stream::transit_with_inspection` 继续做下一层协议检测
//! （通常是 TLS 再检测），从而复用 H1/CONNECT 已有的深层检测流水线。

use bytes::Bytes;
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream, StreamId};
use http::{Request, Response, StatusCode, Version};

use g3_h2::{H2StreamReader, H2StreamWriter};
use g3_http::server::UriExt;
use g3_slog_types::{LtDateTime, LtDuration, LtH2StreamId, LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use super::{ExchangeHead, HttpConnectTaskNotes};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;

/// 以 "H2Connect" 为拦截类型输出标准 CONNECT 隧道的全生命周期日志，
/// 附带两侧流 ID、目的地址与各阶段耗时。未配置检测日志器时不输出。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2Connect",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "clt_stream" => LtH2StreamId(&$obj.clt_stream_id),
                "ups_stream" => $obj.ups_stream_id.as_ref().map(LtH2StreamId),
                "next_upstream" => $obj.upstream.as_ref().map(LtUpstreamAddr),
                "started_at" => LtDateTime(&$obj.http_notes.started_datetime),
                "ready_time" => LtDuration($obj.http_notes.ready_time),
                "rsp_status" => $obj.http_notes.rsp_status,
                "origin_status" => $obj.http_notes.origin_status,
                "dur_req_send_hdr" => LtDuration($obj.http_notes.dur_req_send_hdr),
                "dur_rsp_recv_hdr" => LtDuration($obj.http_notes.dur_rsp_recv_hdr),
            );
        }
    };
}

/// 标准 CONNECT 隧道任务：一个实例对应客户端发起的一条 CONNECT 流。
pub(crate) struct H2ConnectTask<SC: ServerConfig> {
    /// 检测上下文（ACL、审计句柄、空闲配置等）
    ctx: StreamInspectContext<SC>,
    /// 客户端侧逻辑流 ID，用于日志关联
    clt_stream_id: StreamId,
    /// 源站侧逻辑流 ID；请求头尚未发出时为 None
    ups_stream_id: Option<StreamId>,
    /// 从 :authority 解析出的隧道目的地址；解析失败时为 None
    upstream: Option<UpstreamAddr>,
    /// 头部交换阶段的耗时/状态记录
    http_notes: HttpConnectTaskNotes,
}

impl<SC> H2ConnectTask<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建任务，目的地址将在 into_running 中从请求 URI 解析。
    pub(crate) fn new(ctx: StreamInspectContext<SC>, clt_stream_id: StreamId) -> Self {
        H2ConnectTask {
            ctx,
            clt_stream_id,
            ups_stream_id: None,
            upstream: None,
            http_notes: HttpConnectTaskNotes::default(),
        }
    }

    /// 向客户端直接回 400 并结束该流（请求不合规，不能发往源站）。
    fn reply_bad_request(&mut self, mut clt_send_rsp: SendResponse<Bytes>) {
        if let Ok(rsp) = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .version(Version::HTTP_2)
            .body(())
        {
            let rsp_status = rsp.status().as_u16();
            if clt_send_rsp.send_response(rsp, true).is_ok() {
                self.http_notes.rsp_status = rsp_status;
            }
        }
    }

    /// 运行 CONNECT 任务：先解析目的地址（非法则回 400 终止），再完成
    /// 头部交换；成功建立隧道后进入双向数据中继。返回即代表本流结束。
    pub(crate) async fn into_running(
        mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        // CONNECT 的目标由 :authority 伪头给出，默认按 443 端口补全
        let upstream = match clt_req.uri().get_upstream_with_default_port(443) {
            Ok(d) => {
                self.upstream = Some(d.clone());
                d
            }
            Err(e) => {
                self.reply_bad_request(clt_send_rsp);
                intercept_log!(self, "invalid connect request: {e}");
                return;
            }
        };

        let mut exchange_head = ExchangeHead::new(&self.ctx, &mut self.http_notes);
        let exchange_head_result = exchange_head.run(clt_req, clt_send_rsp, h2s).await;
        self.ups_stream_id = exchange_head.ups_stream_id.take();
        match exchange_head_result {
            // 隧道建立成功：四条半流就绪，开始字节级中继
            Ok(Some((clt_r, clt_w, ups_r, ups_w))) => {
                intercept_log!(self, "started");

                self.run_standard_transfer(upstream, clt_r, clt_w, ups_r, ups_w)
                    .await;
            }
            // 流程已终结（CONNECT 被拒/错误响应已发出），无数据要中继
            Ok(None) => {
                intercept_log!(self, "finished without data");
            }
            Err(e) => {
                intercept_log!(self, "head exchange error: {e}");
            }
        }
    }

    /// 隧道内数据中继：把 h2 半流适配成 AsyncRead/AsyncWrite 句柄后，交由
    /// 通用检测转发流水线（含协议再检测、ACL、TLS 拦截等）处理，
    /// 行为与 HTTP/1 CONNECT 隧道一致。
    async fn run_standard_transfer(
        self,
        upstream: UpstreamAddr,
        clt_r: RecvStream,
        clt_w: SendStream<Bytes>,
        ups_r: RecvStream,
        ups_w: SendStream<Bytes>,
    ) {
        // h2 RecvStream/SendStream 包装为字节流读写器，对上层表现得像一条 TCP
        let clt_r = H2StreamReader::new(clt_r);
        let clt_w = H2StreamWriter::new(clt_w);
        let ups_r = H2StreamReader::new(ups_r);
        let ups_w = H2StreamWriter::new(ups_w);

        // explicit_protocol 传 None：隧道内协议未知，由内层 DPI 重新探测
        if let Err(e) = crate::inspect::stream::transit_with_inspection(
            clt_r,
            clt_w,
            ups_r,
            ups_w,
            self.ctx.clone(),
            upstream,
            None,
        )
        .await
        {
            intercept_log!(self, "data transfer error: {e}");
        } else {
            intercept_log!(self, "finished");
        }
    }
}
