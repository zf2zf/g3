/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 扩展 CONNECT（带 `:protocol` 伪头，如 RFC 8441 websocket、CONNECT-UDP）任务。
//!
//! [`H2ExtendedConnectTask`] 按协商出的升级协议分派：websocket 走深层检测并
//! 交给 H2WebsocketInterceptObject；connect-udp 及其他未知协议在头部交换成功后
//! 做透明中继（协议本身不可解析，由 ACL 决定是否放行）；HTTP/TLS 升级与
//! connect-ip 目前明确不支持，直接回 400。

use std::str::FromStr;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{RecvStream, StreamId};
use http::{Request, Response, StatusCode, Version, header};

use g3_dpi::Protocol;
use g3_h2::{H2StreamReader, H2StreamWriter};
use g3_http::server::UriExt;
use g3_slog_types::{LtDateTime, LtDuration, LtH2StreamId, LtUpstreamAddr, LtUuid};
use g3_types::net::{HttpUpgradeToken, UpstreamAddr, WebSocketNotes};

use super::{ExchangeHead, H2StreamTransferError, HttpConnectTaskNotes};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspectContext;
use crate::log::inspect::{InspectSource, stream::StreamInspectLog};

/// 以 "H2ExtendedConnect" 为拦截类型输出扩展 CONNECT 的全生命周期日志，
/// 附带升级协议名、两侧流 ID 与各阶段耗时。未配置检测日志器时不输出。
macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "H2ExtendedConnect",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "clt_stream" => LtH2StreamId(&$obj.clt_stream_id),
                "ups_stream" => $obj.ups_stream_id.as_ref().map(LtH2StreamId),
                "next_protocol" => $obj.protocol.to_string(),
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

/// 扩展 CONNECT 任务：一个实例对应一条带 :protocol 伪头的客户端逻辑流。
pub(crate) struct H2ExtendedConnectTask<SC: ServerConfig> {
    /// 检测上下文（websocket ACL 动作、审计句柄等）
    ctx: StreamInspectContext<SC>,
    /// 客户端侧逻辑流 ID，用于日志关联
    clt_stream_id: StreamId,
    /// 源站侧逻辑流 ID；请求头尚未发出时为 None
    ups_stream_id: Option<StreamId>,
    /// 由 :protocol 伪头映射出的升级协议类型
    protocol: HttpUpgradeToken,
    /// 隧道目的地址；按协议从 Host 头或 :authority 解析，失败时为 None
    upstream: Option<UpstreamAddr>,
    /// 头部交换阶段的耗时/状态记录
    http_notes: HttpConnectTaskNotes,
}

/// 从请求的 Host 头解析隧道目的地址（扩展 CONNECT 的目标在 Host 中给出）。
/// 返回 None 表示请求没有 Host 头；解析失败视为非法 Host。
fn get_host(clt_req: &Request<RecvStream>) -> Result<Option<UpstreamAddr>, H2StreamTransferError> {
    match clt_req.headers().get(header::HOST) {
        Some(value) => {
            let host = std::str::from_utf8(value.as_bytes())
                .map_err(|_| H2StreamTransferError::InvalidHostHeader)?;
            let host = UpstreamAddr::from_str(host)
                .map_err(|_| H2StreamTransferError::InvalidHostHeader)?;
            // we didn't set the default port here, as we didn't know the server port
            // 这里不补默认端口：无法预知对端服务监听哪个端口
            Ok(Some(host))
        }
        None => Ok(None),
    }
}

impl<SC> H2ExtendedConnectTask<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 创建任务，protocol 为 stream.rs 中由 :protocol 伪头映射出的升级类型。
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        clt_stream_id: StreamId,
        protocol: HttpUpgradeToken,
    ) -> Self {
        H2ExtendedConnectTask {
            ctx,
            clt_stream_id,
            ups_stream_id: None,
            protocol,
            upstream: None,
            http_notes: HttpConnectTaskNotes::default(),
        }
    }

    /// 向客户端直接回 400 并结束该流（请求不被支持或不合规）。
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

    /// 向客户端回 403：ACL/检测策略明确封锁该协议（如 websocket 被禁）。
    fn reply_forbidden(&mut self, mut clt_send_rsp: SendResponse<Bytes>) {
        if let Ok(rsp) = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .version(Version::HTTP_2)
            .body(())
        {
            let rsp_status = rsp.status().as_u16();
            if clt_send_rsp.send_response(rsp, true).is_ok() {
                self.http_notes.rsp_status = rsp_status;
            }
        }
    }

    /// 运行任务入口：按升级协议分派到对应处理分支，返回即代表本流结束。
    /// Http/Tls 升级与 connect-ip 不支持；websocket 做协议级拦截；
    /// connect-udp 与未知 token 走透传。
    pub(crate) async fn into_running(
        mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        match self.protocol {
            HttpUpgradeToken::Http(_) => {
                self.cancel_and_log(clt_send_rsp, "http upgrade is not supported");
            }
            HttpUpgradeToken::Tls(_, _) => {
                self.cancel_and_log(clt_send_rsp, "tls upgrade is not supported");
            }
            HttpUpgradeToken::Websocket => {
                self.run_extended_websocket(clt_req, clt_send_rsp, h2s)
                    .await;
            }
            HttpUpgradeToken::ConnectUdp => {
                self.run_extended_connect_udp(clt_req, clt_send_rsp, h2s)
                    .await
            }
            HttpUpgradeToken::ConnectIp => {
                self.cancel_and_log(clt_send_rsp, "connect-ip upgrade is not supported");
            }
            _ => self.run_extended_unknown(clt_req, clt_send_rsp, h2s).await,
        }
    }

    /// 拒绝该流（回 400）并记录拒绝原因。
    fn cancel_and_log(&mut self, clt_send_rsp: SendResponse<Bytes>, reason: &str) {
        self.reply_bad_request(clt_send_rsp);
        intercept_log!(self, "{reason}");
    }

    /// 扩展 CONNECT websocket：目的地址取自 Host 头；先做 ACL 封锁检查，
    /// 头部交换成功后把内层升级为 websocket 协议，交给
    /// H2WebsocketInterceptObject 做帧级检测（检测深度加一并记录检测来源）。
    async fn run_extended_websocket(
        mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        // 扩展 CONNECT websocket 的目标主机由 Host 头给出
        let upstream = match get_host(&clt_req) {
            Ok(Some(d)) => {
                self.upstream = Some(d.clone());
                d
            }
            Ok(None) => {
                self.reply_bad_request(clt_send_rsp);
                intercept_log!(self, "no Host header found in websocket request");
                return;
            }
            Err(e) => {
                self.reply_bad_request(clt_send_rsp);
                intercept_log!(self, "invalid request: {e}");
                return;
            }
        };

        // 按目的主机查询 websocket 检测动作，被封锁时直接回 403
        if self
            .ctx
            .websocket_inspect_action(upstream.host())
            .is_block()
        {
            self.reply_forbidden(clt_send_rsp);
            intercept_log!(self, "websocket blocked by inspection policy");
            return;
        }

        // 收集请求头到 ws_notes，供 websocket 审计日志使用
        let mut ws_notes = WebSocketNotes::new(clt_req.uri().clone());
        for (name, value) in clt_req.headers() {
            ws_notes.append_request_header(name, value);
        }
        let mut exchange_head =
            ExchangeHead::new_websocket(&self.ctx, &mut self.http_notes, &mut ws_notes);
        let exchange_head_result = exchange_head.run(clt_req, clt_send_rsp, h2s).await;
        self.ups_stream_id = exchange_head.ups_stream_id.take();
        match exchange_head_result {
            // 握手 2xx 成功：升级完成，进入 websocket 帧检测
            Ok(Some((clt_r, clt_w, ups_r, ups_w))) => {
                intercept_log!(self, "ok");

                self.ctx.increase_inspection_depth();
                StreamInspectLog::new(&self.ctx)
                    .log(InspectSource::H2ExtendedConnect, Protocol::Websocket);
                let websocket_obj = crate::inspect::websocket::H2WebsocketInterceptObject::new(
                    self.ctx, upstream, ws_notes,
                );
                websocket_obj.intercept(clt_r, clt_w, ups_r, ups_w).await;
            }
            Ok(None) => {
                intercept_log!(self, "finished without data");
            }
            Err(e) => {
                intercept_log!(self, "head transfer error: {e}");
            }
        }
    }

    /// CONNECT-UDP（RFC 9297 风格）：目的地址由 :authority 中的 host:port 解析，
    /// 其余流程与未知协议一致——代理不理解其 datagram 帧，只做头部交换+透传。
    async fn run_extended_connect_udp(
        mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        match clt_req.uri().get_connect_udp_upstream() {
            Ok(d) => self.upstream = Some(d),
            Err(e) => {
                self.reply_bad_request(clt_send_rsp);
                intercept_log!(self, "invalid upstream addr for connect-udp request: {e}");
                return;
            }
        }

        self.run_extended_unknown(clt_req, clt_send_rsp, h2s).await
    }

    /// 未知/透传类扩展 CONNECT 的通用处理：完成头部交换后，把四条半流包装成
    /// 字节流做检测式透明中继；协议无法识别时交由策略决定是否禁止。
    async fn run_extended_unknown(
        mut self,
        clt_req: Request<RecvStream>,
        clt_send_rsp: SendResponse<Bytes>,
        h2s: SendRequest<Bytes>,
    ) {
        let mut exchange_head = ExchangeHead::new(&self.ctx, &mut self.http_notes);
        let exchange_head_result = exchange_head.run(clt_req, clt_send_rsp, h2s).await;
        self.ups_stream_id = exchange_head.ups_stream_id.take();
        match exchange_head_result {
            Ok(Some((clt_r, clt_w, ups_r, ups_w))) => {
                intercept_log!(self, "ok");

                self.ctx.increase_inspection_depth();
                StreamInspectLog::new(&self.ctx)
                    .log(InspectSource::H2ExtendedConnect, Protocol::Unknown);

                // do transparent for other protocols ?
                let clt_r = H2StreamReader::new(clt_r);
                let clt_w = H2StreamWriter::new(clt_w);
                let ups_r = H2StreamReader::new(ups_r);
                let ups_w = H2StreamWriter::new(ups_w);

                // Just treat it as unknown. Unknown protocol should be forbidden if needed.
                // 按未知协议处理：仍经过内层检测，若策略要求可在此被禁止
                if let Err(e) = self
                    .ctx
                    .transit_inspect_unknown(clt_r, clt_w, ups_r, ups_w)
                    .await
                {
                    intercept_log!(self, "stream transfer error: {e}");
                } else {
                    intercept_log!(self, "finished");
                }
            }
            Ok(None) => {
                intercept_log!(self, "finished without data");
            }
            Err(e) => {
                intercept_log!(self, "head transfer error: {e}");
            }
        }
    }
}
