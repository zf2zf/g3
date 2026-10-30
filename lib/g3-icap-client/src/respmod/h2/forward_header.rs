/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2：无 body 响应的纯头部上报路径。
//!
//! 当上游 h2 响应没有 body（`RecvStream::is_end_stream()` 为真，如 204/304
//! 或空响应）时走这里：只把降级序列化的 HTTP/1.1 请求头 + 响应头封装上报，
//! `Encapsulated:` 用 `null-body=` 声明 body 长度为零，与 h1 版语义一致；
//! 并允许 ICAP 以 204 应答表示"不改写、原样放行"。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use http::{Request, Response};
use tokio::io::AsyncWriteExt;

use g3_h2::{RequestExt, ResponseExt};
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    H2RespmodAdaptationError, H2ResponseAdapter, H2SendResponseToClient, RespmodAdaptationEndState,
    RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> H2ResponseAdapter<I> {
    /// 构造"仅上报头、无 body"的 ICAP 请求头。
    ///
    /// 偏移布局与 `build_forward_all_request` 相同（req-hdr=0 起算），
    /// 但用 `null-body=<请求头+响应头长度>` 声明封装 body 为空；若服务
    /// 允许 204 则加 `Allow: 204`，表示可接受"不改写"应答。
    fn build_header_only_request(
        &self,
        http_req_hdr_len: usize,
        http_rsp_hdr_len: usize,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        if self.icap_options.support_204 {
            header.put_slice(b"Allow: 204\r\n");
        }
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, res-hdr={http_req_hdr_len}, null-body={}\r\n",
            http_req_hdr_len + http_rsp_hdr_len
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 无 body 响应的完整往返：发送降级头 -> 等 ICAP 应答 -> 按
    /// 204 / 2xx / 其它分别处理（原样放行、应用改写、或报错）。
    pub(super) async fn xfer_without_body<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &Request<()>,
        http_response: Response<()>,
        clt_send_response: &mut CW,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        // 降级序列化 h2 请求/响应头为 HTTP/1.1 文本，并按其长度计算偏移
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header =
            self.build_header_only_request(http_req_header.len(), http_rsp_header.len());

        // 聚合发送后 flush；无 body，请求到此结束
        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
            ])
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            // 204 No Modification：ICAP 不改写，把原始无 body 响应直接发给客户端
            204 => {
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_response_without_body(
                    state,
                    rsp,
                    http_response,
                    clt_send_response,
                )
                .await
            }
            // 2xx：按 ICAP 封装负载的三种形态分别转回 h2 发给客户端
            n if (200..300).contains(&n) => match rsp.payload {
                IcapRespmodResponsePayload::NoPayload => {
                    self.icap_connection.mark_reader_finished();
                    self.handle_icap_ok_without_payload(rsp).await
                }
                IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                    self.handle_icap_http_response_without_body(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_send_response,
                    )
                    .await
                }
                // 声明了 null-body 却收到带改写 body 的响应：读它（少见但合法）
                IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                    self.handle_icap_http_response_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_send_response,
                    )
                    .await
                }
            },
            // 非 2xx（错误应答）：若无封装负载可尝试保活回池，然后向上报错
            _ => {
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive && rsp.payload == IcapRespmodResponsePayload::NoPayload {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
