/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 无 body 分支：只把"请求头 + 响应头"上报给 ICAP 服务器。
//!
//! 对应 RESPMOD 状态机中最短的一条路径：当响应按方法/状态码不允许带 body 时
//! （HEAD、1xx、204、304 等，即 `HttpResponseForAdaptation::body_type()` 返回
//! `None`），[`crate::respmod::h1::HttpResponseAdapter::xfer`] 会调进来。
//! 由于没有 body，整条上报可以一次性写完并等 ICAP 回包，无需 preview，也无需
//! 双向流水线——这是与 `reqmod::h1::forward_header`（无 body 请求）对称的分支。
//!
//! ICAP 报文体布局（偏移量都相对于 ICAP 报文首字节，即 req-hdr 起点为 0）：
//! ```text
//! [0, http_req_hdr_len)                    封装的 HTTP 请求头
//! [http_req_hdr_len, +http_rsp_hdr_len)    封装的 HTTP 响应头
//! ↑ 该处即 null-body 偏移（本分支不真的发 body，仅用于声明位置）
//! ```
//! 因为确实没有 body，这里可以安全声明 `Allow: 204`（前提是服务端 OPTIONS 通告
//! 支持）：ICAP 用 204 表示"不改写"，客户端就能直接收到上游原响应。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::AsyncWriteExt;

use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    H1RespmodAdaptationError, HttpResponseAdapter, HttpResponseClientWriter,
    HttpResponseForAdaptation, RespmodAdaptationEndState, RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::h1::HttpRequestForAdaptation;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> HttpResponseAdapter<I> {
    /// 拼装"只报头"分支的 ICAP 请求头块（请求行 + 前缀 + 扩展头 + Allow/Encapsulated + 空行）。
    ///
    /// `Encapsulated: req-hdr=0, res-hdr=<请求头长度>, null-body=<请求头长度+响应头长度>`：
    /// 响应头紧跟在请求头之后，故 res-hdr 偏移就是请求头字节数；null-body 偏移指向
    /// 响应头之后的位置（本分支不写任何 body）。
    fn build_header_only_request(
        &self,
        http_req_hdr_len: usize,
        http_rsp_hdr_len: usize,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        // 无 body 时才能接受 204：ICAP 不必回任何封装内容即可表达"放行"
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

    /// 执行"无 body"上报并处理 ICAP 回包。
    ///
    /// 时序：序列化两份头 → 一次性 vectored 写出 ICAP 请求 → flush 并标记写端结束
    /// → 同步等待 ICAP 响应 → 按状态码分派：
    /// - 204：上游原响应（只有头）直接发给客户端，结果 `OriginalTransferred`；
    /// - 2xx：按 `Encapsulated` 载荷决定是"无载荷异常"、"改写后的无 body 响应"
    ///   还是"改写后带 body 的响应"（后者少见但合法，例如 ICAP 给 HEAD 请求造出内容）；
    /// - 其他：返回错误，并在可复用时把连接归还连接池。
    pub(super) async fn xfer_without_body<R, H, CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &R,
        http_response: &H,
        clt_writer: &mut CW,
    ) -> Result<RespmodAdaptationEndState<H>, H1RespmodAdaptationError>
    where
        R: HttpRequestForAdaptation,
        H: HttpResponseForAdaptation,
        CW: HttpResponseClientWriter<H> + Unpin,
    {
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        // ICAP 的 Encapsulated 偏移必须在拼装头之前就确定，故先序列化两份头
        let icap_header =
            self.build_header_only_request(http_req_header.len(), http_rsp_header.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
            ])
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1RespmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            204 => {
                // 204 = ICAP 明确不改写；无载荷时读端也已到边界
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_response_without_body(
                    state,
                    rsp,
                    http_response,
                    clt_writer,
                )
                .await
            }
            n if (200..300).contains(&n) => match rsp.payload {
                IcapRespmodResponsePayload::NoPayload => {
                    // 2xx 却没有任何 Encapsulated 载荷，属于协议错误（见 recv_response.rs）
                    self.icap_connection.mark_reader_finished();
                    self.handle_icap_ok_without_payload(rsp).await
                }
                IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                    // header_size：ICAP 回包中封装响应头的字节数，body 偏移 = header_size
                    self.handle_icap_http_response_without_body(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_writer,
                    )
                    .await
                }
                IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                    // ICAP 给无 body 的响应造出了 body：需按 chunked 解码后转发给客户端
                    self.handle_icap_http_response_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_response,
                        clt_writer,
                    )
                    .await
                }
            },
            _ => {
                // 非 2xx/204：视为 ICAP 错误响应；只有确认读到了报文边界才能复用连接
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H1RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
