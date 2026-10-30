/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! RESPMOD h2 的 preview（预览）上报路径，对应 ICAP 的
//! "Preview + 100-continue" 时序（RFC 3507 第 4.5 节）。
//!
//! 与 h1 版时序相同，但预览数据来自 h2 `RecvStream` 数据帧而非原始
//! TCP 流；后续续传时 h2 body 需按 chunked 重编码写入 ICAP，其中已缓存
//! 的预览余量（`take_left`）要先作为第一个 chunk 补发。
//!
//! 时序概要：
//! 1. `recv_initial` 从 h2 上游读取首段数据（带超时）；
//! 2. 若读到了结尾（end_of_data）-> 走 `xfer_small_body` 一次性上报；
//!    若一个字节都没等到（preview_size()==0，上游太慢）-> 退化为
//!    `xfer_without_preview` 全量双向流上报；
//! 3. 否则发送带 `Preview: n` 偏移头的 ICAP 请求（头 + 预览体），等响应：
//!    - 100 Continue：ICAP 收完预览后要求继续，进入双向流续传剩余
//!      chunked body 并等待最终 200 响应；
//!    - 204：不改写，把已缓存的预览数据 + 剩余 h2 body 原样发给客户端；
//!    - 206：本实现未支持（ICAP 提前的部分改写，NotImplemented）；
//!    - 其它 2xx：ICAP 提前给出完整改写结果，停止续传直接进入收尾；
//!    - 非 2xx：报错。
//! 注意：本路径故意不发送 `Allow: 204, 206`（见 build_preview_request），
//! 避免在已发出 100-continue 之后又收到 204/206 这种矛盾应答。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use h2::RecvStream;
use http::{Request, Response};
use tokio::io::AsyncWriteExt;

use g3_h2::{H2PreviewData, H2StreamToChunkedTransfer, RequestExt, ResponseExt};
use g3_io_ext::{IdleCheck, LimitedWriteExt};

use super::{
    BidirectionalRecvHttpResponse, BidirectionalRecvIcapResponse, H2RespmodAdaptationError,
    H2ResponseAdapter, H2SendResponseToClient, RespmodAdaptationEndState,
    RespmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::respmod::IcapRespmodResponsePayload;
use crate::respmod::response::RespmodResponse;

impl<I: IdleCheck> H2ResponseAdapter<I> {
    /// 构造带 `Preview: n` 的 ICAP 请求头：偏移布局与全量上报一致
    /// （req-hdr=0、res-hdr、res-body 依次为降级头长度），
    /// `Preview` 值 = 实际随本请求发送的预览 body 字节数。
    fn build_preview_request(
        &self,
        http_req_hdr_len: usize,
        http_rsp_hdr_len: usize,
        preview_size: usize,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        // do not send `Allow: 204, 206` as we don't want to accept 204/206 after 100-continue
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, res-hdr={http_req_hdr_len}, res-body={}\r\nPreview: {preview_size}\r\n",
            http_req_hdr_len + http_rsp_hdr_len,
        );
        header.put_slice(b"\r\n");
        header
    }

    /// preview 流程总控：见模块头的时序说明。返回值各分支最终收敛到
    /// recv_response / bidirectional 中的公共收尾处理。
    pub(super) async fn xfer_with_preview<CW>(
        mut self,
        state: &mut RespmodAdaptationRunState,
        http_request: &Request<()>,
        http_response: Response<()>,
        mut ups_body: RecvStream,
        clt_send_response: &mut CW,
        max_preview_size: usize,
    ) -> Result<RespmodAdaptationEndState, H2RespmodAdaptationError>
    where
        CW: H2SendResponseToClient,
    {
        // 步骤 1：限时读取首段 h2 数据作为预览候选
        let mut preview_data = H2PreviewData::new(max_preview_size);
        preview_data
            .recv_initial(
                &mut ups_body,
                self.icap_client.config.preview_data_read_timeout,
            )
            .await?;

        if preview_data.end_of_data() {
            // 步骤 2a：上游 body 很小已读完（收到结束帧），聚合为一次性上报
            return self
                .xfer_small_body(
                    state,
                    http_request,
                    http_response,
                    preview_data,
                    ups_body,
                    clt_send_response,
                )
                .await;
        } else if preview_data.preview_size() == 0 {
            // 步骤 2b：超时也没等到任何数据，preview 无意义，退化为全量双向流
            return self
                .xfer_without_preview(
                    state,
                    http_request,
                    http_response,
                    ups_body,
                    clt_send_response,
                )
                .await;
        }

        // 步骤 3：发送 ICAP 头 + 降级序列化的请求/响应头 + 预览 body
        //（预览段也按 chunked 编码写入），flush 后等待 ICAP 表态
        let http_req_header = http_request.serialize_for_adapter();
        let http_rsp_header = http_response.serialize_for_adapter();
        let icap_header = self.build_preview_request(
            http_req_header.len(),
            http_rsp_header.len(),
            preview_data.preview_size(),
        );

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_req_header),
                IoSlice::new(&http_rsp_header),
            ])
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;
        preview_data
            .icap_write_preview_data(icap_w)
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H2RespmodAdaptationError::IcapServerWriteFailed)?;

        let rsp = RespmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
        )
        .await?;

        match rsp.code {
            // 100 Continue：ICAP 收下预览并要求继续，把剩余 h2 body
            //（连同已缓存未发出的预览余量 left_data，先作为 chunk 补发）
            // 以 chunked 双向流方式继续传给 ICAP，并等待它的最终响应
            100 => {
                let mut body_transfer = if let Some(left_data) = preview_data.take_left() {
                    // 预览缓存里还有没写出去的数据：用 with_chunk 先发出
                    H2StreamToChunkedTransfer::with_chunk(
                        &mut ups_body,
                        &mut self.icap_connection.writer,
                        self.copy_config.yield_size(),
                        left_data,
                    )
                } else {
                    H2StreamToChunkedTransfer::new(
                        &mut ups_body,
                        &mut self.icap_connection.writer,
                        self.copy_config.yield_size(),
                    )
                };

                let bidirectional_transfer = BidirectionalRecvIcapResponse {
                    icap_client: &self.icap_client,
                    icap_reader: &mut self.icap_connection.reader,
                    idle_checker: &self.idle_checker,
                };
                // 续传与接收最终响应并发进行；最终响应同样分三种负载形态收尾
                let rsp = bidirectional_transfer
                    .transfer_and_recv(&mut body_transfer)
                    .await?;
                if body_transfer.finished() {
                    state.mark_ups_recv_all();
                }

                match rsp.payload {
                    IcapRespmodResponsePayload::NoPayload => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                        }
                        self.icap_connection.mark_reader_finished();
                        self.handle_icap_ok_without_payload(rsp).await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                        }
                        self.handle_icap_http_response_without_body(
                            state,
                            rsp,
                            header_size,
                            http_response,
                            clt_send_response,
                        )
                        .await
                    }
                    IcapRespmodResponsePayload::HttpResponseWithBody(header_size) => {
                        if body_transfer.finished() {
                            self.icap_connection.mark_writer_finished();
                            self.handle_icap_http_response_with_body_after_transfer(
                                state,
                                rsp,
                                header_size,
                                http_response,
                                clt_send_response,
                            )
                            .await
                        } else {
                            // 上游 body 未传完而 ICAP 已回改写响应：双向流
                            // 并发续传 + 向客户端流式转发改写结果
                            let mut bidirectional_transfer = BidirectionalRecvHttpResponse {
                                icap_reader: &mut self.icap_connection.reader,
                                copy_config: self.copy_config,
                                http_body_line_max_size: self.http_body_line_max_size,
                                http_trailer_max_size: self.http_trailer_max_size,
                                idle_checker: &self.idle_checker,
                                http_header_size: header_size,
                                icap_read_finished: false,
                            };
                            let r = bidirectional_transfer
                                .transfer(
                                    state,
                                    &mut body_transfer,
                                    http_response,
                                    clt_send_response,
                                )
                                .await?;
                            let icap_read_finished = bidirectional_transfer.icap_read_finished;
                            if body_transfer.finished() {
                                state.mark_ups_recv_all();
                                self.icap_connection.mark_writer_finished();
                                if icap_read_finished {
                                    self.icap_connection.mark_reader_finished();
                                    if rsp.keep_alive {
                                        self.icap_client.save_connection(self.icap_connection);
                                    }
                                }
                            }
                            Ok(r)
                        }
                    }
                }
            }
            // 204 No Modification：ICAP 决定不改写（在收到 100-continue 前
            // 就返回）。停止向 ICAP 续传，把已缓存的预览数据 + 剩余 h2
            // body 原样直通发给客户端
            204 => {
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                }
                self.handle_original_http_response_with_body(
                    state,
                    rsp,
                    http_response,
                    preview_data,
                    ups_body,
                    clt_send_response,
                )
                .await
            }
            // 206：ICAP 在预览阶段就返回部分改写结果，本实现暂不支持
            206 => Err(H2RespmodAdaptationError::NotImplemented("ICAP-REQMOD-206")),
            // 其它 2xx：ICAP 提前给出完整改写响应，不再续传剩余 body，
            // 直接进入"读改写响应并发给客户端"的收尾流程
            n if (200..300).contains(&n) => {
                // FIXME we should stop send the pending HTTP body to ICAP server?
                self.icap_connection.mark_writer_finished();
                match rsp.payload {
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
                }
            }
            // 非 2xx：ICAP 对 preview 请求返回错误应答，向上报错；
            // 干净的空负载连接可保活回池
            _ => {
                self.icap_connection.mark_writer_finished();
                if rsp.payload == IcapRespmodResponsePayload::NoPayload {
                    self.icap_connection.mark_reader_finished();
                    if rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }
                Err(H2RespmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponseForPreview,
                    rsp.code,
                    rsp.reason,
                ))
            }
        }
    }
}
