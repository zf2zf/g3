/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 全量上报 body 的 REQMOD 分支（不使用 Preview 时，以及小 body 一次成型）。
//!
//! 处于状态机的"有 body 但无 preview"分支（mod.rs 的 xfer() 分派进来），
//! 以及 preview 读完后发现 body 很小的退化分支：
//! - `xfer_without_preview`：头先写，body 由 H1BodyToChunkedTransfer 流式转成
//!   ICAP 的 chunked 封装，同时用 bidirectional.rs 并行读 ICAP 响应——
//!   所以这一路上 ICAP 的响应码不会是 204/206（那种语义只属于 preview 分支：
//!   没拿到完整 body 就说"放行"），出现即视为非法响应；
//! - `xfer_small_body` / `xfer_small_body_chunked`：body 已完整读在内存里，
//!   一次 vectored 写全部发完，之后按普通一问一答处理响应。
//!
//! 关于 chunked 重编码：客户端可能是 Content-Length、chunked 或"读到结束"，
//! 而 ICAP 封装的 body 统一写成 chunked（以 `0\r\n\r\n` 结束）。因此
//! 无论客户端用哪种形式，这里都先解码成裸数据再重新分块，trailer 单独搬运。

use std::io::{IoSlice, Write};

use bytes::BufMut;
use tokio::io::{AsyncBufRead, AsyncWriteExt};

use g3_http::{H1BodyToChunkedTransfer, HttpBodyReader, HttpBodyType};
use g3_io_ext::{IdleCheck, LimitedWriteExt, StreamCopy, StreamCopyError};

use super::{
    BidirectionalRecvHttpRequest, BidirectionalRecvIcapResponse, H1ReqmodAdaptationError,
    HttpRequestAdapter, HttpRequestForAdaptation, HttpRequestUpstreamWriter,
    ReqmodAdaptationEndState, ReqmodAdaptationRunState,
};
use crate::reason::IcapErrorReason;
use crate::reqmod::IcapReqmodResponsePayload;
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> HttpRequestAdapter<I> {
    /// 组装"头 + 完整 body"上报的 ICAP 请求头。
    ///
    /// `req-body=<len>` 的 len 是封装内容中 body 的起点偏移，等于 HTTP 头字节数
    /// （req-hdr 从 0 起）。不带 `Preview:`，表示本次就是完整上报。
    fn build_forward_all_request(&self, http_header_len: usize) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 128);
        header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut header);
        let _ = write!(
            header,
            "Encapsulated: req-hdr=0, req-body={http_header_len}\r\n",
        );
        header.put_slice(b"\r\n");
        header
    }

    /// 小 body（已完整读入内存）一次性上报：头 + HTTP 头 + 单个 chunk + 结束块。
    ///
    /// 一次 `write_all_vectored` 把所有片段拼装发出，避免多轮小包；
    /// `{:x}` 是 chunked 要求的十六进制 chunk 长度，`0\r\n\r\n` 是结束块
    /// （无 trailer，因为客户端的 trailer 在非 chunked 场景不存在）。
    /// 发完即 `mark_writer_finished()`，之后进入同步等响应路径。
    pub(super) async fn xfer_small_body<H, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        clt_body: Vec<u8>,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_forward_all_request(http_header.len());

        let chunk_start = format!("{:x}\r\n", clt_body.len());

        let icap_w = &mut self.icap_connection.writer;
        icap_w
            .write_all_vectored([
                IoSlice::new(&icap_header),
                IoSlice::new(&http_header),
                IoSlice::new(chunk_start.as_bytes()),
                IoSlice::new(&clt_body),
                IoSlice::new(b"\r\n0\r\n\r\n"),
            ])
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        icap_w
            .flush()
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        self.icap_connection.mark_writer_finished();

        self.handle_small_body_response(state, http_request, ups_writer)
            .await
    }

    /// 客户端原本是 chunked 且已读完的小 body：数据一次写完，trailer 另行搬运。
    ///
    /// 结束块的写法有讲究：空 body 时只写 `0\r\n`（长度 0 的结束 chunk），
    /// 否则写 `<len>\r\n<data>\r\n0\r\n`；两种情况都不再写结束空行，
    /// 因为紧接着的 trailer（可能为空）会补上最后的 `\r\n`。
    pub(super) async fn xfer_small_body_chunked<H, CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        clt_body: Vec<u8>,
        mut trailer_reader: HttpBodyReader<'_, CR>,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        CR: AsyncBufRead + Unpin,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_forward_all_request(http_header.len());

        if clt_body.is_empty() {
            self.icap_connection
                .writer
                .write_all_vectored([
                    IoSlice::new(&icap_header),
                    IoSlice::new(&http_header),
                    IoSlice::new(b"0\r\n"),
                ])
                .await
                .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        } else {
            let chunk_start = format!("{:x}\r\n", clt_body.len());
            self.icap_connection
                .writer
                .write_all_vectored([
                    IoSlice::new(&icap_header),
                    IoSlice::new(&http_header),
                    IoSlice::new(chunk_start.as_bytes()),
                    IoSlice::new(&clt_body),
                    IoSlice::new(b"\r\n0\r\n"),
                ])
                .await
                .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;
        }

        self.recv_send_trailer(&mut trailer_reader).await?;

        state.clt_read_finished = true;
        self.icap_connection.mark_writer_finished();

        self.handle_small_body_response(state, http_request, ups_writer)
            .await
    }

    /// 把客户端 chunked 的 trailer 原样搬到 ICAP 封装的 chunked 流尾部。
    ///
    /// trailer 属于 HTTP 语义的一部分（如 `X-Checksum:`），ICAP 侧改写可能依赖它，
    /// 所以不能丢；拷贝同样受 idle_checker 保护，避免客户端迟迟不发 trailer 挂死。
    async fn recv_send_trailer<CR>(
        &mut self,
        trailer_reader: &mut HttpBodyReader<'_, CR>,
    ) -> Result<(), H1ReqmodAdaptationError>
    where
        CR: AsyncBufRead + Unpin,
    {
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0;

        let mut trailer_transfer = StreamCopy::new(
            trailer_reader,
            &mut self.icap_connection.writer,
            &self.copy_config,
        );
        loop {
            tokio::select! {
                biased;

                r = &mut trailer_transfer => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::HttpClientReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if trailer_transfer.is_idle() {
                        idle_count += n;

                        let quit = self.idle_checker.check_quit(idle_count);
                        if quit {
                            return if trailer_transfer.no_cached_data() {
                                Err(H1ReqmodAdaptationError::HttpClientReadIdle)
                            } else {
                                Err(H1ReqmodAdaptationError::IcapServerWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        trailer_transfer.reset_active();
                    }

                    if let Some(reason) = self.idle_checker.check_force_quit() {
                        return Err(H1ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }

    /// 小 body 一次上报完成后，读取并处理 ICAP 响应。
    ///
    /// 因为 body 已全量发给 ICAP，204/206 都没有意义（204 的"原样放行"我们本可
    /// 预先知道，206 的"部分改写"我们已无法回退），故只接受 200 系列。
    pub(super) async fn handle_small_body_response<H, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let mut rsp = ReqmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await?;
        let shared_headers = rsp.take_shared_headers();
        if !shared_headers.is_empty() {
            state.respond_shared_headers = Some(shared_headers);
        }

        match rsp.code {
            204 | 206 => {
                return Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }
        match rsp.payload {
            IcapReqmodResponsePayload::NoPayload => {
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                self.handle_icap_http_request_without_body(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_writer,
                )
                .await
            }
            IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                self.handle_icap_http_request_with_body_after_transfer(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_writer,
                )
                .await
            }
            IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => self
                .handle_icap_http_response_without_body(rsp, header_size)
                .await
                .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None)),
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => self
                .handle_icap_http_response_with_body(rsp, header_size)
                .await
                .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body))),
        }
    }

    /// 无 preview 的全量流式上报：ICAP 头 + HTTP 头先写，body 边读边转成 chunked。
    ///
    /// 关键点是"不等 body 传完就开始读 ICAP 响应"（bidirectional 流水线）：
    /// 大 body 场景下 ICAP 往往在收到足够数据后就先回 200 改写结果，
    /// 若串行等待会让两侧缓冲区互相阻塞。
    /// 若客户端 body 一直不结束而 ICAP 已给出带 body 的改写请求，
    /// 则切到 BidirectionalRecvHttpRequest 同时搬运两路数据。
    pub(super) async fn xfer_without_preview<H, CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        http_request: &H,
        clt_body_type: HttpBodyType,
        clt_body_io: &mut CR,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        CR: AsyncBufRead + Unpin,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_header = http_request.serialize_for_adapter();
        let icap_header = self.build_forward_all_request(http_header.len());

        let icap_w = &mut self.icap_connection.writer;
        // 头先行：此时还不知道 body 长度，所以不写结束块，交给 body_transfer 续写
        icap_w
            .write_all_vectored([IoSlice::new(&icap_header), IoSlice::new(&http_header)])
            .await
            .map_err(H1ReqmodAdaptationError::IcapServerWriteFailed)?;

        let mut body_transfer = H1BodyToChunkedTransfer::new(
            clt_body_io,
            &mut self.icap_connection.writer,
            clt_body_type,
            self.http_body_line_max_size,
            self.copy_config,
        );
        let bidirectional_transfer = BidirectionalRecvIcapResponse {
            icap_client: &self.icap_client,
            icap_reader: &mut self.icap_connection.reader,
            idle_checker: &self.idle_checker,
        };
        let mut rsp = bidirectional_transfer
            .transfer_and_recv(&mut body_transfer)
            .await?;
        let shared_headers = rsp.take_shared_headers();
        if !shared_headers.is_empty() {
            state.respond_shared_headers = Some(shared_headers);
        }
        if body_transfer.finished() {
            state.clt_read_finished = true;
        }

        match rsp.code {
            204 | 206 => {
                return Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::InvalidResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
            n if (200..300).contains(&n) => {}
            _ => {
                return Err(H1ReqmodAdaptationError::IcapServerErrorResponse(
                    IcapErrorReason::UnknownResponse,
                    rsp.code,
                    rsp.reason,
                ));
            }
        }
        match rsp.payload {
            IcapReqmodResponsePayload::NoPayload => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.icap_connection.mark_reader_finished();
                self.handle_icap_ok_without_payload(rsp).await
            }
            IcapReqmodResponsePayload::HttpRequestWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_request_without_body(
                    state,
                    rsp,
                    header_size,
                    http_request,
                    ups_writer,
                )
                .await
            }
            IcapReqmodResponsePayload::HttpRequestWithBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                    self.handle_icap_http_request_with_body_after_transfer(
                        state,
                        rsp,
                        header_size,
                        http_request,
                        ups_writer,
                    )
                    .await
                } else {
                    let mut bidirectional_transfer = BidirectionalRecvHttpRequest {
                        http_body_line_max_size: self.http_body_line_max_size,
                        http_req_add_no_via_header: self.http_req_add_no_via_header,
                        copy_config: self.copy_config,
                        idle_checker: &self.idle_checker,
                        http_header_size: header_size,
                        icap_read_finished: false,
                    };
                    let r = bidirectional_transfer
                        .transfer(
                            state,
                            &mut body_transfer,
                            http_request,
                            &mut self.icap_connection.reader,
                            ups_writer,
                        )
                        .await?;
                    if body_transfer.finished() {
                        state.clt_read_finished = true;
                        self.icap_connection.mark_writer_finished();
                        if bidirectional_transfer.icap_read_finished {
                            self.icap_connection.mark_reader_finished();
                            if rsp.keep_alive {
                                self.icap_client.save_connection(self.icap_connection);
                            }
                        }
                    }
                    Ok(r)
                }
            }
            IcapReqmodResponsePayload::HttpResponseWithoutBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_response_without_body(rsp, header_size)
                    .await
                    .map(|rsp| ReqmodAdaptationEndState::HttpErrResponse(rsp, None))
            }
            IcapReqmodResponsePayload::HttpResponseWithBody(header_size) => {
                if body_transfer.finished() {
                    self.icap_connection.mark_writer_finished();
                }
                self.handle_icap_http_response_with_body(rsp, header_size)
                    .await
                    .map(|(rsp, body)| ReqmodAdaptationEndState::HttpErrResponse(rsp, Some(body)))
            }
        }
    }
}
