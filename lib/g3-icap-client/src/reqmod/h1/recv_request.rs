/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 接收 ICAP 返回的"改写后 HTTP 请求"并转发给真实上游。
//!
//! 这是 REQMOD 状态机中 `200 + req-hdr/req-body` 载荷的落地实现，被
//! preview.rs / forward_body.rs / forward_header.rs 各分支调用。要点：
//! - ICAP 封装的改写请求 body 一律按 chunked 传输编码组织，所以读侧固定
//!   用 chunked 解码器；若改写头里带 Content-Length，则解码长度必须与之相等
//!   （不一致说明 ICAP 服务实现有问题，直接判为非法 body）。
//! - `null-body` / 无 body 的改写结果只需把头写给上游（adapt_without_body）。
//! - "已把 body 全量交给 ICAP"之后的分支才能用本文件的同步函数；
//!   否则（body 还在传）要用 bidirectional.rs 的双向流版本。
//! - 所有拷贝循环都有 idle_checker 保护：卡在读 ICAP 还是写上游由
//!   `no_cached_data()` 区分。

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use g3_http::{HttpBodyDecodeReader, HttpBodyReader};
use g3_io_ext::{IdleCheck, StreamCopy, StreamCopyError};

use super::{
    H1ReqmodAdaptationError, HttpAdaptedRequest, HttpRequestAdapter, HttpRequestForAdaptation,
    HttpRequestUpstreamWriter, ReqmodAdaptationEndState, ReqmodAdaptationMidState,
    ReqmodAdaptationRunState,
};
use crate::reqmod::response::ReqmodResponse;

impl<I: IdleCheck> HttpRequestAdapter<I> {
    /// ICAP 放行（204）且原请求无 body：把头写完即结束，不做任何修改。
    ///
    /// 此处不改动请求内容，因此状态里的"全部发送"与"头发送"同时置位。
    pub(super) async fn handle_original_http_request_without_body<H, UW>(
        self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_request: &H,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        ups_writer
            .send_request_header(http_request)
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        // flush 确保头立刻上线：上游可能在等第一个字节才回响应
        ups_writer
            .flush()
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        state.mark_ups_send_header();
        state.mark_ups_send_no_body();
        Ok(ReqmodAdaptationEndState::OriginalTransferred)
    }

    /// 只"接收"无 body 的改写请求，不写上游，返回中间态（CONNECT 场景用）。
    ///
    /// CONNECT 的后续隧道由调用方建立，所以这里只重建请求对象并归还 ICAP 连接。
    pub(super) async fn recv_icap_http_request_without_body<H>(
        mut self,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: &H,
    ) -> Result<ReqmodAdaptationMidState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
    {
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        let final_req = orig_http_request.adapt_without_body(http_req);

        Ok(ReqmodAdaptationMidState::AdaptedRequest(final_req))
    }

    /// 接收无 body 的改写请求并直接发给上游（终态：AdaptedTransferred）。
    ///
    /// `http_header_size` 来自 ICAP 响应的 Encapsulated 偏移，界定封装内容的边界，
    /// 解析完头之后连接即读干净，可以按 keep_alive 回池。
    pub(super) async fn handle_icap_http_request_without_body<H, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: &H,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        self.icap_connection.mark_reader_finished();
        if icap_rsp.keep_alive {
            self.icap_client.save_connection(self.icap_connection);
        }

        let final_req = orig_http_request.adapt_without_body(http_req);
        ups_writer
            .send_request_header(&final_req)
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        ups_writer
            .flush()
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        state.mark_ups_send_header();
        state.mark_ups_send_no_body();

        Ok(ReqmodAdaptationEndState::AdaptedTransferred(final_req))
    }

    /// 接收带 body 的改写请求并转发上游（前提：客户端 body 已全部交给 ICAP）。
    ///
    /// 顺序：解析改写请求头 → 用 adapt_with_body 重建请求 → 先把头写给上游
    /// （头必须早于 body）→ 再流式搬运 chunked body。
    /// Content-Length 存在时走"解码 + 校验"路径：`copied != expected` 说明
    /// ICAP 给的长度与实际数据不符，必须报错；同时尝试读 trailer，读干净才
    /// 允许连接回池。无 Content-Length 时只能信任 chunked 的结束块边界。
    pub(super) async fn handle_icap_http_request_with_body_after_transfer<H, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        icap_rsp: ReqmodResponse,
        http_header_size: usize,
        orig_http_request: &H,
        ups_writer: &mut UW,
    ) -> Result<ReqmodAdaptationEndState<H>, H1ReqmodAdaptationError>
    where
        H: HttpRequestForAdaptation,
        UW: HttpRequestUpstreamWriter<H> + Unpin,
    {
        let http_req = HttpAdaptedRequest::parse(
            &mut self.icap_connection.reader,
            http_header_size,
            self.http_req_add_no_via_header,
        )
        .await?;
        let body_content_length = http_req.content_length;

        let final_req = orig_http_request.adapt_with_body(http_req);
        ups_writer
            .send_request_header(&final_req)
            .await
            .map_err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed)?;
        state.mark_ups_send_header();

        match body_content_length {
            // 声明长度为 0 却仍带 req-body 偏移：自相矛盾，按非法响应处理
            Some(0) => Err(H1ReqmodAdaptationError::InvalidHttpBodyFromIcapServer(
                anyhow!("Content-Length is 0 but the ICAP server response contains http-body"),
            )),
            Some(expected) => {
                let mut body_reader = HttpBodyDecodeReader::new_chunked(
                    &mut self.icap_connection.reader,
                    self.http_body_line_max_size,
                );
                let mut body_copy =
                    StreamCopy::new(&mut body_reader, ups_writer, &self.copy_config);
                Self::send_request_body(&self.idle_checker, &mut body_copy).await?;

                state.mark_ups_send_all();
                let copied = body_copy.copied_size();

                // 读完结束块之后的 trailer（上限 128 字节，仅防御畸形数据）；
                // 读失败意味着连接上还有残留，本连接不能归还连接池
                if body_reader.trailer(128).await.is_ok() {
                    self.icap_connection.mark_reader_finished();
                    if icap_rsp.keep_alive {
                        self.icap_client.save_connection(self.icap_connection);
                    }
                }

                // chunked 解码出的长度必须与改写请求头里的 Content-Length 一致，
                // 否则上游会按错误的长度解析（截断或超读）
                if copied != expected {
                    return Err(H1ReqmodAdaptationError::InvalidHttpBodyFromIcapServer(
                        anyhow!("Content-Length is {expected} but decoded length is {copied}"),
                    ));
                }
                Ok(ReqmodAdaptationEndState::AdaptedTransferred(final_req))
            }
            None => {
                // 无 Content-Length：完全以 chunked 结束块为边界，读到即结束
                let mut body_reader = HttpBodyReader::new_chunked(
                    &mut self.icap_connection.reader,
                    self.http_body_line_max_size,
                );
                let mut body_copy =
                    StreamCopy::new(&mut body_reader, ups_writer, &self.copy_config);
                Self::send_request_body(&self.idle_checker, &mut body_copy).await?;

                state.mark_ups_send_all();

                self.icap_connection.mark_reader_finished();
                if icap_rsp.keep_alive {
                    self.icap_client.save_connection(self.icap_connection);
                }

                Ok(ReqmodAdaptationEndState::AdaptedTransferred(final_req))
            }
        }
    }

    /// 把改写请求的 body 拷给上游，并施加空闲检测（读 ICAP / 写上游两侧方向判断）。
    ///
    /// `n` 是本轮 tick 跨过的间隔数，累加到 idle_count 后由 `check_quit` 换算是否
    /// 超时；`no_cached_data()` 为真表示缓冲区已无待写数据，即卡在"读 ICAP"，
    /// 否则说明数据堆在缓冲区写不出去，卡在"写上游"。
    async fn send_request_body<R, W>(
        idle_checker: &I,
        mut body_copy: &mut StreamCopy<'_, R, W>,
    ) -> Result<(), H1ReqmodAdaptationError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut idle_interval = idle_checker.interval_timer();
        let mut idle_count = 0;

        loop {
            tokio::select! {
                biased;

                r = &mut body_copy => {
                    return match r {
                        Ok(_) => Ok(()),
                        Err(StreamCopyError::ReadFailed(e)) => Err(H1ReqmodAdaptationError::IcapServerReadFailed(e)),
                        Err(StreamCopyError::WriteFailed(e)) => Err(H1ReqmodAdaptationError::HttpUpstreamWriteFailed(e)),
                    };
                }
                n = idle_interval.tick() => {
                    if body_copy.is_idle() {
                        idle_count += n;

                        let quit = idle_checker.check_quit(idle_count);
                        if quit {
                            return if body_copy.no_cached_data() {
                                Err(H1ReqmodAdaptationError::IcapServerReadIdle)
                            } else {
                                Err(H1ReqmodAdaptationError::HttpUpstreamWriteIdle)
                            };
                        }
                    } else {
                        idle_count = 0;

                        body_copy.reset_active();
                    }

                    if let Some(reason) = idle_checker.check_force_quit() {
                        return Err(H1ReqmodAdaptationError::IdleForceQuit(reason));
                    }
                }
            }
        }
    }
}
