/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 为 h2 server 侧的两种"响应发送器"实现 [`H2SendResponseToClient`]
//! 统一抽象：普通响应走 `h2::server::SendResponse`，服务器推送走
//! `SendPushedResponse`。二者方法签名一致，适配代码即可不关心具体来源。

use bytes::Bytes;
use h2::SendStream;
use h2::server::{SendPushedResponse, SendResponse};
use http::Response;

use super::H2SendResponseToClient;

// 普通 h2 响应：透传到 h2 crate 同名方法（方法名相同，注意用 self. 区分）
impl H2SendResponseToClient for SendResponse<Bytes> {
    fn send_response(
        &mut self,
        response: Response<()>,
        end_of_stream: bool,
    ) -> Result<SendStream<Bytes>, h2::Error> {
        self.send_response(response, end_of_stream)
    }
}

// 服务器推送（push）响应：同样转发给底层 h2 发送器
impl H2SendResponseToClient for SendPushedResponse<Bytes> {
    fn send_response(
        &mut self,
        response: Response<()>,
        end_of_stream: bool,
    ) -> Result<SendStream<Bytes>, h2::Error> {
        self.send_response(response, end_of_stream)
    }
}
