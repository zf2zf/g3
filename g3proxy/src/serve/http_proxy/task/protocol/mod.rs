/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 客户端 HTTP 报文在流水线中的表示与类型别名。

use g3_io_ext::{LimitedBufReader, LimitedWriter};

mod request;
pub(super) use request::HttpProxyRequest;

// 客户端 socket 的带限速读端 / 写端类型别名，在 reader、writer 及各子任务间传递
pub(super) type HttpClientReader<CDR> = LimitedBufReader<CDR>;
pub(super) type HttpClientWriter<CDW> = LimitedWriter<CDW>;
