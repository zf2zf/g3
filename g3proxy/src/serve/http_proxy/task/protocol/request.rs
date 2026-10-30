/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use http::{HeaderValue, Method, Version, header};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tokio::time::Instant;

use g3_http::server::{HttpProxyClientRequest, HttpRequestParseError, UriExt};
use g3_http::uri::{HttpMasque, WellKnownUri};
use g3_types::net::{HttpProxySubProtocol, UpstreamAddr};

use super::HttpClientReader;
use crate::config::server::http_proxy::HttpProxyServerConfig;

/// 从客户端连接解析出的一条代理请求，reader→writer 之间传递的基本单元。
pub(crate) struct HttpProxyRequest<CDR> {
    // 客户端侧子协议：决定 writer 分发到哪种任务（CONNECT/HTTP/HTTPS/FTP-over-HTTP）
    pub(crate) client_protocol: HttpProxySubProtocol,
    pub(crate) inner: HttpProxyClientRequest,
    // 从 URI/Host 解析出的目标上游地址
    pub(crate) upstream: UpstreamAddr,
    pub(crate) time_accepted: Instant, // 开始解析请求头的时刻
    pub(crate) time_received: Instant, // 请求头接收完毕的时刻
    // Some 表示 socket 读端随本请求移交（请求带 body，或 CONNECT 等需独占连接）
    pub(crate) body_reader: Option<HttpClientReader<CDR>>,
    // 用完读端后经此 channel 归还给 reader 任务（见 pipeline/reader.rs 的主循环）
    pub(crate) stream_sender: mpsc::Sender<Option<HttpClientReader<CDR>>>,
}

impl<CDR> HttpProxyRequest<CDR>
where
    CDR: AsyncRead + Unpin,
{
    /// 从 reader 解析一条完整请求。返回 `(请求, send_reader)`：
    /// `send_reader` 为 true 时 reader 必须把 socket 读端随请求移交出去
    /// （不再继续读下一条），false 时读端留在 reader 侧（普通无 body 转发的 keep-alive 路径）。
    pub(crate) async fn parse(
        config: &HttpProxyServerConfig,
        reader: &mut HttpClientReader<CDR>,
        sender: mpsc::Sender<Option<HttpClientReader<CDR>>>,
        version: &mut Version,
    ) -> Result<(Self, bool), HttpRequestParseError> {
        let time_accepted = Instant::now();

        // 解析请求头；对代理特有头部做拦截处理：
        // Proxy-Authorization 单独提取认证信息，Proxy-Connection 按 Connection 处理，
        // steal_forwarded_for 开启时吞掉客户端伪造的 Forwarded/X-Forwarded-For
        let mut req = HttpProxyClientRequest::parse(
            reader,
            config.req_hdr_max_size,
            version,
            |req, name, header| {
                match name.as_str() {
                    "proxy-authorization" => return req.parse_header_authorization(header.value),
                    "proxy-connection" => {
                        // proxy-connection is not standard, but at least curl use it
                        return req.parse_header_connection(header);
                    }
                    "forwarded" | "x-forwarded-for" if config.steal_forwarded_for => {
                        return Ok(());
                    }
                    _ => {}
                }
                req.append_parsed_header(name, header)?;
                Ok(())
            },
        )
        .await?;
        let time_received = Instant::now();

        // 确定目标上游与子协议，三种来源：
        // CONNECT 方法 → 默认 443 端口的 TCP 隧道；
        // 请求打到本代理的"本地服务名" → 从 well-known URI 尾部解出真实目标；
        // 其余 → 标准绝对形式 URI（http://host/... 或 origin-form + Host）
        let (upstream, sub_protocol) = if matches!(&req.method, &Method::CONNECT) {
            let addr = req.uri.get_upstream_with_default_port(443)?;
            (addr, HttpProxySubProtocol::TcpConnect)
        } else if req.is_local_request(&config.local_server_names) {
            match WellKnownUri::parse(&req.uri).map_err(|e| {
                HttpRequestParseError::UnsupportedRequest(format!("invalid well-known uri: {e}",))
            })? {
                // /.well-known/easy-proxy/<scheme>/<host>/<port>/<path> 风格：
                // 真实目标与协议编码在 URI 中，剩下的 <path> 作为改写后的转发 URI
                Some(WellKnownUri::EasyProxy(protocol, addr, uri)) => {
                    req.uri = uri;
                    req.set_host(&addr);
                    (addr, protocol)
                }
                // Masque 风格 URI：取出内层 HTTP 请求作为实际转发请求
                Some(WellKnownUri::Masque(HttpMasque::Http(uri))) => {
                    req.uri = uri;
                    let (addr, protocol) = req.uri.get_upstream_and_protocol()?;
                    req.set_host(&addr);
                    (addr, protocol)
                }
                Some(v) => {
                    return Err(HttpRequestParseError::UnsupportedRequest(format!(
                        "unsupported well-known uri suffix: {}",
                        v.suffix()
                    )));
                }
                None => {
                    return Err(HttpRequestParseError::UnsupportedRequest(
                        "unsupported local request uri".to_string(),
                    ));
                }
            }
        } else {
            req.uri.get_upstream_and_protocol()?
        };

        // 默认要求 Host 头与 URI 目标一致，防止面向错误上游的请求走私
        if !config.allow_custom_host
            && let Some(host) = &req.host
            && !host.host_eq(&upstream)
        {
            return Err(HttpRequestParseError::UnmatchedHostAndAuthority);
        }

        let req = HttpProxyRequest {
            client_protocol: sub_protocol,
            inner: req,
            upstream,
            time_accepted,
            time_received,
            body_reader: None,
            stream_sender: sender,
        };

        // 决定是否把 socket 读端随请求移交（send_reader）
        match req.client_protocol {
            HttpProxySubProtocol::TcpConnect => {
                // just send to forward task, which will go into a connect task
                // reader should be sent
                // CONNECT 接管整条连接，读端必须移交
                return Ok((req, true));
            }
            HttpProxySubProtocol::FtpOverHttp => {}
            HttpProxySubProtocol::HttpForward | HttpProxySubProtocol::HttpsForward => {
                if req.inner.pipeline_safe() {
                    // reader should not be sent
                    // 幂等且无 body 的请求（GET/HEAD/PUT/DELETE）可安全管道化：
                    // reader 继续读下一条，实现请求并发
                    return Ok((req, false));
                }
            }
        }

        // reader should be sent by default
        // 兜底：带 body 的请求等场景，读端移交，等 writer 归还后才读下一条
        Ok((req, true))
    }

    /// 去掉 Host 头里显式写出的默认端口（:80 / :443），使转发到上游的 Host 更规范。
    pub(crate) fn drop_default_port_in_host(&mut self) {
        if let Some(v) = self.inner.end_to_end_headers.get_mut(header::HOST) {
            let b = v.inner().as_bytes();
            if let Some(d) = memchr::memchr(b':', b) {
                let new_v = HeaderValue::from_bytes(&b[..d]).unwrap();
                v.set_inner(new_v);
            }
        }
    }
}
