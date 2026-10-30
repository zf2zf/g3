/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! 现代 TLS（标准 OpenSSL 后端）的中间人拦截握手实现。
//!
//! 实现 `TlsInterceptObject::do_intercept_modern`：基于已解析的 ClientHello，
//! 先与上游完成真实 TLS 握手并取得其证书，再按域名向 cert agent 申请假证书
//! 作为服务端身份接受客户端握手，最后依据协商结果（ALPN/协议识别）把 TLS 内的
//! 明文流交给下一检测状态。TLCP（国密）分支见 tlcp.rs。

use std::sync::Arc;

use anyhow::anyhow;
use arcstr::ArcStr;
use openssl::ssl::Ssl;

use g3_dpi::{Protocol, ProtocolInspector};
use g3_io_ext::OnceBufReader;
use g3_openssl::{SslAcceptor, SslConnector};
use g3_types::net::{AlpnProtocol, Host, TlsCertUsage, TlsKeyLogBuffer, TlsServiceType};

use super::{ParsedClientHello, TlsInterceptIo, TlsInterceptObject, TlsInterceptionError};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspection;

/// 假证书签发时声明的用途（cert agent 按用途选择签发策略）
///
/// 普通 OpenSSL 用 TlsServer；tongsuo 后端用 TLsServerTongsuo 变体。
#[cfg(not(feature = "vendored-tongsuo"))]
const CERT_USAGE: TlsCertUsage = TlsCertUsage::TlsServer;
#[cfg(feature = "vendored-tongsuo")]
const CERT_USAGE: TlsCertUsage = TlsCertUsage::TLsServerTongsuo;

impl<SC> TlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 现代 TLS 中间人拦截主流程
    ///
    /// 步骤概览：构造上下游 SSL 状态 -> 处理 SNI/ALPN -> 与上游握手 ->
    /// 申请假证书 -> 接受客户端握手 -> 按协商协议转移到内层检测。
    pub(super) async fn do_intercept_modern(
        &mut self,
        client_hello: ParsedClientHello,
        inspector: &mut ProtocolInspector,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        // 取出双向 IO；客户端读半部稍后用于握手
        let TlsInterceptIo {
            clt_r_buf,
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        // 作为服务端面向客户端的 SSL 状态（稍后用假证书接受握手）
        let mut clt_ssl =
            Ssl::new(&self.tls_interception.server_config.ssl_context).map_err(|e| {
                TlsInterceptionError::InternalOpensslServerError(anyhow!(
                    "failed to get new SSL state: {e}"
                ))
            })?;

        let sni_hostname = client_hello.sni.as_ref();
        // build to server ssl context based on client hello
        // （根据 ClientHello 构造到上游的 SSL 上下文）
        if let Some(domain) = sni_hostname {
            // TODO also fetch user-site config here?
            // 用 SNI 覆盖上游地址的主机名，确保连到正确的目标
            self.upstream.set_host(Host::from(domain));
        }
        // 过滤 ALPN：剔除检测策略要求拦截的协议；若全部被剔除则保留原始列表，
        // 不在 TLS 层阻断，改由应用层返回错误，避免误伤连接。
        let alpn_ext = client_hello.alpn.as_ref().map(|ext| {
            let new_ext = ext.retain_clone(|p| self.retain_alpn_protocol(p));
            if new_ext.is_empty() {
                // don't block traffic here, return error at the application layer
                ext.clone()
            } else {
                // make sure there are still at least 1 client accepted protocol
                new_ext
            }
        });
        // 若审计开启 TLS keylog，则分配密钥日志缓冲，供解密转储流量
        let keylog_buffer = if self.ctx.audit_handle.tls_keylog() {
            Some(Arc::new(TlsKeyLogBuffer::new_with_max(
                self.ctx.audit_handle.tls_keylog_max_entries(),
            )))
        } else {
            None
        };
        // 构造到上游的 SSL 状态：优先用用户站点配置模拟指纹，否则用通用配置
        let mut ups_ssl = match self.ctx.user_site_tls_client() {
            Some(c) => c
                .build_mimic_ssl(sni_hostname, &self.upstream, alpn_ext.as_ref())
                .map_err(|e| {
                    TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                        "failed to build user-site ssl context: {e}"
                    ))
                })?,
            None => self
                .tls_interception
                .client_config
                .build_ssl(
                    sni_hostname,
                    &self.upstream,
                    alpn_ext.as_ref(),
                    keylog_buffer.clone(),
                )
                .map_err(|e| {
                    TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                        "failed to build general ssl context: {e}"
                    ))
                })?,
        };
        self.keylog_buffer = keylog_buffer;

        // Check if this is an FTPS data channel (vsftpd require_ssl_reuse)
        // 判断是否为 FTPS 数据通道（vsftpd 要求复用控制通道的 TLS 会话）
        let ftps_domain = crate::inspect::ftp::get_ftps_domain(
            self.ctx.task_notes.client_addr,
            self.ctx.connect_notes.server_addr,
        );

        // Reuse FTPS control channel TLS session for data channel (vsftpd require_ssl_reuse)
        // 把控制通道缓存的 TLS 会话注入到数据通道，满足 require_ssl_reuse 要求
        if ftps_domain.is_some()
            && let Some(session_der) = crate::serve::ftp_proxy::upload_state::get_ftp_upload_state()
                .get_tls_session(
                    self.ctx.task_notes.client_addr.ip(),
                    self.ctx.connect_notes.server_addr.ip(),
                )
        {
            match openssl::ssl::SslSession::from_der(&session_der) {
                Ok(session) => unsafe {
                    if let Err(e) = ups_ssl.set_session(&session) {
                        log::warn!("FTPS data channel set_session failed: {e}");
                    }
                },
                Err(e) => {
                    log::warn!("FTPS data channel session deserialization failed: {e}");
                }
            }
        }

        // fetch fake server cert early in the background
        // Use FTPS domain if available, otherwise use SNI or upstream hostname
        // 提前在后台预取假证书以隐藏签发延迟；域名优先用 FTPS 域名，否则 SNI/上游主机名
        let cert_domain = if let Some(domain) = ftps_domain {
            ArcStr::from(domain)
        } else {
            sni_hostname
                .map(ArcStr::from)
                .unwrap_or_else(|| self.upstream.host().to_arc_str())
        };
        let cert_domain2 = cert_domain.clone();
        let cert_agent = self.tls_interception.cert_agent.clone();
        let pre_fetch_handle = tokio::spawn(async move {
            cert_agent
                .pre_fetch(TlsServiceType::Http, CERT_USAGE, cert_domain2)
                .await
        });

        // handshake with upstream server
        // 与上游完成真实 TLS 握手，带握手超时
        let ups_tls_connector =
            SslConnector::new(ups_ssl, tokio::io::join(ups_r, ups_w)).map_err(|e| {
                TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                    "failed to get ssl stream: {e}"
                ))
            })?;
        let ups_tls_stream = tokio::time::timeout(
            self.tls_interception.client_config.handshake_timeout,
            ups_tls_connector.connect(),
        )
        .await
        .map_err(|_| TlsInterceptionError::UpstreamHandshakeTimeout)?
        .map_err(|e| {
            TlsInterceptionError::UpstreamHandshakeFailed(anyhow!("upstream handshake error: {e}"))
        })?;

        // 等待后台预取结果；未命中缓存则取上游真实证书去签发对应假证书
        let pre_fetch_pair = pre_fetch_handle.await.map_err(|e| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                "join client cert handle failed: {e}"
            ))
        })?;

        let cert_pair = match pre_fetch_pair {
            Some(pair) => pair,
            None => {
                let upstream_cert = ups_tls_stream.ssl().peer_certificate().ok_or_else(|| {
                    TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                        "failed to get upstream certificate"
                    ))
                })?;
                self.tls_interception
                    .cert_agent
                    .fetch(TlsServiceType::Http, CERT_USAGE, cert_domain, upstream_cert)
                    .await
                    .ok_or_else(|| {
                        TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                            "failed to get fake upstream certificate"
                        ))
                    })?
            }
        };
        // 记录上游真实证书的校验结果，供拦截审计日志输出
        self.server_verify_result = Some(ups_tls_stream.ssl().verify_result());

        // set certificate and private key
        // 将假证书与私钥装入面向客户端的 SSL 状态，伪装成上游服务器
        cert_pair
            .add_to_ssl(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        // set alpn
        // 把与上游协商出的 ALPN 透传给客户端，保证两侧协议一致
        if let Some(alpn_protocol) = ups_tls_stream.ssl().selected_alpn_protocol() {
            self.tls_interception
                .server_config
                .set_selected_alpn(&mut clt_ssl, alpn_protocol.to_vec());
        }

        // 作为服务端接受客户端 TLS 握手；预读缓冲需重新拼回读流避免丢字节
        let clt_acceptor = SslAcceptor::new(
            clt_ssl,
            tokio::io::join(OnceBufReader::new(clt_r, clt_r_buf), clt_w),
            self.tls_interception.server_config.accept_timeout,
        )
        .map_err(|e| {
            TlsInterceptionError::InternalOpensslServerError(anyhow!(
                "failed to convert acceptor: {e}"
            ))
        })?;
        let clt_tls_stream = clt_acceptor.accept().await.map_err(|e| {
            TlsInterceptionError::ClientHandshakeFailed(anyhow!("client handshake error: {e:?}"))
        })?;

        // 根据客户端侧协商出的 ALPN 确定内层协议：命中 ALPN 则标记 has_alpn 并
        // 预置到协议识别器；否则保持 Unknown 由后续探测
        let mut protocol = Protocol::Unknown;
        let has_alpn = if let Some(alpn_protocol) = clt_tls_stream.ssl().selected_alpn_protocol() {
            if let Some(p) = AlpnProtocol::from_selected(alpn_protocol) {
                inspector.push_alpn_protocol(p);
                protocol = Protocol::from(p);
            }
            true
        } else {
            false
        };

        // 握手完成，把双向 TLS 流转移到下一检测状态
        Ok(self.transfer_connected(protocol, has_alpn, clt_tls_stream, ups_tls_stream))
    }
}
