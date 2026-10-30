/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! TLCP（国密 TLS，GM/T 0024）中间人拦截握手实现。
//!
//! 仅在启用 `vendored-tongsuo` 后端时编译。与现代 TLS 的区别：TLCP 使用签名+加密
//! 双证书，因此需要向 cert agent 分别申请两张贴片假证书（ServerSignature /
//! ServerEncryption），并用 `build_tlcp` 构造上游 SSL。其余流程（读 ClientHello、
//! 上游握手、客户端握手、按 ALPN 转移）与 modern.rs 对应。

use anyhow::anyhow;
use arcstr::ArcStr;
use openssl::ssl::Ssl;

use g3_dpi::{Protocol, ProtocolInspector};
use g3_io_ext::OnceBufReader;
use g3_openssl::{SslAcceptor, SslConnector};
use g3_types::net::{AlpnProtocol, Host, TlsCertUsage, TlsServiceType};

use super::{ParsedClientHello, TlsInterceptIo, TlsInterceptObject, TlsInterceptionError};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspection;

impl<SC> TlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// TLCP 中间人拦截主流程
    ///
    /// 与 `do_intercept_modern` 结构一致，差异在于上游使用 TLCP 上下文、
    /// 并需为客户端并行预取签名证书与加密证书两份假证书。
    pub(super) async fn do_intercept_tlcp(
        &mut self,
        client_hello: ParsedClientHello,
        inspector: &mut ProtocolInspector,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        // 取出双向 IO
        let TlsInterceptIo {
            clt_r_buf,
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        // 面向客户端的 SSL 状态，使用 TLCP 专用上下文
        let mut clt_ssl =
            Ssl::new(&self.tls_interception.server_config.tlcp_context).map_err(|e| {
                TlsInterceptionError::InternalOpensslServerError(anyhow!(
                    "failed to get new TLCP SSL state: {e}"
                ))
            })?;

        // build to server ssl context based on client hello
        // （根据 ClientHello 构造到上游的 SSL 上下文）
        let sni_hostname = client_hello.sni.as_ref();
        if let Some(domain) = sni_hostname {
            // TODO also fetch user-site config here?
            // 用 SNI 覆盖上游主机名
            self.upstream.set_host(Host::from(domain));
        }
        // 过滤 ALPN：被策略拦截的协议剔除；全被剔除时保留原列表，留到应用层再处理
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
        // 构造到上游的 SSL：优先用户站点模拟配置，否则用通用 TLCP 配置
        let ups_ssl = match self.ctx.user_site_tls_client() {
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
                .build_tlcp(sni_hostname, &self.upstream, alpn_ext.as_ref())
                .map_err(|e| {
                    TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                        "failed to build general ssl context: {e}"
                    ))
                })?,
        };

        // fetch fake server cert early in the background
        // TLCP 需两张假证书，故并行预取签名证书与加密证书以隐藏签发延迟
        let cert_domain = sni_hostname
            .map(ArcStr::from)
            .unwrap_or_else(|| self.upstream.host().to_arc_str());
        let cert_domain2 = cert_domain.clone();
        let cert_agent = self.tls_interception.cert_agent.clone();
        let sign_pre_fetch_handle = tokio::spawn(async move {
            cert_agent
                .pre_fetch(
                    TlsServiceType::Http,
                    TlsCertUsage::TlcpServerSignature,
                    cert_domain2,
                )
                .await
        });
        let cert_domain2 = cert_domain.clone();
        let cert_agent = self.tls_interception.cert_agent.clone();
        let enc_pre_fetch_handle = tokio::spawn(async move {
            cert_agent
                .pre_fetch(
                    TlsServiceType::Http,
                    TlsCertUsage::TlcpServerEncryption,
                    cert_domain2,
                )
                .await
        });

        // handshake with upstream server
        // 与上游完成 TLCP 真实握手，带握手超时
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

        // 取上游真实证书：作为签发两张假证书的依据
        let upstream_cert = ups_tls_stream.ssl().peer_certificate().ok_or_else(|| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!("failed to get upstream certificate"))
        })?;
        // 记录上游证书校验结果供审计
        self.server_verify_result = Some(ups_tls_stream.ssl().verify_result());

        // 签名证书：命中预取缓存则复用，否则现签
        let sign_pre_fetch_pair = sign_pre_fetch_handle.await.map_err(|e| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                "join client cert handle failed: {e}"
            ))
        })?;
        let sign_cert_pair = match sign_pre_fetch_pair {
            Some(pair) => pair,
            None => self
                .tls_interception
                .cert_agent
                .fetch(
                    TlsServiceType::Http,
                    TlsCertUsage::TlcpServerSignature,
                    cert_domain.clone(),
                    upstream_cert.clone(),
                )
                .await
                .ok_or_else(|| {
                    TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                        "failed to get fake upstream sign certificate"
                    ))
                })?,
        };

        // 加密证书：同上，注意此处 move 走 upstream_cert（签名分支已 clone）
        let enc_pre_fetch_pair = enc_pre_fetch_handle.await.map_err(|e| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                "join client cert handle failed: {e}"
            ))
        })?;
        let enc_cert_pair = match enc_pre_fetch_pair {
            Some(pair) => pair,
            None => self
                .tls_interception
                .cert_agent
                .fetch(
                    TlsServiceType::Http,
                    TlsCertUsage::TlcpServerEncryption,
                    cert_domain,
                    upstream_cert,
                )
                .await
                .ok_or_else(|| {
                    TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                        "failed to get fake upstream enc certificate"
                    ))
                })?,
        };

        // set certificate and private key
        // 将签名/加密两张假证书及配套私钥装入面向客户端的 TLCP SSL 状态
        sign_cert_pair
            .add_sign_to_tlcp(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        enc_cert_pair
            .add_enc_to_tlcp(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        // set alpn
        // 透传与上游协商的 ALPN 给客户端
        if let Some(alpn_protocol) = ups_tls_stream.ssl().selected_alpn_protocol() {
            self.tls_interception
                .server_config
                .set_selected_alpn(&mut clt_ssl, alpn_protocol.to_vec());
        }

        // 作为服务端接受客户端 TLCP 握手；预读缓冲重新拼回读流
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

        // 依据客户端侧协商的 ALPN 确定内层协议并预置识别器；无 ALPN 则保持 Unknown
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

        // 握手完成，转移到下一检测状态
        Ok(self.transfer_connected(protocol, has_alpn, clt_tls_stream, ups_tls_stream))
    }
}
