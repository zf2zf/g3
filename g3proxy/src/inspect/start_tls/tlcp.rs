/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025 ByteDance and/or its affiliates.
 */

//! STARTTLS 升级后的国密 TLCP 拦截实现（仅在 `vendored-tongsuo` 构建下编译）。
//!
//! 与 [`super::tls`] 的标准 TLS 流程同构：先与源站握手取回真实证书，再签伪造证书
//! 接受客户端握手。差异在于 TLCP（GB/T 38636）要求服务端提供**签名证书 + 加密证书**
//! 两份证书，因此需要向证书代理分别申请两个用途的证书对，并分别装入 SSL 状态。

use anyhow::anyhow;
use arcstr::ArcStr;
use bytes::BytesMut;
use openssl::ssl::Ssl;

use g3_io_ext::OnceBufReader;
use g3_openssl::{SslAcceptor, SslConnector};
use g3_types::net::{Host, TlsCertUsage, TlsKeyLogBuffer, TlsServiceType, TlsVersion};

use super::{StartTlsInterceptIo, StartTlsInterceptObject};
use crate::config::server::ServerConfig;
use crate::inspect::StreamInspection;
use crate::inspect::tls::{ParsedClientHello, TlsInterceptionError};

impl<SC> StartTlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 在 STARTTLS 升级点上完成国密 TLCP 的 MITM 拦截握手。
    ///
    /// `clt_r_buf` 为读取 ClientHello 时已缓冲的字节，需回灌到客户端读流前面，
    /// 否则 acceptor 读不到完整的握手记录。
    pub(super) async fn do_intercept_tlcp(
        &mut self,
        client_hello: ParsedClientHello,
        clt_r_buf: BytesMut,
    ) -> Result<StreamInspection<SC>, TlsInterceptionError> {
        let StartTlsInterceptIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        // 面向客户端的 SSL 状态，取自 TLCP 专用上下文（SM2 曲线/国密套件）
        let mut clt_ssl =
            Ssl::new(&self.tls_interception.server_config.tlcp_context).map_err(|e| {
                TlsInterceptionError::InternalOpensslServerError(anyhow!(
                    "failed to get new TLCP SSL state: {e}"
                ))
            })?;

        // build to server ssl context based on client hello
        // 按 ClientHello 的 SNI/ALPN 构造与源站通信的 SSL 状态，保持两端协商一致
        let sni_hostname = client_hello.sni.as_ref();
        if let Some(domain) = sni_hostname {
            // TODO also fetch user-site config here?
            self.upstream.set_host(Host::from(domain));
        }
        let alpn_ext = client_hello.alpn.as_ref();
        // keylog 缓冲区仅在审计策略开启时分配，用于事后解密导出的国密流量
        let keylog_buffer = if self.ctx.audit_handle.tls_keylog() {
            Some(Arc::new(TlsKeyLogBuffer::new_with_max(
                self.ctx.audit_handle.tls_keylog_max_entries(),
            )))
        } else {
            None
        };
        // 用户站点级 TLS 客户端配置优先于通用配置
        let ups_ssl = match self.ctx.user_site_tls_client() {
            Some(c) => c
                .build_mimic_ssl(sni_hostname, &self.upstream, alpn_ext)
                .map_err(|e| {
                    TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                        "failed to build user-site ssl context: {e}"
                    ))
                })?,
            None => self
                .tls_interception
                .client_config
                .build_tlcp(
                    sni_hostname,
                    &self.upstream,
                    alpn_ext,
                    keylog_buffer.clone(),
                )
                .map_err(|e| {
                    TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                        "failed to build general ssl context: {e}"
                    ))
                })?,
        };
        self.keylog_buffer = keylog_buffer;

        // handshake with upstream server
        // 先与源站完成 TLCP 握手，取得真实的签名/加密证书链
        let ups_tls_connector =
            SslConnector::new(ups_ssl, tokio::io::join(ups_r, ups_w)).map_err(|e| {
                TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                    "failed to get ssl stream: {e}"
                ))
            })?;
        // 限时握手，避免源站在 TLCP 阶段停滞导致任务长时间挂起
        let ups_tls_stream = tokio::time::timeout(
            self.tls_interception.client_config.handshake_timeout,
            ups_tls_connector.connect(),
        )
        .await
        .map_err(|_| TlsInterceptionError::UpstreamHandshakeTimeout)?
        .map_err(|e| {
            TlsInterceptionError::UpstreamHandshakeFailed(anyhow!("upstream handshake error: {e}"))
        })?;

        // 回填 TLS 版本/套件/服务端随机数，为 keylog 解密提供素材
        if let Some(buf) = &self.keylog_buffer {
            if let Some(ssl_version) = ups_tls_stream.ssl().version2() {
                if let Ok(version) = TlsVersion::try_from(ssl_version) {
                    buf.set_tls_version(version);
                }
            }
            if let Some(cipher) = ups_tls_stream.ssl().current_cipher() {
                let cipher_id = u16::from_be_bytes(cipher.protocol_id());
                buf.set_cipher_suite(cipher_id);
            }
            let mut random_buf = [0u8; 32];
            let random_len = ups_tls_stream.ssl().server_random(&mut random_buf);
            if random_len > 0 {
                buf.set_server_random(hex::encode(&random_buf[..random_len]));
            }
        }

        // 源站证书是签发伪造证书的依据，缺失即无法继续拦截
        let upstream_cert = ups_tls_stream.ssl().peer_certificate().ok_or_else(|| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!("failed to get upstream certificate"))
        })?;
        // 记录源站证书校验结果供审计（校验失败不阻断拦截，交由客户端裁决）
        self.server_verify_result = Some(ups_tls_stream.ssl().verify_result());
        let cert_domain = sni_hostname
            .map(ArcStr::from)
            .unwrap_or_else(|| self.upstream.host().to_arc_str());

        // TLCP 需要两份证书：签名证书用于身份认证，加密证书用于密钥交换，
        // 因此分别向证书代理申请两个用途的伪造证书对
        let tls_service_type = TlsServiceType::from(self.protocol);
        let sign_cert_pair = self
            .tls_interception
            .cert_agent
            .fetch(
                tls_service_type,
                TlsCertUsage::TlcpServerSignature,
                cert_domain.clone(),
                upstream_cert.clone(),
            )
            .await
            .ok_or_else(|| {
                TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                    "failed to get fake upstream sign certificate"
                ))
            })?;
        let enc_cert_pair = self
            .tls_interception
            .cert_agent
            .fetch(
                tls_service_type,
                TlsCertUsage::TlcpServerEncryption,
                cert_domain.clone(),
                upstream_cert,
            )
            .await
            .ok_or_else(|| {
                TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                    "failed to get fake upstream enc certificate"
                ))
            })?;

        // set certificate and private key
        // 两套证书分别装入面向客户端的 SSL 状态，缺一不可完成 TLCP 握手
        sign_cert_pair
            .add_sign_to_tlcp(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        enc_cert_pair
            .add_enc_to_tlcp(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        // set alpn
        // 沿用与源站协商出的 ALPN，保证客户端与源站的应用层协议视图一致
        if let Some(alpn_protocol) = ups_tls_stream.ssl().selected_alpn_protocol() {
            self.tls_interception
                .server_config
                .set_selected_alpn(&mut clt_ssl, alpn_protocol.to_vec());
        }

        // 以 TLCP 服务端身份接受客户端握手（客户端不信任国密 CA 或超时会在此失败）
        let clt_acceptor = SslAcceptor::new(
            clt_ssl,
            // 回灌 ClientHello 原始字节，让 acceptor 能从头解析握手记录
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

        // 双向国密安全通道就绪，转入解密后的协议检测
        Ok(self.transfer_connected(clt_tls_stream, ups_tls_stream))
    }
}
