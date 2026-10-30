/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025 ByteDance and/or its affiliates.
 */

//! STARTTLS 升级后的标准 TLS 拦截实现（MITM 双握手）。
//!
//! 为 [`StartTlsInterceptObject`] 提供 `do_intercept_tls`：先用客户端 ClientHello
//! 中的 SNI/ALPN 与源站完成 TLS 客户端握手，再取源站证书签发伪造证书，
//! 以 TLS 服务端身份接受客户端握手；两侧都建立安全通道后，把明文流交回
//! 协议检测循环（见 [`super::StartTlsInterceptObject::transfer_connected`]）。

use std::sync::Arc;

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

// 伪造服务端证书的用例随构建分支不同：tongsuo 需使用其专用扩展位
#[cfg(not(feature = "vendored-tongsuo"))]
const CERT_USAGE: TlsCertUsage = TlsCertUsage::TlsServer;
#[cfg(feature = "vendored-tongsuo")]
const CERT_USAGE: TlsCertUsage = TlsCertUsage::TLsServerTongsuo;

impl<SC> StartTlsInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    /// 在 STARTTLS 升级点上完成标准 TLS 的 MITM 拦截握手。
    ///
    /// 步骤：构造面向客户端的 SSL 状态 → 依据 ClientHello 构造面向源站的 SSL 状态
    /// → 与源站握手并保存会话/keylog 信息 → 用源站证书换取伪造证书 →
    /// 接受客户端握手 → 交给上层继续协议检测。
    ///
    /// `clt_r_buf` 是读取 ClientHello 时已缓冲的字节，必须回灌到客户端读流前面。
    pub(super) async fn do_intercept_tls(
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

        // 面向客户端的 SSL 状态：稍后作为 TLS 服务端，用伪造证书完成握手
        let mut clt_ssl =
            Ssl::new(&self.tls_interception.server_config.ssl_context).map_err(|e| {
                TlsInterceptionError::InternalOpensslServerError(anyhow!(
                    "failed to get new SSL state: {e}"
                ))
            })?;

        // build to server ssl context based on client hello
        // 依据 ClientHello 构造与源站通信的 SSL 状态（SNI / ALPN 都要与客户端保持一致，
        // 否则源站可能选到不同的证书或协议版本）
        let sni_hostname = client_hello.sni.as_ref();
        if let Some(domain) = sni_hostname {
            // TODO also fetch user-site config here?
            self.upstream.set_host(Host::from(domain));
        }
        let alpn_ext = client_hello.alpn.as_ref();
        // 仅在审计策略开启 keylog 时分配缓冲区，用于事后解密导出的流量
        let keylog_buffer = if self.ctx.audit_handle.tls_keylog() {
            Some(Arc::new(TlsKeyLogBuffer::new_with_max(
                self.ctx.audit_handle.tls_keylog_max_entries(),
            )))
        } else {
            None
        };
        // 用户站点配置优先：它可按站点定制证书校验、SNI、ALPN 等外连行为
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
                .build_ssl(
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
        // 先与源站握手：只有拿到真实证书，才能生成要给客户端的伪造证书
        let ups_tls_connector =
            SslConnector::new(ups_ssl, tokio::io::join(ups_r, ups_w)).map_err(|e| {
                TlsInterceptionError::UpstreamPrepareFailed(anyhow!(
                    "failed to get ssl stream: {e}"
                ))
            })?;
        // 握手必须限时：源站 stall 在 TLS 阶段会一直占住这条任务的连接资源
        let ups_tls_stream = tokio::time::timeout(
            self.tls_interception.client_config.handshake_timeout,
            ups_tls_connector.connect(),
        )
        .await
        .map_err(|_| TlsInterceptionError::UpstreamHandshakeTimeout)?
        .map_err(|e| {
            TlsInterceptionError::UpstreamHandshakeFailed(anyhow!("upstream handshake error: {e}"))
        })?;

        // Save TLS session for FTPS data channel reuse (vsftpd require_ssl_reuse)
        // 保存 FTPS 控制通道的 TLS 会话：部分服务端（vsftpd 的 require_ssl_reuse）
        // 要求数据通道必须复用同一会话，否则拒绝建连
        if self.protocol == super::StartTlsProtocol::Ftp
            && let Some(session) = ups_tls_stream.ssl().session()
        {
            match session.to_der() {
                Ok(session_der) => {
                    // 以「客户端 IP + FTP 服务端 IP」为键存入全局上传状态，供数据通道侧取回
                    let client_ip = self.ctx.task_notes.client_addr.ip();
                    let ftp_server_ip = self.ctx.connect_notes.server_addr.ip();
                    crate::serve::ftp_proxy::upload_state::get_ftp_upload_state().save_tls_session(
                        client_ip,
                        ftp_server_ip,
                        session_der,
                    );
                }
                Err(e) => {
                    // 会话序列化失败只影响数据通道复用，不阻断控制通道检测
                    log::warn!("FTPS control channel session serialization failed: {e}");
                }
            }
        }

        // 记录 TLS 版本/套件/服务端随机数，配合主密钥得到可解密的 keylog 素材
        if let Some(buf) = &self.keylog_buffer {
            if let Some(ssl_version) = ups_tls_stream.ssl().version2()
                && let Ok(version) = TlsVersion::try_from(ssl_version)
            {
                buf.set_tls_version(version);
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

        // 源站未提供证书就无法签发伪造证书，检测无法继续（不降级放行，避免"静默绕过"）
        let upstream_cert = ups_tls_stream.ssl().peer_certificate().ok_or_else(|| {
            TlsInterceptionError::NoFakeCertGenerated(anyhow!("failed to get upstream certificate"))
        })?;
        // 记录校验结果供拦截日志审计：校验失败也继续拦截，由客户端自行判断证书
        self.server_verify_result = Some(ups_tls_stream.ssl().verify_result());
        let cert_domain = sni_hostname
            .map(ArcStr::from)
            .unwrap_or_else(|| self.upstream.host().to_arc_str());
        // 按协议类型与证书用途向证书代理申请伪造证书（内部带缓存与 CA 签发）
        let cert_pair = self
            .tls_interception
            .cert_agent
            .fetch(
                TlsServiceType::from(self.protocol),
                CERT_USAGE,
                cert_domain,
                upstream_cert,
            )
            .await
            .ok_or_else(|| {
                TlsInterceptionError::NoFakeCertGenerated(anyhow!(
                    "failed to get fake upstream certificate"
                ))
            })?;

        // set certificate and private key
        // 把伪造证书装到面向客户端的 SSL 状态上
        cert_pair
            .add_to_ssl(&mut clt_ssl)
            .map_err(TlsInterceptionError::InternalOpensslServerError)?;
        // set alpn
        // 沿用与源站协商出的 ALPN，保证客户端与源站看到同一套应用层协议
        if let Some(alpn_protocol) = ups_tls_stream.ssl().selected_alpn_protocol() {
            self.tls_interception
                .server_config
                .set_selected_alpn(&mut clt_ssl, alpn_protocol.to_vec());
        }

        // 以 TLS 服务端身份接受客户端握手；客户端拒绝伪造证书、协商不兼容或
        // 超出 accept_timeout 都会在此失败，明文已无法继续，只能终止任务
        let clt_acceptor = SslAcceptor::new(
            clt_ssl,
            // 回灌已读取的 ClientHello 字节，让 acceptor 看到完整的握手记录
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

        // 双向安全通道就绪，转入解密后的协议检测
        Ok(self.transfer_connected(clt_tls_stream, ups_tls_stream))
    }
}
