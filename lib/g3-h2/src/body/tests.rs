/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! [`H2StreamReader`] / [`H2StreamWriter`] 的 h2 回环测试：在内存双工管道上跑
//! 一对真实的 h2 client/server 连接，验证请求体字节、TRAILERS 帧与 END_STREAM
//! 的收发语义——旁路审计管线正是靠这两个适配器把 h2 流接进通用读写接口。

use std::time::Duration;

use http::{HeaderMap, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{H2StreamBodyEnd, H2StreamReader, H2StreamWriter};

const PIPE_BUF: usize = 64 * 1024;
/// `body_end()` 只应在数据侧已经结束后被调用，此时结论必须立即可得；
/// 超时把"卡住"变成可诊断的测试失败而不是挂死。
const NO_WAIT: Duration = Duration::from_secs(2);

type ServerConn = h2::server::Connection<tokio::io::DuplexStream, bytes::Bytes>;

fn upload_req() -> Request<()> {
    Request::builder()
        .method("POST")
        .uri("http://example.org/upload")
        .body(())
        .unwrap()
}

/// 服务端读完一个请求体后的观测结果。
struct RecvOutcome {
    data: Vec<u8>,
    read_err: bool,
    end: H2StreamBodyEnd,
}

impl std::fmt::Debug for RecvOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvOutcome")
            .field("bytes", &String::from_utf8_lossy(&self.data))
            .field("read_err", &self.read_err)
            .field("end", &self.end)
            .finish()
    }
}

/// 起一对走内存管道的 h2 连接：返回客户端 `SendRequest` 与服务端握手结果。
async fn h2_pair() -> (h2::client::SendRequest<bytes::Bytes>, ServerConn) {
    let (client_io, server_io) = tokio::io::duplex(PIPE_BUF);
    let (h2c, driver) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(driver);
    let h2s = h2::server::handshake(server_io).await.unwrap();
    (h2c, h2s)
}

/// 读掉请求体并给出结束结论。`drain` 为真表示读到 EOF（请求体应当已结束），
/// 为假表示只取第一块就收尾，用于观察"流还没结束"的状态。
async fn read_body(body: h2::RecvStream, drain: bool) -> RecvOutcome {
    let mut reader = H2StreamReader::new(body);
    let mut data = Vec::new();
    let read_err = if drain {
        reader.read_to_end(&mut data).await.is_err()
    } else {
        let mut buf = [0u8; 32];
        match reader.read(&mut buf).await {
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                false
            }
            Err(_) => true,
        }
    };
    let end = tokio::time::timeout(NO_WAIT, reader.body_end())
        .await
        .expect("body_end must not block once the data side is done");
    RecvOutcome {
        data,
        read_err,
        end,
    }
}

/// 服务端收下一个请求并读体，返回结论句柄。
///
/// 读体必须和处理帧分开跑：`accept()` 返回之后若不再 poll 连接，后续
/// DATA / TRAILERS / RST 帧根本不会被解析，读侧就永远等不到数据。这里让
/// 读体任务独立运行、连接停在第二次 `accept()` 上被持续驱动，与代理里
/// 真实的 h2 拦截循环同构。`drain` 的含义见 [`read_body`]。
fn spawn_server(conn: ServerConn, drain: bool) -> tokio::task::JoinHandle<RecvOutcome> {
    let mut conn = conn;
    tokio::spawn(async move {
        let (req, _rsp) = conn.accept().await.expect("accept").expect("request");
        let (_parts, body) = req.into_parts();
        let reader = tokio::spawn(read_body(body, drain));

        tokio::select! {
            out = reader => out.expect("body reader panicked"),
            next = conn.accept() => {
                let _ = next;
                panic!("test sends only one request");
            }
        }
    })
}

#[tokio::test]
async fn writer_finish_sends_trailers() {
    let (mut h2c, h2s) = h2_pair().await;
    let server = spawn_server(h2s, true);
    let (_rsp_fut, send_stream) = h2c.send_request(upload_req(), false).unwrap();
    let mut writer = H2StreamWriter::new(send_stream);
    writer.write_all(b"hello ").await.unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().unwrap());
    writer.finish(Some(trailers)).unwrap();
    drop(writer);

    let server = server.await.unwrap();
    assert!(
        !server.read_err,
        "a body ended with TRAILERS must read cleanly"
    );
    assert_eq!(server.data, b"hello ");
    match server.end {
        H2StreamBodyEnd::Trailers(received) => {
            assert_eq!(received.get("x-checksum").unwrap(), "abc123");
        }
        other => panic!("TRAILERS frame must reach the origin, got {other:?}"),
    }
}

#[tokio::test]
async fn writer_finish_without_trailers_sends_end_stream() {
    let (mut h2c, h2s) = h2_pair().await;
    let server = spawn_server(h2s, true);
    let (_rsp_fut, send_stream) = h2c.send_request(upload_req(), false).unwrap();
    let mut writer = H2StreamWriter::new(send_stream);
    writer.write_all(b"payload").await.unwrap();
    writer.finish(None).unwrap();
    drop(writer);

    let server = server.await.unwrap();
    assert!(
        !server.read_err,
        "END_STREAM must let the origin finish reading the body"
    );
    assert_eq!(server.data, b"payload");
    assert!(
        matches!(server.end, H2StreamBodyEnd::EndOfStream),
        "{:?}",
        server.end
    );
}

#[tokio::test]
async fn body_end_reports_incomplete_while_client_stalls() {
    let (mut h2c, h2s) = h2_pair().await;
    // 客户端只送出一半就停住：对应旁路管线的空闲看门狗掐断中继循环
    let server = spawn_server(h2s, false);
    let (_rsp_fut, send_stream) = h2c.send_request(upload_req(), false).unwrap();
    let mut writer = H2StreamWriter::new(send_stream);
    writer.write_all(b"part").await.unwrap();

    let server = server.await.unwrap();
    assert!(!server.read_err, "{server:?}");
    assert_eq!(server.data, b"part");
    assert!(
        matches!(server.end, H2StreamBodyEnd::Incomplete),
        "a body that has not reached END_STREAM/TRAILERS is incomplete: {:?}",
        server.end
    );
}

#[tokio::test]
async fn body_end_reports_incomplete_after_writer_dropped_mid_body() {
    let (mut h2c, h2s) = h2_pair().await;
    // 请求体只送出一半就整体丢弃：h2 要在写流与响应句柄都释放（流引用计数归零）
    // 后才对未结束的请求流发 RST_STREAM，对应旁路管线被掐断后整段转发生命周期
    // 一起析构的真实情形。已发出的 DATA 是否在 reset 前抵达源站由 h2 内部调度
    // 决定，这里只锁定"被 reset 的流不可能给出干净结论"这一条语义。
    let server = spawn_server(h2s, true);
    let (rsp_fut, send_stream) = h2c.send_request(upload_req(), false).unwrap();
    let mut writer = H2StreamWriter::new(send_stream);
    writer.write_all(b"part").await.unwrap();
    drop(writer);
    drop(rsp_fut);

    let server = server.await.unwrap();
    assert!(server.read_err, "the reset must surface as a read error");
    assert!(
        matches!(server.end, H2StreamBodyEnd::Incomplete),
        "a reset stream never ends cleanly: {:?}",
        server.end
    );
}
