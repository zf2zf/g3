//! ICAP 回显（echo）调试服务器：基于开源库 `icap-rs`，把 `g3-icap-client`
//! 发来的每个 ICAP 请求逐段打印出来，并回一个"不修改"响应闭环。
//!
//! 打印内容：
//! 1. ICAP 请求线（方法 + 服务路径）；
//! 2. 全部 ICAP 头（Host / Encapsulated / Preview / X-Client-IP / Allow / ISTag…）；
//! 3. 封装的 HTTP 报文：请求行（或响应状态行）+ 头，RESPMOD 还包含
//!    可选的原始请求上下文（`req-hdr`）；
//! 4. 解码后的 body 长度与前 N 字节的 hexdump（默认 512，可用环境变量
//!    `G3_ICAP_ECHO_MAX_BODY` 调整）。
//!
//! 协议细节由 icap-rs 处理：OPTIONS 自动应答（按注册的 ServiceOptions），
//! Preview 握手（`ICAP/1.0 100 Continue`）自动完成，客户端未声明
//! `Allow: 204` 时自动把 204 换成 200 原样回显封装报文。
//!
//! 用法：
//! ```sh
//! # 默认监听 127.0.0.1:1344，注册 echo/reqmod/respmod 三个服务
//! cargo run -p g3-icap-client --example icap_echo_server
//! # 自定义：监听地址 + 额外服务名（逗号分隔）
//! cargo run -p g3-icap-client --example icap_echo_server -- 0.0.0.0:1344 scan,v1/scan
//! ```
//! 配合 `icap_perf_test`（连接 127.0.0.1:1344 的 echo 服务）或
//! `g3proxy` 的 icap 配置做联调。

use std::env;
use std::process::ExitCode;

use http::{HeaderMap, Request as HttpRequest, Response as HttpResponse};
use icap_rs::{
    Body, EmbeddedHttp, HandlerResult, IncomingRequest, Method, Response, Server, ServiceOptions,
};

const ISTAG: &str = "g3-icap-echo-1.0";

fn max_body_print() -> usize {
    env::var("G3_ICAP_ECHO_MAX_BODY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512)
}

fn print_headers(name: &str, headers: &HeaderMap) {
    println!("  {name}:");
    if headers.is_empty() {
        println!("    (none)");
        return;
    }
    for (k, v) in headers {
        let v = String::from_utf8_lossy(v.as_bytes());
        println!("    {k}: {v}");
    }
}

fn print_http_request_head(prefix: &str, head: &HttpRequest<()>) {
    println!("  {prefix} {} {:?}", head.method(), head.uri());
    print_headers(&format!("{prefix} headers"), head.headers());
}

fn print_http_response_head(prefix: &str, head: &HttpResponse<()>) {
    let version = match head.version() {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    };
    println!("  {prefix} {} {version}", head.status());
    print_headers(&format!("{prefix} headers"), head.headers());
}

fn print_body(body: &Body<Vec<u8>>) {
    let limit = max_body_print();
    match body {
        Body::Empty => println!("  body: (empty)"),
        Body::Preview { bytes, ieof, .. } => {
            println!("  body: preview {} bytes (ieof={ieof})", bytes.len());
            hexdump(bytes, limit);
        }
        Body::Full { reader } => {
            println!("  body: {} bytes", reader.len());
            hexdump(reader, limit);
        }
    }
}

fn hexdump(data: &[u8], limit: usize) {
    let shown = data.len().min(limit);
    if shown == 0 {
        return;
    }
    for (line_idx, chunk) in data[..shown].chunks(16).enumerate() {
        let mut ascii = String::with_capacity(chunk.len());
        for b in chunk {
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        let hex = chunk
            .iter()
            .map(|b| format!("{b:02x} "))
            .collect::<String>();
        println!("    {:04x}  {hex:<48} |{ascii}|", line_idx * 16);
    }
    if shown < data.len() {
        println!(
            "    ... ({} bytes truncated, G3_ICAP_ECHO_MAX_BODY={limit})",
            data.len() - shown
        );
    }
}

fn print_request(request: &IncomingRequest) {
    println!("========================================================");
    println!("ICAP {} {}", request.method(), request.service());
    if let Some(preview) = request.preview_size() {
        println!("  client preview: {preview}");
    }
    print_headers("ICAP headers", request.icap_headers());
    println!("  ISTag: {:?}", request.istag());
    if !request.chunk_trailers().is_empty() {
        print_headers("chunk trailers", request.chunk_trailers());
    }

    match request.embedded() {
        None => println!("  embedded: (none)"),
        Some(EmbeddedHttp::Req { head, body }) => {
            println!("  ---- embedded HTTP request ----");
            print_http_request_head("request-line:", head);
            print_body(body);
        }
        Some(EmbeddedHttp::Resp {
            req_head,
            head,
            body,
        }) => {
            if let Some(req_head) = req_head {
                println!("  ---- embedded HTTP request context (req-hdr) ----");
                print_http_request_head("request-line:", req_head);
            }
            println!("  ---- embedded HTTP response ----");
            print_http_response_head("status-line:", head);
            print_body(body);
        }
    }
    println!("========================================================");
}

async fn echo(request: IncomingRequest) -> HandlerResult<Response> {
    print_request(&request);
    // 204 = 不修改；客户端未 Allow: 204 时服务器自动改为原样 200 回显。
    Ok(Response::no_content_with_istag(ISTAG)?)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();

    let mut args = env::args().skip(1);
    let bind = args.next().unwrap_or_else(|| "127.0.0.1:1344".to_string());
    let services: Vec<String> = match args.next() {
        Some(s) => s.split(',').map(|x| x.to_string()).collect(),
        None => vec![
            "echo".to_string(),
            "reqmod".to_string(),
            "respmod".to_string(),
        ],
    };

    let opts = || {
        ServiceOptions::new()
            .with_static_istag(ISTAG)
            .with_service("g3 icap echo/debug service")
            .allow_204()
            .allow_206()
    };

    let mut builder = Server::builder()
        .bind(&bind)
        // 兼容不带 Encapsulated 的 OPTIONS 探测（RFC 3507 允许, g3-icap-client 即如此）
        .with_compatibility_request_parser();
    for svc in &services {
        builder = builder.route(svc, [Method::ReqMod, Method::RespMod], echo, Some(opts()));
    }
    let server = match builder.build().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("build ICAP server failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("icap-echo listening on {bind}, services: {services:?}");
    println!("press Ctrl-C to shut down (graceful drain)");

    if let Err(e) = server
        .run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    {
        eprintln!("icap-echo server error: {e}");
        return ExitCode::FAILURE;
    }
    println!("icap-echo stopped");
    ExitCode::SUCCESS
}
