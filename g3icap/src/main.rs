/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP 回显（echo）服务：基于开源库 `icap-rs`，把 `g3-icap-client` 发来的每个 ICAP
//! 请求逐段打印出来，并回一个"不修改"响应闭环。
//!
//! 它是审计链路的末端：g3proxy 的 auditor 把上行请求送到
//! `icap://127.0.0.1:1344/<service>`，这里收下来打印并放行。用来验证送审判定与协议
//! 标签是否正确、旁路链路是否通，真实审计引擎还没就位时也能先把端口占住。
//!
//! 打印内容：
//! 1. ICAP 请求线（方法 + 服务路径）；
//! 2. 全部 ICAP 头（Host / Encapsulated / Preview / X-Client-IP / Allow / ISTag…）；
//! 3. 封装的 HTTP 报文：请求行（或响应状态行）+ 头，RESPMOD 还包含
//!    可选的原始请求上下文（`req-hdr`）；
//! 4. 解码后的 body 长度与前 N 字节的 hexdump（默认 512，`--max-body-print` 调整）。
//!
//! 协议细节由 icap-rs 处理：OPTIONS 自动应答（按注册的 ServiceOptions），
//! Preview 握手（`ICAP/1.0 100 Continue`）自动完成，客户端未声明
//! `Allow: 204` 时自动把 204 换成 200 原样回显封装报文。
//!
//! 服务默认注册 `echo,reqmod,respmod,icap_audit` 四个名字，对应 g3proxy 的 HTTP
//! 审计（`/echo`）与 FTP 审计（`/icap_audit`）两条链路。
//!
//! 用法：
//! ```sh
//! # 默认监听 127.0.0.1:1344
//! cargo run -p g3icap
//! # 自定义监听地址与服务名（逗号分隔）
//! cargo run -p g3icap -- --listen 0.0.0.0:1344 --service echo,scan
//! ```
//! 部署形态见 `deploy/systemd/g3icap.service`：run 包把它装成 systemd 服务，收
//! SIGINT/SIGTERM 时把手上的请求收尾后再退。配合 `icap_perf_test`
//! （`cargo run -p g3-icap-client --example icap_perf_test`）可以量一下基础吞吐。

use std::process::ExitCode;

use clap::{Arg, Command, value_parser};
use http::{HeaderMap, Request as HttpRequest, Response as HttpResponse};
use icap_rs::{
    Body, EmbeddedHttp, HandlerResult, IncomingRequest, Method, Response, Server, ServiceOptions,
};

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const ISTAG: &str = "g3-icap-echo-1.0";

const ARG_LISTEN: &str = "listen";
const ARG_SERVICE: &str = "service";
const ARG_MAX_BODY_PRINT: &str = "max-body-print";

const DEFAULT_LISTEN: &str = "127.0.0.1:1344";
// HTTP 审计走 /echo（deploy/conf/g3proxy.yaml），FTP 审计走 /icap_audit
// （etc/g3proxy/ftp/auditor.d/ftp_auditor.yaml），默认两个都要接得住
const DEFAULT_SERVICES: &str = "echo,reqmod,respmod,icap_audit";
const DEFAULT_MAX_BODY_PRINT: &str = "512";

fn build_cli_args() -> Command {
    Command::new(PKG_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .about("ICAP echo server: print every ICAP request it receives and reply unmodified")
        .arg(
            Arg::new(ARG_LISTEN)
                .help("Address and port to listen on")
                .long(ARG_LISTEN)
                .num_args(1)
                .value_name("ADDR:PORT")
                .default_value(DEFAULT_LISTEN),
        )
        .arg(
            Arg::new(ARG_SERVICE)
                .help("ICAP service names to register, as a comma separated list")
                .long(ARG_SERVICE)
                .num_args(1)
                .value_name("NAME[,...]")
                .value_delimiter(',')
                .default_value(DEFAULT_SERVICES),
        )
        .arg(
            Arg::new(ARG_MAX_BODY_PRINT)
                .help("Max body bytes to hexdump per request")
                .long(ARG_MAX_BODY_PRINT)
                .num_args(1)
                .value_name("BYTES")
                .value_parser(value_parser!(usize))
                .default_value(DEFAULT_MAX_BODY_PRINT),
        )
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
    print_headers("headers", head.headers());
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
    print_headers("headers", head.headers());
}

fn print_body(body: &Body<Vec<u8>>, limit: usize) {
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
        let hex = chunk.iter().map(|b| format!("{b:02x} ")).collect::<String>();
        println!("    {:04x}  {hex:<48} |{ascii}|", line_idx * 16);
    }
    if shown < data.len() {
        println!(
            "    ... ({} bytes truncated, --max-body-print={limit})",
            data.len() - shown
        );
    }
}

fn print_request(request: &IncomingRequest, limit: usize) {
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
            print_body(body, limit);
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
            print_body(body, limit);
        }
    }
    println!("========================================================");
}

async fn echo(request: IncomingRequest, limit: usize) -> HandlerResult<Response> {
    print_request(&request, limit);
    // 204 = 不修改；客户端未 Allow: 204 时服务器自动改为原样 200 回显。
    Ok(Response::no_content_with_istag(ISTAG)?)
}

// systemd 默认用 SIGTERM 停服务，本包的单元用 SIGINT 让它优雅收尾——两种都要接住，
// 否则漏掉的那一种会直接砍断在途的审计请求
async fn wait_stop_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = build_cli_args().get_matches();

    let bind = args
        .get_one::<String>(ARG_LISTEN)
        .expect(ARG_LISTEN)
        .to_string();
    let services: Vec<String> = args
        .get_many::<String>(ARG_SERVICE)
        .expect(ARG_SERVICE)
        .cloned()
        .collect();
    let max_body_print = *args.get_one::<usize>(ARG_MAX_BODY_PRINT).expect(ARG_MAX_BODY_PRINT);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();

    if services.is_empty() {
        eprintln!("--service 至少要注册一个服务名");
        return ExitCode::FAILURE;
    }

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
        builder = builder.route(
            svc,
            [Method::ReqMod, Method::RespMod],
            move |request| echo(request, max_body_print),
            Some(opts()),
        );
    }
    let server = match builder.build().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("build ICAP server failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("g3icap listening on {bind}, services: {services:?}");

    if let Err(e) = server.run_until(wait_stop_signal()).await {
        eprintln!("g3icap server error: {e}");
        return ExitCode::FAILURE;
    }
    println!("g3icap stopped");
    ExitCode::SUCCESS
}
