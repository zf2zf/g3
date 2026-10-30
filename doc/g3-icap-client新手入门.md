# g3-icap-client 新手入门文档

> 适用版本：`lib/g3-icap-client` v0.4.0（分支 `local/work-v113`）
> 前置知识：RFC 3507 (ICAP)、HTTP/1.1 chunked 编码、Rust + tokio 异步基础

---

## 1. 这个项目是什么

`g3-icap-client` 是 g3 项目中的一个 **ICAP 客户端库**（RFC 3507）。它不是独立程序，而是被
`g3proxy` 依赖的 library crate。它的职责是：

**把代理上采集到的流量内容（HTTP 请求/响应、SMTP 邮件、IMAP 邮件、FTP 上传文件、
TLS 会话密钥等），按照 ICAP 协议"封装上报"给远端的 ICAP 服务（内容检测/审计/DLP 引擎），
并解析 ICAP 服务返回的处置结果（放行 / 改写 / 阻断）。**

一句话概括数据流：

```
客户端 ──► g3proxy(inspect 模块采集) ──► g3-icap-client(封装上报) ──► ICAP 服务器(检测)
                    ▲                                                        │
                    └──────────── 处置结果 (204放行/200改写/错误响应) ◄───────┘
```

ICAP 协议族有三个方法，本库全部实现：

| 方法 | 方向 | 作用 |
|------|------|------|
| `OPTIONS` | 客户端→服务器 | 查询服务能力：是否支持 204/206、preview 大小、连接数上限 |
| `REQMOD` | 客户端→服务器 | 上报**请求**内容（含 FTP 上传、SMTP/IMAP 发信），可被改写或返回错误响应 |
| `RESPMOD` | 客户端→服务器 | 上报**响应**内容（下行流量），可被改写 |

---

## 2. 目录结构导读

```
src/
├── lib.rs                  # 出口：reqmod / respmod / options / service 类型
├── reason.rs               # 错误原因枚举（审计日志里可见）
├── serialize/
│   └── header.rs           # ★ 所有"采集信息"的头部序列化（上报格式的核心）
├── parse/                  # ICAP 状态行/头部行的低成本解析（不区分大小写）
├── options/                # OPTIONS 请求的发送与响应解析（preview_size、Allow 能力）
├── service/
│   ├── config/mod.rs       # 服务配置：URL、鉴权、TLS、连接池、preview 开关等
│   ├── config/yaml.rs      # YAML 配置解析（g3proxy 配置文件由此接入）
│   ├── connection.rs       # 单条 ICAP TCP/TLS 连接的读写端
│   ├── pool.rs             # 连接池 + keep-alive + OPTIONS 缓存
│   └── client.rs           # IcapServiceClient：fetch_connection / save_connection
├── reqmod/                 # ★ REQMOD 上报（各协议适配器）
│   ├── mod.rs              # ConnectionTuple / ConnectionProtocol / IcapReqmodClient
│   ├── payload.rs          # 响应 Encapsulated 头解析
│   ├── response.rs         # 响应状态行+头部解析（含共享头回传）
│   ├── mail.rs             # SMTP/IMAP 适配器共用的状态结构
│   ├── h1/                 # HTTP/1.1 适配器（含 preview、双向流式传输）
│   ├── h2/                 # HTTP/2 适配器
│   ├── smtp/               # SMTP DATA 阶段适配器
│   ├── imap/               # IMAP APPEND 阶段适配器
│   └── ftp/                # FTP 上传审计适配器（本机扩展，含降级放行逻辑）
└── respmod/                # RESPMOD 上报（h1/h2），结构与 reqmod 对称
```

建议阅读顺序：`serialize/header.rs` → `service/config/mod.rs` → `reqmod/h1/mod.rs`
→ `reqmod/h1/preview.rs` → `reqmod/ftp/mod.rs`（本仓库为审计场景做的扩展最集中在这里）。

---

## 3. 核心对象模型

```rust
IcapServiceConfig            // 一个 ICAP 服务的配置（url + 池 + preview 策略 + bypass 等）
      │ Arc
IcapServiceClient            // 客户端实体：内部 spawn 连接池任务，缓存 OPTIONS
      │ 被包装
IcapReqmodClient / IcapRespmodClient   // 面向协议的入口，如 h1_adapter()、ftp_upload_audit_adapter()
      │ 每次上报前构造
HttpRequestAdapter / SmtpMessageAdapter / ImapMessageAdapter / FtpUploadAdapter
      │ set_xxx() 注入采集信息 → xfer()/audit_and_forward() 执行上报
```

生命周期要点：

1. `IcapServiceClient::new()` 启动后台池任务（`service/pool.rs`）。
2. 每次协议适配先 `fetch_connection()`：池里取空闲连接；取不到就新建 TCP/TLS 连接并
   **立即发一次 OPTIONS**（`service/client.rs:56`），拿到 `IcapServiceOptions`
   （`preview` 大小、`Allow: 204/206` 能力、`ISTag`、`Options-TTL`）。
3. 上报结束后若服务器未要求 `Connection: close`，连接回池复用（keep-alive）。

---

## 4. ★ 信息是如何"采集"的（g3proxy 侧）

本库自身**不主动采集**任何信息，所有上下文由调用方（g3proxy 的 `src/inspect/` 各协议任务）
在发起上报前通过 `set_*` 方法注入。这是新手最容易混淆的一点：

| 采集项 | 注入方法 | 定义位置 | 采集来源（g3proxy 侧） |
|--------|----------|----------|------------------------|
| 客户端地址 | `set_client_addr(SocketAddr)` | 各 Adapter | 代理接入连接的远端地址 |
| 认证用户名 | `set_client_username(ArcStr)` | 各 Adapter | 代理认证（Basic 等）后的用户名 |
| 连接五元组 | `set_connection_tuple(ConnectionTuple)` | `reqmod/mod.rs:31`（本机扩展，注释 `added by wming for repid audit`） | HTTP 转发链路 `g3proxy/src/inspect/http/v1/forward/mod.rs:262`、v2 `forward/mod.rs:318`、FTP 数据通道 `inspect/ftp/upload_data.rs:215`、TLS 数据通道 `inspect/tls/mod.rs:708` |
| TLS 密钥日志 | `set_keylog_buffer(Arc<TlsKeyLogBuffer>)` | `reqmod/h1/mod.rs:154`（本机扩展） | TLS 握手时生成（`inspect/tls/modern.rs:88`、`inspect/start_tls/tls.rs:77`、TLCP 同），含 TLS 版本、加密套件、server_random、各密钥派生标签的 secret |
| 共享 HTTP 头 | 配置项 `respond_shared_names` | `service/config/mod.rs:42` | ICAP 服务器响应中同名头会被回传给 g3proxy（`ReqmodResponse::take_shared_headers`） |

`ConnectionTuple` 结构（`reqmod/mod.rs`）：

```rust
pub struct ConnectionTuple {
    pub server_addr: SocketAddr,   // 代理侧（本地）地址
    pub remote_addr: SocketAddr,   // 远端服务器地址
    pub protocol: ConnectionProtocol, // Tcp=6, Udp=17（IANA 协议号）
}
```

---

## 5. ★★ 上报的数据格式（重点）

### 5.1 整体线格式（wire format）

一次 REQMOD 上报在 TCP 流上是**一段 ICAP 头 + 一段封装的 HTTP 报文**，中间用一个空行分隔：

```
REQMOD icap://icap-server.example.com/avcheck ICAP/1.0␍␊        ← 请求行（config 生成，
Host: icap-server.example.com␍␊                                     见 write_header）
User-Agent: g3proxy/...␍␊
Authorization: Basic cHJveHk6cHdA␍␊                                ← 可选，URL 中带 user:pass 时
X-Transformed-From: HTTP/1.0␍␊                                   ← 扩展头区（采集信息）
X-Client-IP: 10.0.0.5␍␊
X-Client-Port: 52334␍␊
X-Client-Username: alice␍␊
X-Authenticated-User: TG9jYWw6Ly9hbGljZQ==␍␊                       ← base64("Local://alice")
X-Proxy-IP: 172.16.0.2␍␊
X-Proxy-PORT: 8080␍␊
X-Remote-IP: 93.184.216.34␍␊
X-Remote-PORT: 443␍␊
X-Proto-P: 6␍␊
X-TLS-VERSION: TLSv1_3␍␊
X-TLS-CIPHER: TLS_AES_256_GCM_SHA384␍␊
X-TLS-SERVER_RANDOM: 3a7f...␍␊
X-TLS-CLIENT_HANDSHAKE_TRAFFIC_SECRET: <client_random> <hexsecret>␍␊
Allow: 204, 206␍␊                                                  ← 视协议/配置而定
Encapsulated: req-hdr=0, req-body=246␍␊                           ← 封装偏移量
Preview: 1024␍␊                                                   ← preview 模式才有
␍␊
POST /upload/file.bin HTTP/1.1␍␊     ← 从 req-hdr=0 偏移起：原始（或改写）HTTP 头字节
Host: example.com␍␊
...
␍␊
9␍␊                                  ← req-body 指向的偏移起：HTTP 体，chunked 编码
Hello ICAP␍␊
0␍␊
␍␊
```

序列化由三部分拼接（以 HTTP h1 为例，`reqmod/h1/preview.rs:24` 与
`reqmod/h1/forward_header.rs`）：

1. `partial_request_header`：请求行 + Host + User-Agent + Authorization
   （`IcapServiceConfig::build_request_header()`，连接创建时算一次复用）；
2. `push_extended_headers()`：所有采集信息头（`serialize/header.rs`）；
3. `Encapsulated: ...`（+ 可选 `Preview:`）+ 空行 + 封装 HTTP 报文。

封装的 HTTP 请求头字节由调用方提供（`HttpRequestForAdaptation::serialize_for_adapter()`），
长度即 `req-body` 的偏移值；请求体一律**重新按 chunked 编码**上报，与客户端原始的
Content-Length / chunked / 无限流无关。

### 5.2 采集信息头字段一览（ICAP 扩展头，RFC 3507 §4.4 / 4.6）

| 头部名 | 值格式 | 出处 | 说明 |
|--------|--------|------|------|
| `X-Transformed-From` | `HTTP/1.0` / `SMTP` / `IMAP` / `FTP` | 各 Adapter | 标识被封装的原始协议 |
| `X-Client-IP` / `X-Client-Port` | IP / 数字 | `serialize/header.rs:54` | 发起请求的客户端地址 |
| `X-Client-Username` | 明文用户名 | `serialize/header.rs:59` | 认证用户名 |
| `X-Authenticated-User` | base64(`Local://<user>`) | 同上 | 兼容 ICAP 生态（如 Squid）的认证头 |
| `X-Proxy-IP` / `X-Proxy-PORT` | IP / 数字 | `serialize/header.rs:17`（本机扩展） | 代理本机（server 侧）地址 |
| `X-Remote-IP` / `X-Remote-PORT` | IP / 数字 | 同上 | 上游目标服务器地址 |
| `X-Proto-P` | `6`(TCP) / `17`(UDP) | 同上 | IANA 协议号，供审计服务关联五元组（repid audit） |
| `X-TLS-VERSION` | 如 `TLSv1_3` | `serialize/header.rs:27`（本机扩展） | TLS 版本 |
| `X-TLS-CIPHER` | 如 `TLS_AES_256_GCM_SHA384` | 同上 | 协商的加密套件 |
| `X-TLS-SERVER_RANDOM` | hex | 同上 | ServerHello random |
| `X-TLS-<LABEL>` | `<client_random> <hex secret>` | `g3-types/src/net/tls/keylog.rs:195` | 每条 NSS keylog 一个头，如 `X-TLS-CLIENT_TRAFFIC_SECRET_0`，供审计侧解密流量 |
| `Allow` | `204` / `204, 206` | 各 Adapter | 本请求**只接受**哪些响应码；preview 请求刻意不带，避免 100-continue 后又收到 204/206 |
| `Encapsulated` | `req-hdr=0, req-body=<off>` 等 | 各 Adapter | 封装报文头/体在 ICAP 消息体中的字节偏移 |
| `Preview` | 字节数 | `reqmod/h1/preview.rs:31` | 本次只发送前 N 字节预览，等服务器回 `100 Continue` 再续传 |

> 注意控制字符清洗：keylog 头值中的 ASCII 控制字符会被替换为空格
> （`serialize/header.rs:43`），防止头部注入。

### 5.3 各协议的封装差异

虽然框架相同，但**封装进 ICAP 体的"伪 HTTP 报文"因协议而异**：

**HTTP h1/h2**（`reqmod/h1/mod.rs:159`，`reqmod/h2/mod.rs`）

- `X-Transformed-From: HTTP/1.0`（h2 同样如此标注）
- 封装真实方法/URI/头的序列化请求；`Encapsulated: req-hdr=0, req-body=<len>`
- 支持 Preview 模式（见 5.5）。

**SMTP**（`reqmod/smtp/mod.rs:66`）

```
PUT / HTTP/1.1␍␊
Content-Type: message/rfc822␍␊
X-SMTP-From: alice@example.com␍␊
X-SMTP-To: bob@example.com␍␊          ← 每个收件人一条
␍␊
<DATA 阶段的邮件正文，去点转义后按 chunked 重编码>
```
ICAP 头带 `X-Transformed-From: SMTP`；暂不支持 preview。

**IMAP APPEND**（`reqmod/imap/mod.rs:68`）

```
PUT / HTTP/1.1␍␊
Content-Type: message/rfc822␍␊
Content-Length: <literal_size>␍␊       ← literal 精确字节数
␍␊
<邮件原文>
```
ICAP 头带 `X-Transformed-From: IMAP`。

**FTP 上传审计**（本机扩展，`reqmod/ftp/mod.rs:143`）

```
PUT /pub/incoming/file.zip HTTP/1.1␍␊
Host: localhost␍␊
Content-Type: application/octet-stream␍␊
X-FTP-Command: STOR␍␊
␍␊
<数据通道文件内容，chunked>
```
ICAP 头带 `Allow: 204`、`X-Transformed-From: FTP`，并带五元组/keylog 扩展头。
特点：**审计失败绝不阻断上传** —— ICAP 写失败/读超时时回退为
`OriginalTransferredAfterFallback`，原始字节仍转发上游（企业审计场景的安全网）。

### 5.4 响应格式（ICAP 服务器 → 本库）

`ReqmodResponse::parse()`（`reqmod/response.rs:47`）解析状态行 + 头部：

- `204 No Modification`：内容无需改动，原样转发（最常见的"放行"）。
- `200 OK` + `Encapsulated:`：服务器给出改写结果或**替代响应**：
  - `req-hdr=0, req-body=N` / `req-hdr=0, null-body=N` → 改写后的 HTTP **请求**；
  - `res-hdr=0, res-body=N` / `res-hdr=0, null-body=N` → 要求代理直接返回给客户端的
    HTTP **错误响应**（`ReqmodAdaptationEndState::HttpErrResponse`）；
  - `null-body=0` → 无载荷的 2xx，等同放行。
  解析逻辑见 `reqmod/payload.rs`。
- `100 Continue`：preview 模式的中间响应（见下）。
- `206 Partial Modification`：当前实现明确**不支持**（`preview.rs:304` 返回
  `NotImplemented`）。
- `Connection: close`：连接不回池。
- 命中 `respond_shared_names` 配置的响应头会被收集，经
  `ReqmodAdaptationRunState::take_respond_shared_headers()` 交还 g3proxy
  （用于审计侧向客户端回写自定义头）。

### 5.5 Preview（预检）机制

ICAP 允许"先发一小段，服务器决定要不要看全文"：

1. 新连接建立时 `OPTIONS` 响应里的 `Preview: <size>` 头给出服务器可接受的预览大小
   （`options/response.rs:205`）；配置 `disable_preview` 可关掉。
2. 有 body 的 h1 请求：读客户端 body 前 N 字节 → 带 `Preview: N` 头发送 → 等响应：
   - `100 Continue`：继续把剩余 body 以 chunked **双向流水线**发完，同时收结果
     （`bidirectional.rs`）；
   - `204`：直接放行，已读的 preview 与剩余 body 原样转发上游（不再等 ICAP）；
   - `200`：按 Encapsulated 处理改写/错误响应。
3. 读 preview 期间受 `preview_data_read_timeout`（默认 4s）与 idle 检查约束。

---

## 6. 配置（YAML，g3proxy 侧）

```yaml
services:
  - name: icap-audit
    reqmod:                        # 或 respmod
      url: icaps://user:pass@icap.example.com:1344/reqmod-service
      # icap:// 明文，icaps:// 走 TLS（rustls）
      connection_pool:
        max_cached_per_server: 16
        idle_ttl: 30s
      icap_max_header_size: 8KiB   # 默认 8192
      disable_preview: false       # true 时全量上报
      preview_data_read_timeout: 4s
      respond_shared_names:        # ICAP 响应里要回传给代理的头
        - X-Scan-Verdict
      bypass: false                # true: ICAP 失败时直接放行（降级开关）
      tls_client:
        trusted_certs: /etc/g3/ca.pem
      tcp_keepalive: ...
```

解析入口：`service/config/yaml.rs`（`parse_reqmod_service_yaml` / `parse_respmod_service_yaml`，
也可以直接给一个 URL 字符串用默认值）。

---

## 7. 动手体验（新手路径）

1. **起一个 ICAP 服务器**：如 c-icap / Squid icap 示例服务，监听 1344。
2. **跑压测样例**（它同时是一个手写的"最小上报报文"教材，直接展示了
   `Encapsulated: req-hdr=0, req-body=<off>` + chunked body 的拼法）：
   ```bash
   cargo run --example icap_perf_test          # examples/icap_perf_test.rs
   ```
3. **抓包看格式**：`tcpdump -A -s0 port 1344`，对照 §5.1 逐行辨认扩展头与偏移。
4. **单步跟踪一条上报**：从 `g3proxy` 的
   `inspect/http/v1/forward/adaptation.rs`（set_connection_tuple → h1_adapter → xfer）
   进入本库 `HttpRequestAdapter::xfer`，观察 `build_preview_request` 与
   `send_preview_data` 的字节拼装顺序。
5. 单元测试/文档测试：`cargo test -p g3-icap-client`。

---

## 8. 常见坑

- **偏移量错位**：`Encapsulated` 的 `req-body` 偏移是相对 ICAP 头之后封装报文起点的
  字节数，改封装头（如追加 X- 头）必须同步重算，否则服务器解析失败。
- **body 必须 chunked**：不论客户端原来是什么传输编码，上报 ICAP 的 body 一律重编码为
  chunked，并以 `0␍␊␍␊` 结束（小 body 路径 `xfer_small_body_chunked` 也如此）。
- **Allow 与响应码必须匹配**：请求声明 `Allow: 204` 却返回 200 会被判为
  `IcapServerErrorResponse`；FTP 审计固定 `Allow: 204`（只关心放行，不改变行为）。
- **206 不支持**：带 preview 请求收到 206 直接报 `NotImplemented`。
- **连接池取连接超时 5s**：池里陈旧连接的 poller 已退出时不会永久挂起
  （`service/client.rs:47`），排查"上报卡住"时可先看 ICAP 服务端是否半关闭。
- **keylog 是敏感数据**：`X-TLS-*` 头会把解密秘密发给 ICAP 服务，网络路径与
  ICAP 服务器的保管能力要按密钥级别评估；控制字符已被过滤但信任边界仍是明文头。
- 本机扩展（注释 `added by wming for repid audit` / `X-Proxy-IP` 等）不在上游
  标准 g3 中，与上游合并时注意保留。

---

## 9. 延伸阅读

- RFC 3507（ICAP）：REQMOD/RESPMOD/OPTIONS、Encapsulated、Preview、X- 头约定
- 库内相邻依赖：`g3-http`（chunked 编解码 `H1BodyToChunkedTransfer`）、
  `g3-types`（`TlsKeyLogBuffer`、`HttpHeaderMap`）、`g3-io-ext`（`StreamCopy`/idle 检查）
- 调用方总览：`g3proxy/src/inspect/`（HTTP v1/v2、SMTP、IMAP、FTP、TLS 各采集链路）
