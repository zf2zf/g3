# HTTP 旁路上传审计（ICAP bypass audit）设计

日期：2026-11-01
状态：待批准
范围：`lib/g3-icap-client`（新增公共管线、FTP 下沉）、`g3proxy`（HTTP/1、HTTP/2 两处接入点）

## 1. 意图与背景

项目已为 FTP 代理定制了 ICAP 上传审计（repid 审计场景）：FTP 数据通道的上传字节流被
伪装成 `PUT <path> HTTP/1.1` 请求，走标准 REQMOD 通道送给 ICAP 服务，同时原样转发给上游。
该通路的核心语义是 **fail-open 旁路审计**：ICAP 任何故障（头写失败、连接断、判决慢）只降级
审计，绝不阻断上传；判决在后台任务读取，不影响数据流。

现在要对 HTTP 协议（HTTP/1 与 HTTP/2）做同样的处理。经与需求方确认：

- **ICAP 对 HTTP 不拦截、不改写**，仅采集请求数据作为旁路，供后续离线审计；
- **上报格式与 FTP 保持一致**：同一套扩展头（四元组、TLS keylog、客户端地址等）与
  req-hdr + chunked req-body 的封装结构，让审计服务端对所有协议看到统一 schema；
- 审计策略与 FTP 相同（fail-open、不阻断、判决后台化）。

## 2. 目标 / 非目标 / 反目标

**目标**

- G1：HTTP/1、HTTP/2 携带请求体的请求，其 body 在照常转发上游的同时流式送 ICAP 审计；
  ICAP 任何故障不影响 HTTP 请求本身。
- G2：上报报文 schema 与 FTP 通路一致（见 §7 格式清单），协议来源用
  `X-Transformed-From` 区分（FTP 保持 `FTP`，HTTP 沿用现值 `HTTP/1.0`、`HTTP/2.0`）。
- G3：把 FTP 实现中与协议无关的管线部分下沉为公共模块，FTP 重构为第一个使用者，
  HTTP h1/h2 复用同一管线；行为对 FTP 完全无变化。
- G4：管线结构上为响应方向（下载）审计预留扩展位（本期不实现）。

**非目标**

- N1：不做响应方向（respmod）采集；现有 respmod 代码与接线保持原样，本设计不触碰。
- N2：不做无请求体请求的送检（GET 等完全不碰 ICAP；现通路"header-only 上报"行为在新通路上取消）。
- N3：不做 CONNECT 隧道内 HTTP 的审计（FTP-over-CONNECT 已有独立审计桥，维持现状）。
- N4：不删除 `g3-icap-client` 中标准 h1/h2 REQMOD 拦截/改写库代码（保留以便与上游合并；
  g3proxy 侧不再调用其 reqmod 拦截路径）。

**反目标**

- A1：绝不因 ICAP 故障导致 HTTP 请求失败、变慢或语义变化。
- A2：绝不因审计使堆占用随被审计 body 大小增长（固定缓冲流式管线）。
- A3：绝不改变 FTP 通路的对外行为（重构必须行为等价）。

## 3. 约束

- 本仓库是 g3 fork（基线上游 v1.13.0），本地扩展需保持集中、可标记，便于后续同步上游；
  新公共模块作为独立目录新增，对上游 h1/h2 适配器文件零改动。
- Rust / tokio；公共层放在 `g3-icap-client`（只管协议与管线），g3proxy 只做业务接线，
  与现有分层一致。
- ICAP 连接来自 `IcapServiceClient` 连接池，判决与 keep-alive 决定回收，规则沿用 FTP 现状
  （2xx + keep-alive + 排空干净才回收）。

## 4. 方案与取舍

- **方案 A（采纳）**：下沉协议无关"旁路审计管线"到 `g3-icap-client` 新模块，协议差异收敛为
  "封装输入"（req-hdr 字节 + 扩展头参数），FTP 先重构接入，HTTP h1/h2 再接入。
  一条管线、两协议行为严格一致、响应方向只需新增封装输入。代价：动 FTP 在产代码，需回归。
- 方案 B（否）：HTTP 复制一份独立 fail-open 适配器，FTP 不动。双管线长期双倍维护，违背复用意图。
- 方案 C（否）：在现有 h1/h2 适配器上加 audit-only 开关。旧 xfer 深度绑定"等判决/可改写"语义，
  改造风险高于下沉新管线，且旧语义代码沦为死路。

## 5. 公共管线设计（`lib/g3-icap-client/src/reqmod/bypass/`）

新模块名：`bypass`（`reqmod::bypass`），核心类型：

```text
BypassAdapter<I: IdleCheck>          // 由 IcapReqmodClient::bypass_adapter() 构造，
                                     // 构造时即从池取 ICAP 连接
  · set_client_addr / set_client_username / set_connection_tuple / set_keylog_buffer
  · audit_and_forward(state, framing, clt_r, ups_w) -> BypassEndState
  · audit_only(state, framing, clt_r)               -> BypassEndState   // 保留 FTP 隧道用法
BypassFraming {                      // 协议差异的全部输入
  req_hdr: Vec<u8>,                  // 封装区 req-hdr 字节（FTP=伪 PUT 头；HTTP=真实请求头序列化）
  transformed_from: &'static str,    // "FTP" | "HTTP/1.0" | "HTTP/2.0"
}
BypassEndState / BypassErrorKind     // 由现 FtpAdaptationEndState / FtpAdaptationErrorKind 泛化，
                                     // 变体与语义不变
```

管线内部逻辑整体取自现 `reqmod/ftp/mod.rs`，不做行为改动：

1. `send_icap_header`：`ICAP/1.0 REQMOD <uri>` 前缀 + 扩展头
   （`Allow: 204`、`X-Transformed-From: <framing.transformed_from>`、client addr、username、
   五元组、keylog）+ `Encapsulated: req-hdr=0, req-body=<len>` + req-hdr 字节，
   一次 `write_all_vectored` 发出；首发失败退化为 forward-only 纯转发。
2. 中继循环：固定缓冲（`max(copy_config.buffer_size(), 256KiB)`）读客户端 → 先写上游 →
   复制进有界 chunk 通道（容量 64，背压天然节流读速）。
3. ICAP 后台写任务：聚合 chunk（16 块或 4MiB 批量落盘）、并发排空 ICAP 读侧防 echo 死锁、
   捕获响应头供后续解析；结束后写 `0\r\n\r\n` 终止标记。上游写失败是唯一终止路径。
4. 判决后台读取：上传完成后立即返回 `OriginalTransferredInBackground`，判决解析、
   body 排空、连接回收在带 300s 总超时的后台任务里完成。
5. 空闲语义由调用方传入的 `IdleCheck` 决定（同现 FTP 的 `CountingIdleChecker`）。
6. **并发上限（HTTP 场景新增）**：ICAP 连接的获取经由调用方持有的并发许可（tokio
   `Semaphore`，容量来自配置项，默认 64）。许可耗尽时 HTTP 请求**直接跳过审计、照常
   转发**（fail-open，计入"跳过"指标），不排队等待——排队违背 A1。FTP 通路保持现行为
   （不受该上限约束，或设为足够大的独立容量）。

错误面六分类（ClientRead / UpstreamWrite / IcapWrite / IcapRead / ForceQuit / Internal）与
`FtpAdaptationEndState` 各变体逐一对应保留。

### 5.1 FTP 下沉（行为等价重构）

`reqmod/ftp/mod.rs` 变薄：保留 `IcapReqmodClient::ftp_upload_audit_adapter()` 入口与
`FtpUploadAdapter`/`FtpAdaptationEndState`/`FtpAdaptationError*` 的公开名（类型别名或
1–2 行包装），把 `build_http_header("PUT …")` 与 `X-Transformed-From: FTP` 收敛为
`BypassFraming` 构造。原 ftp 模块内的单元测试（`append_chunk_header` 等）随逻辑迁移。

### 5.1.1 g3proxy 层：审计桥下沉

`serve/ftp_proxy/audit_bridge.rs` 实际已是跨模块公共件（`serve/http_proxy/task/connect/task.rs`
与 `inspect/ftp/upload_data.rs` 均跨模块引用），本次整体下沉为
`g3proxy/src/serve/audit_bridge.rs`（去 FTP 前缀命名：`UploadAuditContext`、
`run_upload_audit_or_relay{,_bidi}`）：

- 随之下沉（协议无关）：`CountingIdleChecker`、`bidi_half_relay_with_idle`（含 TCP 零窗口
  stall 修复）、`raw_forward_with_idle`、两个 relay 入口、上下文结构。
- `UploadAuditContext` 的 FTP 特有字段 `ftp_command`/`ftp_path` 改为携 `BypassFraming`
  输入（req-hdr 字节 + 协议来源标签）+ 并发许可句柄（可选）；其余字段不变。
- 留在 ftp_proxy：`build_audit_context`（依赖 FTP `CommonTaskContext`）及把
  command/path 组装成 framing 的调用方逻辑；`upload_state.rs`、`connect_bridge.rs`、
  `task.rs`、`ctl_common.rs`、`server.rs`、`stats.rs` 均为 FTP 业务，不动。
- 调用方迁移：`serve/ftp_proxy/task.rs`、`serve/ftp_proxy/connect_bridge.rs`、
  `inspect/ftp/upload_data.rs`、`serve/http_proxy/task/connect/task.rs` 改引新路径，
  行为不变；HTTP 两个新接入点（§5.2/§5.3）与它们共用此桥。

### 5.2 HTTP/1 接入点

两处：`g3proxy/src/serve/http_proxy/task/forward/task.rs`（显式/透明代理）与
`g3proxy/src/inspect/http/v1/forward/mod.rs`（TLS 拦截后的 h1）。新逻辑：

- **触发**：进入 reqmod 送检位置且请求带 body（`Content-Length > 0` 或
  `Transfer-Encoding: chunked`）。不满足则完全不碰 ICAP（替代现"header-only 上报"路径）。
- **req-hdr**：复用现 `HttpRequestForAdaptation` 的请求头序列化能力（真实请求行 +
  转发头集合），产出与上游所见一致的字节；请求行形态保持与现有 wming HTTP 上报完全
  一致（审计服务端已按此格式解析）。
- **管线**：`BypassAdapter::audit_and_forward(state, framing, clt_r, ups_w)` 替换现有
  `icap_adapter.xfer(...)` 的调用；`clt_r` 传入**解码后的 body 读取端**（h1 即
  `HttpBodyReader`，chunk trailer 由其自行消费；Content-Length 与 chunked 两种 body
  类型统一走这一条路，普通转发路径本来就是解码后重新成帧，无语义损失）。
- **小 body 全缓冲路径同样送检**：`run_without_adaptation` 中"整个 body 已在内存、
  可换连接重试"的 `run_with_all_body` 分支不豁免审计——内存字节直接作为 body 源喂给
  管线（`Cursor` 链接或直接 buffer 输入，具体适配留给实现），保证审计覆盖不按体积分档。
- **判决**：`BypassAdaptationEndState` 仅用于打点与日志（审计字节数、ICAP 状态码），
  不回写响应、不影响任务结果；中途失败/上游提前响应时管线行为与 FTP 一致
  （写终止标记、判决后台化、截断记日志）。

### 5.3 HTTP/2 接入点

两处：`serve/http_proxy/task/forward` 的 h2 分支与 `inspect/http/v2/forward`。同样只处理
带 DATA 帧 body 的流（`is_end_stream()` 为 false）。per-stream 粒度：每条有 body 的流
构造一个 `BypassAdapter`。req-hdr 序列化沿用现 h2 适配器把 `:method/:path/头` 展开成
HTTP/1 形态文本的做法（该逻辑在 `bypass` 内由调用方提供 framing 字节，不搬库代码）。

**各接入点扩展头取值（统一约定）**：四元组一律取该请求实际收发两端的 socket 地址
（客户端↔g3proxy 用 X-Client-*，g3proxy↔真实上游/下一跳用 X-Proxy-IP/X-Remote-IP 系列，
显式代理的下一跳即真实服务器）；keylog 仅在该通路握有 TLS 会话密钥日志时附带
（TLS 拦截/解密路径有，明文 h1 客户端侧无），与现有 wming 各入口的实际取值方式保持一致。

### 5.4 body 字节语义（关键设计结论）

ICAP req-body 封装采用 chunked 分块重新编码（管线自己写 `hex-len\r\n<data>\r\n`），因此
**管线输入的 body 必须是解码后的裸内容字节**，与 FTP 裸流语义一致，审计服务端看到的
req-body 就是文件内容本身。经代码核实，g3proxy h1 普通转发路径本身就是
`HttpBodyReader` 解码后再向上游重新成帧（`serve/http_proxy/task/forward/task.rs` 的
`run_without_adaptation`），因此：

- h1 `Content-Length` 与 `Transfer-Encoding: chunked` **统一**：`clt_r` 传解码后的
  body 读取端，管线直接 `audit_and_forward` 接管转发+审计双写，不存在"保留客户端
  原始成帧"的兼容问题；chunk trailer 由 `HttpBodyReader` 消费，无残留字节风险。
- h2：`RecvStream` 帧解码后的 DATA 字节天然是裸流；上游写侧用现有 h2 send 句柄包装成
  `AsyncWrite`（调用方适配，模式同现 `HttpForwardWriterForAdaptation`）。
- `audit_only` 变体保留给 CONNECT 隧道类调用方（FTP-over-CONNECT 现用法），HTTP 两个
  forward 接入点不使用它。

### 5.5 配置与开关

- 复用现有门控链：server 的 `do_task_audit` → auditor 的 `task_audit_ratio` 抽样 →
  auditor `icap_reqmod_service` 存在。命中后行为即本设计的旁路审计；不新增配置键。
  FTP 式"转发但审计失败不阻断"不需要独立开关，因为新通路只有这一种行为。
- **对现有 h1/h2 REQMOD 拦截/改写通路的替代是无条件的、不留旧路径开关**——需求方已
  确认部署中不存在依赖 ICAP 拦截/改写 HTTP 的规则（"ICAP 不对 HTTP 拦截、改写，仅采集"）。
- `disable_preview`、preview 语义：旁路管线不做 preview、不等判决，`icap_reqmod_service`
  的 `Preview` OPTIONS 结果被忽略（对齐 FTP）。
- 并发上限配置：HTTP 旁路审计的并发许可数以服务器配置键
  `upload_audit_max_concurrency` 控制（默认 64，0 表示不设限），信号量由共享审计桥持有、
  按 server 实例隔离；不满足许可即跳过审计。FTP 通路不接该信号量，维持现行为。

## 6. 错误处理与观测

- 管线内部 warn 日志格式对齐现 FTP 通路（`"HTTP ICAP header send failed, fallback …"` 等），
  按协议来源标注。
- 任务打点：审计字节数、降级次数（header 写失败/通道关闭/判决解析失败三类计数器）、
  **超限跳过审计次数**（并发许可耗尽直接旁路放过的请求数），挂现有 task stats；
  具体字段命名留给实现计划。
- 后台判决任务带总超时（同现 300s），ICAP 服务挂死不泄漏连接。

## 7. 上报格式清单（与 FTP 对齐的最终 schema）

```text
ICAP/1.0 REQMOD <service-uri>
Method: <原方法>                       ← HTTP 场景封装区内是真实请求行，无此头；FTP 无
Connection: keep-alive                  ← 池管理自带
Allow: 204
X-Transformed-From: FTP | HTTP/1.0 | HTTP/2.0
X-Client-IP / X-Client-Port
X-Username（如有）
X-Proxy-IP / X-Proxy-PORT / X-Remote-IP / X-Remote-PORT / X-Proto-P
X-TLS-VERSION / X-TLS-CIPHER / X-TLS-SERVER_RANDOM / X-TLS-KeyLog…（如启用 keylog）
Encapsulated: req-hdr=0, req-body=<len>

封装区：
  req-hdr  = FTP: "PUT <path> HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nX-FTP-Command: STOR\r\n\r\n"
             HTTP: 真实请求行 + 转发头部序列化
  req-body = 解码后 body，chunked 重编码流，"0\r\n\r\n" 结束
```

## 8. 遗留为实现者决定（已标注）

- `bypass` 模块与类型最终命名。
- 小 body 全缓冲路径的管线输入形式（`Cursor` 链接 vs 直接 buffer API）。
- metrics 字段命名。
- h2 framing 序列化逻辑是复制现适配器小函数还是在 `bypass` 内重写（倾向由调用方提供
  字节的薄适配，不动上游文件）。
- 并发信号量在共享审计桥中的具体挂点与许可归还时机（构造 adapter 失败也要归还）。

## 9. 验证方案

- 单元测试：`bypass` 管线对 mock ICAP 服务（tokio TcpListener 假服务）跑通
  正常/204、echo 并发排空、头写失败降级、慢判决后台化、连接回收条件五类路径。
- FTP 回归：`etc/g3proxy/ftp` 场景 + 假 ICAP，比对重构前后上报报文逐字节一致
  （现有调试日志已打印完整 ICAP 请求头，可用作文本 diff 依据）。
- HTTP 手工验证：`etc/g3proxy` 本地栈 + curl POST（fixed-length / chunked）与
  h2 上传（curl --http2 -T），检查假 ICAP 收到的 framing/body 与 fail-open
  （中途 kill ICAP 进程，确认上传不受影响、仅日志降级）。
- `cargo test -p g3-icap-client`、`cargo build` 全 workspace。
