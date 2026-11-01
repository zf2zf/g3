# HTTP ICAP 旁路上传审计 Implementation Plan

> **执行状态（2026-11-02 回写）**：Task 1–10 全部完成，落在 `186f1e61..df2d6e66`（10 个提交，
> 含最终评审修复 `df2d6e66`：客户端断流/空闲超时不再把未收尾的请求体上报为完整）。全分支新鲜视角
> 评审已做过，Critical/Important 均已修复并有 RED→GREEN 测试。下方步骤勾选框是执行时未逐步回写，
> 以 `git log` 与 `doc/http-icap-bypass-audit.md` 为准。一处计划步骤在本机不可执行：全 workspace
> `cargo build/test`（macOS 上 c-ares-sys 缺系统库、`g3-journal` 用 Linux 独有 `memfd_*`），
> 实际验证范围为 `cargo test -p g3-icap-client` 与 `cargo build|test -p g3proxy --features vendored-c-ares`。

**Goal:** 把 FTP 的 fail-open ICAP 旁路审计语义推广到 HTTP/1 与 HTTP/2：下沉协议无关旁路管线与共享审计桥，并在三个 HTTP 接入点替换旧 REQMOD 拦截通路。

**Architecture:** `g3-icap-client` 新增 `reqmod::bypass` 通用管线（FTP 逻辑平移，协议差异收敛为 `BypassFraming`）；`g3proxy` 层把 `serve/ftp_proxy/audit_bridge.rs` 泛化下沉为 `serve/audit_bridge.rs`；三个 HTTP 接入点（serve/http_proxy forward h1、inspect/http v1 forward、inspect/http v2 forward）改走旁路管线，并发许可与跳过计数挂在 `AuditHandle`。

**Tech Stack:** Rust / tokio / g3-icap-client / g3-http / g3-h2 / g3_io_ext（GaugeSemaphore、IdleCheck）。

**Spec:** `docs/superpowers/specs/2026-11-01-http-icap-bypass-upload-audit-design.md`

> 对 Spec 的两处有意偏差（执行时按本计划）：
> ① Spec §5.3 说 h2 有 serve/http_proxy 分支——代码核实不存在，h2 接入点只有 `inspect/http/v2/forward`；
> ② Spec §5.5 把 `upload_audit_max_concurrency` 放在 HTTP server 配置——改为放 auditor 配置并挂 `AuditHandle`，因为 serve 与 inspect 两条体系只共享 `AuditHandle`，放 server 配置覆盖不到 inspect 入口。

## Global Constraints

- 旁路管线行为整体平移自 `lib/g3-icap-client/src/reqmod/ftp/mod.rs`，禁止顺手改写中继/排空/回收逻辑（反目标 A3：FTP 行为等价）。
- 不修改 `reqmod/h1`、`reqmod/h2`、`respmod/*` 既有文件（N4：库代码保留但 g3proxy 不再调用 reqmod 拦截路径）。
- 缓冲下限 `max(copy_config.buffer_size(), 256*1024)`；chunk 通道容量 64；聚合 16 块 / 4MiB；后台判决总超时 300s；并发上限默认 64（0 = 不限）。
- `X-Transformed-From` 取值固定：FTP=`"FTP"`，h1=`"HTTP/1.0"`，h2=`"HTTP/2.0"`。
- 每个 Task 结束 commit；`cargo test -p g3-icap-client` 与 `cargo build -p g3proxy` 必须全绿才进下一个 Task。

## Review Focus

- ICAP 服务完全不可达（拒连/头写失败）→ 数据流照常转发，`EndState` 为 fallback 变体，日志降级 warn，不产生任务错误。→ Task 1 测试 `test_header_send_failure_falls_back_to_forward_only`。
- ICAP 判决极慢/挂死 → 转发与判决收尾解耦，主流程立即返回 `OriginalTransferredInBackground`，后台 300s 总超时不泄漏连接。→ Task 1 测试 `test_slow_verdict_returns_background_and_reclaims`。
- echo 型 ICAP 边收边回响应 → 并发排空 + 响应头捕获不死锁、判决仍可解析。→ Task 1 测试 `test_echo_service_concurrent_drain`。
- 并发许可耗尽 → 请求直接跳过审计照常转发（绝不排队），跳过计数 +1。→ Task 4 测试 `test_permit_exhaustion_skips_audit` + Task 5/6/7 各自 skip 分支。
- 客户端中途断流/上游提前响应 → ICAP 请求仍写 `0\r\n\r\n` 终止标记，无连接泄漏。→ Task 1 测试 `test_client_eof_midway_still_terminates_icap_request`。
- h1 chunked trailer、h2 流复位等异常 body 收尾 → 不阻塞主转发（trailer 由 `HttpBodyReader` 消费；h2 `into_async_read` 的错误按 ClientRead 面处理）。→ Task 5/7 代码走查项。

---

### Task 1: `reqmod::bypass` 通用管线模块

**Files:**
- Create: `lib/g3-icap-client/src/reqmod/bypass/mod.rs`
- Create: `lib/g3-icap-client/src/reqmod/bypass/error.rs`（内容来自 `reqmod/ftp/error.rs`，类型更名 `BypassAdaptationError` / `BypassErrorKind`）
- Modify: `lib/g3-icap-client/src/reqmod/mod.rs`（`pub mod bypass;`，与既有 `pub mod ftp;` 并列）
- Test: `lib/g3-icap-client/src/reqmod/bypass/mod.rs` 内 `#[cfg(test)]`（含 `append_chunk_header` 既有 6 个单测平移）

**Interfaces:**
- Consumes: `IcapReqmodClient`、`IcapServiceClient::fetch_connection/save_connection`、`ReqmodAdaptationRunState`（`reqmod::mail`）、`ConnectionTuple`、`TlsKeyLogBuffer`、`serialize::{add_client_addr,add_client_username,add_connection_tuple,add_keylog_headers}`。
- Produces（后续 Task 全部依赖这些名字）:

```rust
pub struct BypassFraming { pub req_hdr: Vec<u8>, pub transformed_from: &'static str }
pub enum BypassEndState {
    OriginalTransferred { icap_status_code: u16, icap_reason: String, bytes: u64 },
    AuditOnly { icap_status_code: u16, icap_reason: String, bytes: u64 },
    OriginalTransferredAfterFallback { bytes: u64, icap_error: String },
    OriginalTransferredInBackground { bytes: u64 },
}
pub struct BypassAdapter<I: IdleCheck> { /* 平移自 FtpUploadAdapter */ }
impl IcapReqmodClient {
    pub async fn bypass_adapter<I: IdleCheck>(&self, copy_config: StreamCopyConfig, idle_checker: I)
        -> anyhow::Result<BypassAdapter<I>>;
}
impl<I: IdleCheck> BypassAdapter<I> {
    pub fn set_client_addr(&mut self, addr: SocketAddr);
    pub fn set_client_username(&mut self, user: g3_types::metrics::ArcStr);
    pub fn set_connection_tuple(&mut self, tuple: ConnectionTuple);
    pub fn set_keylog_buffer(&mut self, buffer: Arc<TlsKeyLogBuffer>);
    pub async fn audit_and_forward<CR, UW>(self, state: &mut ReqmodAdaptationRunState,
        framing: BypassFraming, clt_r: &mut CR, ups_w: &mut UW) -> BypassEndState;
    pub async fn audit_only<CR>(self, state: &mut ReqmodAdaptationRunState,
        framing: BypassFraming, clt_r: &mut CR) -> BypassEndState;
}
pub fn new_run_state() -> ReqmodAdaptationRunState;
```

- [ ] **Step 1: 平移管线代码。** 把 `reqmod/ftp/mod.rs` 的实现整体拷入 `bypass/mod.rs`（含中文注释），差异仅四处：① 参数 `ftp_cmd/ftp_path: &str` 改为消费 `framing.req_hdr` 字节（`send_icap_header`/`audit_only` 内的 `build_http_header` 调用点）；② `push_extended_headers` 的 `X-Transformed-From: FTP` 改为 `framing.transformed_from`，并新增 `set_client_username` + `serialize::add_client_username` 分支（FTP 无 username 时行为不变）；③ 类型更名如上；④ 日志前缀从 `"FTP ICAP …"` 改为 `"Bypass ICAP …"`。`error.rs` 拷自 ftp 版并更名。
- [ ] **Step 2: 写 mock ICAP 假服务与失败测试。** 测试内起 `tokio::net::TcpListener`，用 `IcapServiceConfig`/`IcapReqmodClient::new` 指向它。实现 5 个 Review Focus 命名的 async 测试：`test_header_send_failure_falls_back_to_forward_only`（预置坏 listener 立即断连，断言返回 `OriginalTransferredAfterFallback` 且上游字节完整）、`test_echo_service_concurrent_drain`（listener 收到即回 204 + body echo，断言不死锁、端到端完成）、`test_slow_verdict_returns_background_and_reclaims`（listener 读完 5s 后才回 204，断言 `audit_and_forward` 立即返回 `OriginalTransferredInBackground`）、`test_client_eof_midway_still_terminates_icap_request`（listener 断言收到 `0\r\n\r\n` 终止标记）、`test_normal_204_audit_and_forward_counts_bytes`。
- [ ] **Step 3: `cargo test -p g3-icap-client` 全绿**（含平移过来的 `append_chunk_header` 6 个单测）。
- [ ] **Step 4: Commit** `git commit -m "icap-client: add protocol-agnostic bypass audit pipeline"`

### Task 2: FTP 适配器薄壳化（行为等价）

**Files:**
- Modify: `lib/g3-icap-client/src/reqmod/ftp/mod.rs` → 收缩为 ≤80 行；`lib/g3-icap-client/src/reqmod/ftp/error.rs` 删除
- Test: 既有 `cargo test -p g3-icap-client` 全绿即验收；新增 1 个测试断言 framing 字节

**Interfaces:**
- Consumes: Task 1 的 `BypassAdapter`/`BypassFraming`/`BypassEndState`/`BypassErrorKind`/`BypassAdaptationError`。
- Produces（保持现公开 API 不破坏 `g3proxy/src/serve/ftp_proxy/audit_bridge.rs` 的编译）:

```rust
pub type FtpAdaptationEndState = BypassEndState;
pub type FtpAdaptationError = BypassAdaptationError;
pub type FtpAdaptationErrorKind = BypassErrorKind;
pub struct FtpUploadAdapter<I: IdleCheck>(BypassAdapter<I>); // ftp_upload_audit_adapter() 仍返回它
impl<I: IdleCheck> FtpUploadAdapter<I> {
    pub async fn audit_and_forward<CR, UW>(self, state, clt_r, ups_w,
        ftp_cmd: &str, ftp_path: &str) -> FtpAdaptationEndState; // 内部 build_ftp_framing(cmd,path)
    pub async fn audit_only<CR>(self, state, clt_r, ftp_cmd: &str, ftp_path: &str) -> FtpAdaptationEndState;
    // set_client_addr / set_connection_tuple / set_keylog_buffer 直接透传
}
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState; // 仍导出
pub fn build_ftp_framing(ftp_command: &str, ftp_path: &str) -> BypassFraming; // 公开，供 g3proxy 组 context
```

- [ ] **Step 1:** 写 `build_ftp_framing(cmd, path) -> BypassFraming` 的字节断言测试：req_hdr 必须逐字节等于现 `build_http_header` 输出（`"PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nX-FTP-Command: {cmd}\r\n\r\n"`），transformed_from == `"FTP"`。
- [ ] **Step 2:** 实现薄壳与别名，删 ftp/error.rs 与重复实现。
- [ ] **Step 3:** `cargo test -p g3-icap-client` 全绿；`cargo build -p g3proxy` 通过（audit_bridge 还引用旧 API，必须未破）。
- [ ] **Step 4: Commit** `"icap-client: rebase FTP audit adapter onto bypass pipeline"`

### Task 3: g3proxy 审计桥下沉为 `serve/audit_bridge.rs`

**Files:**
- Create: `g3proxy/src/serve/audit_bridge.rs`（平移自 `serve/ftp_proxy/audit_bridge.rs`）
- Delete: `g3proxy/src/serve/ftp_proxy/audit_bridge.rs`
- Modify: `g3proxy/src/serve/mod.rs`（`pub(crate) mod audit_bridge;`）、`g3proxy/src/serve/ftp_proxy/mod.rs`（删模块声明）、`g3proxy/src/serve/ftp_proxy/task.rs:33`、`g3proxy/src/serve/ftp_proxy/connect_bridge.rs:37`、`g3proxy/src/inspect/ftp/upload_data.rs:23-26`、`g3proxy/src/serve/http_proxy/task/connect/task.rs:30-33`

**Interfaces:**
- Consumes: Task 1 `BypassFraming`、Task 2 保留的 `new_adaptation_run_state` 改用 `g3_icap_client::reqmod::bypass::new_run_state`。
- Produces:

```rust
pub(crate) struct UploadAuditContext {
    pub(crate) icap_client: Arc<IcapReqmodClient>,
    pub(crate) idle_wheel: Arc<IdleWheel>, pub(crate) max_idle_count: usize,
    pub(crate) copy_config: StreamCopyConfig, pub(crate) client_addr: Option<SocketAddr>,
    pub(crate) username: Option<ArcStr>,
    pub(crate) framing: BypassFraming,
    pub(crate) data_channel_tuple: Option<ConnectionTuple>,
    pub(crate) keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}
pub(crate) async fn run_upload_audit_or_relay<CR, UW>(...) -> Option<u64>;      // 原名直译
pub(crate) async fn run_upload_audit_or_relay_bidi<CR, CW, UR, UW>(...) -> Option<u64>;
```

`build_ftp_framing` 直接复用 Task 2 在 `reqmod::ftp` 公开的版本，g3proxy 侧不得重复实现。
`CountingIdleChecker`、`bidi_half_relay_with_idle`（保留零窗口修复注释）、`raw_forward_with_idle` 原样平移；内部 `audit_and_forward` 改用 `BypassAdapter::audit_and_forward(state, ctx.framing, …)`。

- [ ] **Step 1:** 平移 + 更名 + `ftp_command/ftp_path` 字段替换为 `framing`；4 个调用方 import 改路径，FTP 调用点在组 context 处填 `framing: build_ftp_framing(...)`。
- [ ] **Step 2:** `cargo build -p g3proxy && cargo test -p g3-icap-client` 全绿（FTP 通路无新增测试，等价性由 Task 2 字节断言 + 编译面保证）。
- [ ] **Step 3: Commit** `"g3proxy: lift FTP audit bridge to shared serve::audit_bridge"`

### Task 4: AuditHandle 并发许可 + 跳过计数 + auditor 配置键

**Files:**
- Modify: `g3proxy/src/config/audit/auditor.rs`（新字段 + 解析键 + 默认值）
- Modify: `g3proxy/src/audit/handle.rs`（信号量 + 计数）

**Interfaces:**
- Produces:

```rust
// auditor.rs AuditConfig 新字段：
pub(crate) upload_audit_max_concurrency: usize, // 默认 64；0 = 不设限
// 解析键 "upload_audit_max_concurrency" => as_usize（样式仿 auditor.rs 既有 usize 键）
// handle.rs AuditHandle 新API：
pub(crate) fn try_upload_audit_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit>;
    // 上限 0 时恒返回 Some；信号量用 Arc<tokio::sync::Semaphore>（或仓库惯用
    // g3_io_ext::GaugeSemaphore，样式见 auth/user.rs:179），try_acquire 失败即 None
pub(crate) fn mark_upload_audit_skipped(&self);  // 内部 AtomicU64 +1
pub(crate) fn upload_audit_skipped(&self) -> u64;
```

- [ ] **Step 1:** auditor.rs 失败测试：yaml 片段解析 `upload_audit_max_concurrency: 8` 后字段为 8、缺省为 64、非法值报错（若该文件无 test 模块则新建 `#[cfg(test)]`）。
- [ ] **Step 2:** 实现配置解析与 `AuditHandle` 三方法；`AuditHandle` 构造时按 auditor 配置初始化信号量。
- [ ] **Step 3:** 测试 `test_permit_exhaustion_skips_audit`：容量 1 的 handle，持有第一个 permit 后第二个 `try_upload_audit_permit()` 返回 None；`mark_upload_audit_skipped()` 计数可读。
- [ ] **Step 4:** `cargo test -p g3proxy` 相关全绿。**Step 5: Commit** `"g3proxy: add upload-audit concurrency permit and skip counter to AuditHandle"`

### Task 5: serve/http_proxy forward（h1 显式/透明代理）接入旁路管线

**Files:**
- Modify: `g3proxy/src/serve/http_proxy/task/forward/task.rs`（`run_with_connection:868-941`、`run_with_adaptation:954-1100`、`run_without_adaptation:1161` 的 `run_with_all_body:1366` 分支）
- Modify: `g3proxy/src/serve/http_proxy/task/forward/stats/task.rs`（新字段 `upload_audit_skipped: bool`、`upload_audit_bytes: u64`，日志行顺带输出）

**Interfaces:**
- Consumes: Task 1 `BypassAdapter`/`BypassFraming`、Task 3 `UploadAuditContext`/`run_upload_audit_or_relay`、Task 4 permit API、`HttpRequestForAdaptation::{body_type, serialize_for_adapter}`（`HttpProxyClientRequest` 已实现，见 impl_trait.rs:29）。
- Produces: 无对外新接口（内部替换）。

改造要点（不新增文件）：
1. `run_with_connection` 的 reqmod 分支改为：`audit_task && reqmod 客户端存在 && self.req.body_type().is_some()` 才继续，否则直接 `run_without_adaptation`；取不到 permit → `mark_upload_audit_skipped()`、置 `task_stats.upload_audit_skipped = true`、走 `run_without_adaptation`（**不排队**）。
2. framing：`BypassFraming { req_hdr: self.req.serialize_for_adapter(), transformed_from: "HTTP/1.0" }`；沿用现 `set_client_addr/set_client_username`（本入口无 tuple/keylog，保持取值不变——设计 §5.3 统一约定）。
3. `run_with_adaptation` 的 select 循环保留（仍需 `ups_r.fill_wait_data()` 提前响应检测），把 `icap_adapter.xfer(...)` 换成 `bypass.audit_and_forward(...)` 并包成 future；`ReqmodAdaptationEndState` 三变体的 match 删除 `HttpErrResponse` 分支（只剩转移成功两态），`Err` 分支删除（管线不返回 Err，只返回 fallback 变体）；`adaptation_state.clt_read_finished/ups_write_finished` 语义不变。
4. `run_with_all_body`（小 body 全缓冲）：主路径不阻塞——`tokio::spawn` 审计副本：把内存 body 拼 `Cursor<Vec<u8>>`（+ `tail_reader` 若有续读）喂 `audit_only`，EndState 仅记日志。若 Task 1 的 `audit_only` 需要 `'static` 输入流，`Cursor` 满足；permit/计数同 1。

- [ ] **Step 1:** 完成改造；`cargo build -p g3proxy` 通过。
- [ ] **Step 2:** 走查 Review Focus 第 6 行（chunked trailer、提前响应 break 后管线 future drop 的资源归属：chunk 写后台任务已接管连接，无泄漏）。
- [ ] **Step 3: Commit** `"g3proxy: switch HTTP forward to fail-open bypass upload audit"`

### Task 6: inspect/http/v1 forward（TLS 拦截 h1）接入旁路管线

**Files:**
- Modify: `g3proxy/src/inspect/http/v1/forward/mod.rs`（`adapt_with_io:235-313`、`run_with_adaptation:351-459`）

**Interfaces:** Consumes Task 1/3/4；`HttpTransparentRequest` 的 `serialize_for_adapter`（impl_trait.rs:61）。Produces: 无对外接口。

改造与 Task 5 同构，三点差异：① 保留现 "added by wming" 的 `ConnectionTuple`（:267）与 `set_keylog_buffer`（:268-270）取值，塞进 `UploadAuditContext.data_channel_tuple/keylog_buffer`；② 无 body 判定用 `HttpRequestForAdaptation::body_type`（:236 上下文），无 body → 完全跳过 ICAP（删除现 header-only 上报路径调用）；③ respmod 分支（:739 起）**一行不动**（N1）。

- [ ] **Step 1:** 完成改造；`cargo build -p g3proxy` 通过；确认 `reqmod::h1` 的 `xfer*` 在本文件不再被引用（import 清理），但库文件未改。
- [ ] **Step 2: Commit** `"g3proxy: switch intercepted HTTP v1 forward to bypass upload audit"`

### Task 7: inspect/http/v2 forward（TLS 拦截 h2）接入旁路管线

**Files:**
- Modify: `g3proxy/src/inspect/http/v2/forward/mod.rs`（`do_forward:244-381`、`forward_with_adaptation:385-428`）

**Interfaces:** Consumes Task 1/3/4；framing 字节 = `Request<()>::serialize_for_adapter()`（`g3_h2::RequestExt`，lib/g3-h2/src/ext/request.rs:21）；`transformed_from = "HTTP/2.0"`。Produces: `pub(crate) struct H2StreamWriteAdapter`（就地定义于 v2 forward 文件或 `g3proxy/src/inspect/http/v2/` 下新小文件）——把"先 `ups_send_request.send_request(request, end_of_stream=false)` 拿 `SendStream<Bytes>`、再把 tokio 写调用转 `poll_ready + send_data`"包成 `tokio::io::AsyncWrite`；读侧 body 用 `h2::RecvStream::into_async_read()` 作为 `clt_r`。

要点：① 触发 = `!clt_body.is_end_stream()`（无 body 流完全不碰 ICAP，删 header-only 上报调用）；② per-stream 一个 permit + `BypassAdapter`（沿用 :336-344 的 `use_icap` 尺寸门控语义：太小是否跳过由该既有配置决定，不发明新阈值）；③ 保留 tuple/keylog 取值（:311-328 现有 setter 逻辑）；④ `H2ReqmodAdaptationError` 相关 match 删除；⑤ respmod / connect（`xfer_connect`）路径不动——CONNECT 走 Task 3 迁移后的 audit_bridge 旧行为。

- [ ] **Step 1:** 实现 `H2StreamWriteAdapter` + 接入；`cargo build -p g3proxy` 通过。
- [ ] **Step 2:** `cargo test -p g3proxy`（h2 无现成单测，编译 + Task 8 手工场景覆盖）。
- [ ] **Step 3: Commit** `"g3proxy: switch intercepted HTTP v2 forward to bypass upload audit"`

### Task 8: 端到端手工验证 + 配置示例

**Files:**
- Modify: `etc/g3proxy/http/auditor.d/*.yaml`（如存在 http 示例则加 `upload_audit_max_concurrency` 注释示例；没有合适示例文件就只更新下述文档）
- Create: `doc/http-icap-bypass-audit.md`（运维视角：语义、开关链、跳过计数含义）

**Steps:**
- [ ] **Step 1:** 起本地假 ICAP（Task 1 的 mock listener 逻辑抽成 `g3bench` 下临时脚本或直接用测试二进制 `--nocapture` 场景描述写入文档），起 g3proxy http 栈（按 `编译运行.md`），执行四组 curl：`curl -x 127.0.0.1:8080 --data-binary @f http://…/`（CL body）、`-H 'Transfer-Encoding: chunked'`、经 TLS 拦截的 h1 POST、`curl --http2 -T f https://…`；假 ICAP 侧核对：`Allow: 204`、`X-Transformed-From` 三种取值、tuple/keylog 头、req-body 为解码后裸内容 chunked 重编码。
- [ ] **Step 2:** fail-open 验证：kill 假 ICAP 后 curl 上传仍成功（日志仅 warn）；`upload_audit_max_concurrency: 1` 下并发两请求，第二个照常返回且 skip 计数 +1。
- [ ] **Step 3:** FTP 回归：按 `etc/g3proxy/ftp` 场景重跑 STOR 上传，比对 Task 2 framing 字节断言 + 假 ICAP 收到的报文与改造前一致。
- [ ] **Step 4:** `cargo build --workspace && cargo test -p g3-icap-client -p g3proxy` 全绿；写 `doc/http-icap-bypass-audit.md`。
- [ ] **Step 5: Commit** `"docs+verify: HTTP bypass upload audit end-to-end scenarios"`
