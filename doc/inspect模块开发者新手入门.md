# g3proxy `inspect` 模块开发者新手入门

> 面向第一次读 `g3proxy/src/inspect/` 的贡献者：这个模块在整条代理链路里做什么、按什么顺序读代码、
> 以及要给一个新协议加检测拦截需要动哪些地方。
>
> 前置阅读：[g3proxy代码贡献者新手入门](g3proxy代码贡献者新手入门.md)（仓库结构、环境搭建、提交流程）、
> [g3proxy源码架构分析](g3proxy源码架构分析.md)（进程启动与 serve/audit 全貌）。
> 本文的行号以 `local/work-v113` 分支为准，代码内已有中文注释，**遇到不确定的地方优先读注释**。
>
> 下文所有路径均相对 `g3proxy/` crate 根目录。

---

## 目录

1. [inspect 到底在做什么](#1-inspect-到底在做什么)
2. [先跑一次，看到检测日志](#2-先跑一次看到检测日志)
3. [模块地图](#3-模块地图)
4. [先记住三个抽象就够了](#4-先记住三个抽象就够了)
5. [阅读路线 A：一条裸 TCP 流是怎么被认出协议的](#5-阅读路线-a一条裸-tcp-流是怎么被认出协议的)
6. [阅读路线 B：驱动循环与跨协议状态](#6-阅读路线-b驱动循环与跨协议状态)
7. [阅读路线 C：TLS 中间人拦截](#7-阅读路线-ctls-中间人拦截)
8. [决策来源与四岔路分派](#8-决策来源与四岔路分派)
9. [错误与终止](#9-错误与终止)
10. [动手练习：加一个新协议要改哪些地方](#10-动手练习加一个新协议要改哪些地方)
11. [新手常见卡点](#11-新手常见卡点)
12. [排查速查表](#12-排查速查表)

---

## 1. inspect 到底在做什么

一句话：**在客户端与源站之间，先认出这条流用什么协议，再按策略决定"检/绕/放/断"**。

它不是 HTTP 代理的任务层（那在 `src/serve/`），而是任务在建立上游连接之后、开始双向搬运数据之前的
**内容检测阶段**。所有 server 类型（`http_proxy`、`socks_proxy`、`tcp_stream`、`tls_stream`、
`sni_proxy`、`tcp_tproxy`）都复用这一套。

```
客户端 ──▶ serve::<某 server>::task
                 │  解析出目标地址、选好 escaper
                 ▼
        audit::AuditCtx ── check_take_handle() 采样 ──▶ 需要检测？
                 │ yes                                     │ no
                 ▼                                          ▼
        StreamInspectContext::new  ─────────────▶ 直接透明转发（relay/copy）
                 │
                 ▼
        ┌────────────────────────────────────────────┐
        │  inspect::into_loop_inspection(循环)        │
        │                                            │
        │  裸流 ──DPI──▶ 协议 ──policy──▶ 动作       │
        │   ├─ TlsModern / TlsTlcp  ── MITM 后看内层 │
        │   ├─ H1 / H2 / Websocket                   │
        │   ├─ Smtp / Imap / Ftp（含 StartTls 升级）  │
        │   └─ Unknown / Timeout / Bypass ──▶ 转发    │
        └────────────────────────────────────────────┘
                 │  检测通过 ──▶ 按协议语义转发（并可送 ICAP）
                 ▼
              任务结束，返回 ServerTaskResult<()>
```

术语先钉死，后文全部按此：

| 中文 | 代码里的词 | 含义 |
|------|-----------|------|
| 检测 | `inspection` / `inspect` | 识别协议、解析内容，中性动作 |
| 拦截 | `interception` / `intercept` | 代理"参与到协议里"而非仅搬运字节 |
| 绕行 | `Detour` | 把整条流交给外部 `stream_detour_client` 处理 |
| 旁路 | `Bypass` | 认出了协议但不做拦截，退回透明转发 |
| 阻断 | `Block` | 直接拒绝 |
| 送检 | `ICAP` / `icap_reqmod_client` | 把请求/响应内容交给外部 ICAP 服务判定 |
| 嵌套层数 | `inspection_depth` | TLS 拆一层、内层又识别出协议，层数递增 |

> 注意：`inspect`（识别）与 `interception`（拦截）在代码里是两个概念，别混。日志里也是两条
> 独立通道：`inspect_logger` 记录"认出了什么协议"，`intercept_logger` 记录"做了什么动作"。

---

## 2. 先跑一次，看到检测日志

对着 `examples/inspect_http_proxy/g3proxy.yaml` 改，比空读代码有效得多：

```bash
# 1. 编译
cargo build -p g3proxy

# 2. 只校验配置（务必先跑这个）
./target/debug/g3proxy -c examples/inspect_http_proxy/g3proxy.yaml --test-config

# 3. 画出配置对象的引用关系，确认 auditor 已挂到 server 上
./target/debug/g3proxy -c examples/inspect_http_proxy/g3proxy.yaml --output-mermaid-graph

# 4. 前台运行（log: stdout，检测结论会直接打到终端）
./target/debug/g3proxy -c examples/inspect_http_proxy/g3proxy.yaml

# 5. 另开终端，分别触发 HTTP / HTTPS 两种流
curl -x http://127.0.0.1:10087 http://example.com/
curl -x http://127.0.0.1:10087 https://example.com/

# 6. 想看"认不出协议"的分支，用 SOCKS 口发一条隧道内跑非标准协议的流量：
#    http_proxy 口在进 inspect 之前就要先解析 HTTP 请求行，乱码会直接报协议错误，
#    走不到 DPI 的 Unknown 分支（那是 socks_proxy / tcp_stream 这类 server 的路径）
```

那个示例里最关键的几行（`auditor` 段）：

```yaml
auditor:
  - name: default
    protocol_inspection: { }        # DPI 采样参数，全部走默认值
    tls_cert_generator: { }         # TLS 拦截必需：伪证书签发
    tls_interception_client: { }    # 代理→源站 的 TLS 参数
    h1_interception: { }            # HTTP/1 拦截参数（含超时）
    application_audit_ratio: 1.0    # 采样率：1.0 = 每个任务都检测
    icap_reqmod_service: icap://127.0.0.1:1344/echo   # 送检后端
```

两个会绊住人的地方：

- `application_audit_ratio` 不是 1.0 时大部分任务直接不进 inspect，"代码没生效"多半是这个原因。
  采样判定在 `src/audit/mod.rs:220` 的 `check_take_handle()`。
- 示例里配了 `icap_reqmod_service`，本机没有 ICAP 服务时会在送检处报错。想先只看协议识别，
  把这行删掉即可。

看懂日志字段——inspect/intercept 日志用的是 **audit 专用日志器**（`src/log/audit.rs:10` 取
`get_audit_default_config()`）。示例里的 `log: stdout` 会被当作各类日志器的默认值
（`src/config/log.rs:80-85`），所以能直接在终端看到。想把审计日志单独分流，用顶层 `log` 的 `audit` 键覆盖：

```yaml
log:
  default: stdout     # 兜底：各类日志器都用它
  audit: syslog       # 只把 inspect/intercept 这类审计日志送 syslog
```

可选驱动只有 `discard` / `journal`(Linux) / `syslog` / `fluentd` / `stdout`
（`lib/g3-daemon/src/log/event/config.rs:55`）；哈希形式另支持
`channel_size`、`thread_number`、`io_error_sampling_offset`（顶层 `log` 允许的键见 `src/config/log.rs:30-74`）。
两类记录分别带：
`src/log/inspect/mod.rs:12`（识别来源）、`intercept_type` / `task_id` / `depth`（动作、任务、嵌套层数）。
其中识别来源只有五种：

| `InspectSource` | 含义 |
|-----------------|------|
| `stream inspection` | 裸流 DPI 识别（最常见） |
| `tls alpn` | 从 TLS ALPN 得出内层协议 |
| `start tls` | 明文协议经 STARTTLS 升级后再识别 |
| `h2 extended connect` | H2 扩展 CONNECT 里声明的升级协议 |
| `http upgrade` | H1 Upgrade 切换出的协议（如 WebSocket） |

---

## 3. 模块地图

先记住一句话：**`mod.rs` 定义词汇，`stream/` 是引擎，其余目录是各协议的插件**。

| 路径 | 职责 | 建议首读位置 |
|------|------|-------------|
| `src/inspect/mod.rs` | 公共类型：`StreamInspectContext`、`StreamInspection` 枚举、各类配置访问器 | `mod.rs:459` 的状态枚举 |
| `src/inspect/error.rs` | `InterceptionError`，按阶段聚合子模块错误 | `error.rs:41` |
| `src/inspect/stream/mod.rs` | **驱动循环 + 透明转发框架**，最重要 | `stream/mod.rs:571` |
| `src/inspect/stream/object.rs` | 裸流协议识别与分发表 | `object.rs:171` |
| `src/inspect/tls/` | TLS MITM：`mod.rs` ClientHello/分发，`modern.rs` 标准 TLS，`tlcp.rs` 国密 | `tls/mod.rs:395` |
| `src/inspect/start_tls/` | STARTTLS 升级（FTP/SMTP/IMAP → TLS），含不完整读取回灌 | `start_tls/mod.rs:175` |
| `src/inspect/http/v1/` | HTTP/1：`connect/`、`forward/`、`upgrade/`、`pipeline/` | `http/v1/mod.rs:137` |
| `src/inspect/http/v2/` | HTTP/2：连接级多路复用 + `stream`/`ping`/`stats` | `http/v2/mod.rs:197` |
| `src/inspect/websocket/` | WebSocket 帧转发，`h1.rs` / `h2.rs` 两套承载 | `websocket/h1.rs:178` |
| `src/inspect/smtp/` | SMTP 五阶段状态机 | `smtp/mod.rs:193` |
| `src/inspect/imap/` | IMAP 按认证状态划分 | `imap/mod.rs:219` |
| `src/inspect/ftp/` | FTP 控制通道 + 上传数据通道（跨通道全局状态） | `ftp/object.rs:180` |

外部依赖（不用细读，知道边界即可）：

- `lib/g3-dpi/` — 协议识别引擎 `ProtocolInspector`、各协议拦截配置、`ProtocolInspectAction`
- `lib/g3-io-ext/` — `FlexBufReader` / `OnceBufReader`（缓冲回灌）、`IoResultEnum`、`IdleWheel`
- `lib/g3-http/`、`lib/g3-h2/` — HTTP 编解码
- `lib/g3-acl/` — IP 访问控制（裸流阶段就要查表）
- `src/audit/`、`src/config/audit/` — 配置到运行时快照
- `src/serve/` — 调用方，`ServerTaskResult` / `ServerTaskError` 定义在 `src/serve/error.rs`

---

## 4. 先记住三个抽象就够了

新人最容易在十几个协议子目录里迷路。其实整个模块只有三个概念：

### ① `StreamInspectContext<SC>` —— 我能用什么

`src/inspect/mod.rs:218` 构造。它是个"环境句柄"，聚合了单次检测需要的一切：
`audit_handle`（所有策略与拦截配置）、`server_config`、`server_stats`（在线状态）、
`server_quit_policy`、`idle_wheel`（空闲任务轮）、`task_notes`（客户端/服务端地址、task id、用户上下文）、
`connect_notes`、`inspection_depth`、`max_idle_count`。

各协议子模块拿到的都是它的引用或克隆，**所有配置读取都走它的访问器**（`mod.rs:338-450` 那一堆
`tls_interception()` / `h1_interception()` / `smtp_inspect_action()`…）。
找某个配置从哪来，先在这里 grep。

### ② `StreamInspection<SC>` —— 我现在是什么状态

`mod.rs:459`，一个 13 变体的枚举，就是状态机的状态集合：

```
End | StreamUnknown | StreamInspect | TlsModern | TlsTlcp | StartTls
    | H1 | H2 | Websocket | Smtp | Imap | Ftp | FtpUploadData
```

每个变体装着对应协议的**拦截对象**（`*InterceptObject`），对象里带着已经包好 TLS/缓冲的 IO。
变体之间的移动 = 协议识别或升级的结果。

### ③ `async fn intercept(self) -> ...` —— 协议自己怎么干活

每个 `*InterceptObject` 都提供一个 `intercept()`，被循环调用。**返回类型只有三种，各自含义固定**：

| 返回类型 | 语义 | 谁用 |
|---------|------|------|
| `ServerTaskResult<StreamInspection<SC>>` | 必定转移到下一个状态 | TLS `tls/mod.rs:395`、StartTls `start_tls/mod.rs:175` |
| `ServerTaskResult<Option<StreamInspection<SC>>>` | `Some`=继续转移，`None`=会话正常结束 | H1 `:137`、SMTP `:193`、IMAP `:219`、FTP `:180` |
| `ServerTaskResult<()>` | 自己处理完整个连接，直接收尾 | H2 `:197`、WebSocket `h1.rs:178` / `h2.rs:148`、FTP 数据通道 `:91` |

> 为什么 H2 是第三种？因为 HTTP/2 一条连接上有多个逻辑流，拦截对象内部自己起事件循环、
> 自己发 GOAWAY，循环外再转移没有意义。

另外 `StreamTransitTask` trait（`stream/mod.rs:43`）是**纯转发**的框架：双向拷贝、空闲计数、
半关闭处理。唯一实现是 `UnknownStreamTransitTask`（`stream/mod.rs:409`），它同时承担"认不出协议时
就搬运字节"和"某协议内不再检测时搬运字节"两种活。

---

## 5. 阅读路线 A：一条裸 TCP 流是怎么被认出协议的

只读 `src/inspect/stream/object.rs:116-326` 这一个函数就够。**两步采样**：

```rust
// 第一步：select! biased 判断"谁先出声"（客户端先发 or 源站先发 banner）
//         用 data0_wait_timeout 兜底 —— 纯空闲超时 → ServerTaskError::Idle
// object.rs:133

// 第二步：持续喂给 DPI，直到它给出结论
//         用 data0_read_timeout 兜底 —— 读不够 → Protocol::Timeout
// object.rs:150
```

`NeedMoreData` 时继续读，直到 `remaining() == 0`（缓冲满了再也补不出判定依据）才放弃，判 `Unknown`。

默认参数在 `lib/g3-dpi/src/config/mod.rs:173`，排查"识别不出来"时这几个数就是全部嫌疑：

| 配置项 | 默认 | 作用 |
|--------|------|------|
| `inspect_max_depth` | 4 | 嵌套检测层数上限，超了就不再识别 |
| `data0_buffer_size` | 4096 | 首段采样缓冲大小 |
| `data0_wait_timeout` | 60s | 等首段数据出现多久（纯空闲判死） |
| `data0_read_timeout` | 4s | 单次读取超时 |

识别成功后（先 `increase_inspection_depth()` 再打检测日志，`object.rs:169`）进入 match 分发，
**这里最重要的不是协议列表，而是"已读走的字节怎么还给协议对象"**：

| 识别结果 | 下一状态 | 回灌方式 | 为什么 |
|---------|---------|---------|--------|
| `TlsModern` / `TlsTlcp` | TLS 拦截 | `set_io(clt_r_buf, …)` 传 ClientHello **原字节** | 握手不能有任何改写，直接换 raw IO |
| `Http1` | `H1` | `FlexBufReader::with_bytes` | 请求行/头是文本，需要按行解析 |
| `Http2` | `H2` | `OnceBufReader`（仅客户端侧） | 帧解码要精确字节，不能有多余缓冲层 |
| `Smtp` / `Imap` / `FtpControl` | 对应协议 | 回灌**源站侧** | 这三个协议是服务端先发 banner |
| `Unknown` 且命中 FTP 上传/FTPS 域 | `FtpUploadData` | `OnceBufReader` | 跨通道推断，见第 11 节 |
| `Unknown` 其他 / `Timeout` / 未覆盖协议 | → `End` | 先 bypass 转发再返回 | 认不出就当裸流搬 |

FTP 那行是本项目最微妙的一处：FTP 数据通道是**另开一条 TCP 连接**，DPI 看到的是纯二进制内容，
不可能认出协议。于是代码用一份**进程级全局状态** `FtpUploadState`
（`src/serve/ftp_proxy/upload_state.rs`，经 `get_ftp_upload_state()` 取，`:335`）把两条连接关联起来：
控制通道侧写入 `mark_ftps_domain`（`src/serve/http_proxy/task/connect/task.rs:530/583`、
`src/inspect/ftp/object.rs:314`）与 `mark_upload`（`ftp/object.rs:351`），
数据通道侧查询 `check_ftp_upload_data`（`ftp/upload_data.rs:323`，内部 `consume_upload`）/
`get_ftps_domain`（`ftp/upload_data.rs:332`），调用点在 `stream/object.rs:183/188`、
`tls/mod.rs:685`、`tls/modern.rs:122`。**读不懂 FTP 拦截时，先读这份跨通道约定。**

---

## 6. 阅读路线 B：驱动循环与跨协议状态

`src/inspect/stream/mod.rs:571`：

```rust
pub(crate) async fn into_loop_inspection(
    self,
    mut inspector: ProtocolInspector,
) -> ServerTaskResult<()> {
    let mut obj = self;
    loop {
        match obj {
            // ... 每个分支：调用协议的 intercept()，把返回值当作下一状态
        }
    }
}
```

没有 `transition()` 这个方法名，循环就叫 `into_loop_inspection`；`?` 一路冒泡，`break` 即 `Ok(())`。

### 坑 1：`inspector` 是跨轮复用的，必须手工维护它的状态

这是整个模块**最容易写出静默 bug 的地方**，也是代码注释反复强调的地方：

```rust
StreamInspection::StreamInspect(stream) => {
    obj = stream.transit_with_inspection(&mut inspector).await?;
    inspector.unset_no_explicit_ssl();     // 明文裸流上不该期待显式 SSL 升级信号
}
StreamInspection::TlsModern(tls) => {
    obj = tls.intercept(&mut inspector).await?;
    inspector.reset_state();               // TLS 卸载后内层是明文，必须清掉上一层残留
    inspector.set_no_explicit_ssl();
}
```

规则：**每插入一层解密，就要告诉 DPI 接下来怎么看；每退回明文，就要撤销这个告知。**
StartTls / H2 / Websocket / SMTP / IMAP 分支不 reset，因为它们的 `intercept()` 内部已经自行处理了
（见 `stream/mod.rs:608`、`:631` 的注释）。加新协议时先决定：你的 `intercept()` 是自己管、还是要循环帮你管。

### 坑 2：`InspectStatus` 不是返回值

`stream/mod.rs:365` 的 `Bypass` / `Unknown` / `Timeout` 只是**"为什么没能继续检测"的归因标签**，
用来打日志和选择转发出口（三个 `transit_inspect_*` 分别在 `:470`、`:505`、`:536`）。

其中 `Unknown` 与 `Timeout` 会额外受用户级策略约束：`user.audit().prohibit_unknown_protocol` /
`prohibit_timeout_protocol`（`:485`、`:519`）命中就返回 `ServerTaskError::ForbiddenByRule(ProtoBanned)`，
并由 `forbidden_stats.add_proto_banned()` 计数。**"某些用户的未知协议流量被拒"通常是这个开关，不是 inspect 的 bug。**

### 坑 3：嵌套深度守卫

每轮入口先查 `skip_next_inspection()`（`stream/mod.rs:462`：
`inspection_depth >= protocol_inspection().max_depth()`），
超上限就按未知协议转发，防止无限递归识别。

### 入口不止一个

7 个构造点都在 `src/serve/*/task.rs`（`tcp_stream/task.rs:294`、`tls_stream/task.rs:283`、
`tcp_tproxy/task.rs:258`、`socks_proxy/.../tcp_connect/task.rs:413`、
`http_proxy/task/connect/task.rs:596` 与 `:682`、`sni_proxy/task/relay/task.rs:293`）。
另有回路入口：CONNECT 隧道内部会再起一层检测（`http/v2/connect/standard.rs:155`）。

`src/serve/sni_proxy/task/relay/task.rs` 是唯一的例外——它已经知道协议（SNI 配置指定），
所以**跳过裸流识别**，直接 `StreamInspection::TlsModern/TlsTlcp/H1(...).into_loop_inspection(...)`
（`:319`、`:339`、`:352`）。想知道"不经过 DPI 直接进某个协议拦截"长什么样，看这里。

### `explicit_protocol` 目前是死参数

它只是 `transit_with_inspection` 的最后一个参数（`stream/mod.rs:340`），最终走
`ctx.protocol_inspector()` 里的 `inspector.push_protocol(p)`（`mod.rs:308`）。
**当前全部 7 个调用点都传 `None`**——它不是 YAML 配置项，只是给"外层已明确告知协议"预留的钩子。
端口线索另有来源：`server_tcp_portmap` / `client_tcp_portmap`（`src/audit/handle.rs:109/114`）。

---

## 7. 阅读路线 C：TLS 中间人拦截

TLS 拦截是 inspect 的技术核心，也是配置最重的一块。主流程在 `src/inspect/tls/modern.rs`
的 `do_intercept_modern`（`:44`），按顺序理解：

```
1. 读 ClientHello            tls/mod.rs 的 ParsedClientHello（字节不能消费，原样留给下层）
2. 取 SNI / ALPN             modern.rs:66 / :76（ALPN 会先按本代理支持的协议过滤一遍）
3. 查拦截策略                ctx.tls_interception() → mod.rs:338（按域名决定是否 MITM）
4. 构造两侧 SSL 状态          modern.rs:95-116 上游侧：有 user_site 就用 build_mimic_ssl
   （模拟客户端指纹），否则用通用 client_config.build_ssl
5. FTPS 会话注入              modern.rs:127-143（vsftpd 要求数据通道复用控制通道的 TLS 会话）
6. 后台预取伪证书  ┐         modern.rs:158-163  tokio::spawn(cert_agent.pre_fetch(domain))
7. 与源站真实握手  ┘ 并发     modern.rs:168-183  带 handshake_timeout
8. 取伪证书                   modern.rs:184-207：预取命中直接用；未命中则拿第 7 步取到的
   源站真实证书再调 cert_agent.fetch(…, upstream_cert) 签发
9. 记录源站证书校验结果        modern.rs:211（供拦截审计日志输出）
10. 装入伪证书 + 透传 ALPN    modern.rs:212-224
11. 接受客户端握手            modern.rs:226-240（OnceBufReader 把 ClientHello 拼回读流）
12. ALPN 决定内层协议         modern.rs:241-255 → inspector.push_alpn_protocol
```

要点：

- **第 6/7 步是刻意并发的**：签发伪证书可能要走远端 `g3fcgen`，串行会直接加到握手延迟上。
  预取只按域名（SNI / FTPS 域名 / 上游 host）取，命中缓存就不依赖源站证书；
  **只有缓存未命中时**才必须等第 7 步拿到 `peer_certificate()` 再签（`modern.rs:194-202`）。
- **ALPN 结果直接决定下一状态**：这是 `InspectSource::TlsAlpn` 日志的来源，也是 H2-over-TLS
  的识别路径（不靠 DPI 采样，靠协商）。两侧 ALPN 会被对齐：源站协商结果透传回客户端。
- 伪证书签发是**异步外部调用**。`tls_cert_generator`（别名 `tls_cert_agent`）可以是本地、
  `g3fcgen` 服务或 `g3keymess` keyless（私钥不落代理机）。任何一步取不到证书都以
  `NoFakeCertGenerated` 终止——这是新手最常见的第一个报错点。
- 国密 `TlsTlcp` 在 `#[cfg(feature = "vendored-tongsuo")]` 下才编译，需要**签名证书 + 加密证书两份**
  （`tls/tlcp.rs`、`start_tls/tlcp.rs`）。默认 `cargo check` 覆盖不到它——改动这两个文件后
  必须单独用该 feature 编译验证。
- FTPS / IMAPS / SMTP-with-STARTTLS 走 `src/inspect/start_tls/`，不是 `tls/`：
  它们的 TLS 记录层出现在明文会话之后，需要等协议协商到 `234`/`OK` 之类应答才升级，
  因此多了"不完整读取"的缓冲包装（`start_tls/mod.rs`）。

---

## 8. 决策来源与四岔路分派

`src/audit/handle.rs:31` 的 `AuditHandle` 是一份**只读资源快照**：策略与配置在启动时构建完成，
运行期 inspect 只查不改。inspect 侧全部通过 `StreamInspectContext` 的访问器取用。

各协议的策略走同一套 `ProtocolInspectPolicy`（按目标 host 查表），返回：

```rust
// lib/g3-dpi/src/config/mod.rs:114
pub enum ProtocolInspectAction {
    Block,
    #[default] Intercept,   // 默认值：拦截
    Bypass,
    #[cfg(feature = "quic")] Detour,
}
```

YAML 形态（解析入口 `lib/g3-yaml/src/value/dpi/policy/mod.rs:55`，
规则体复用 ACL 的通用解析 `lib/g3-yaml/src/value/acl/mod.rs:50`）——
**记住一条：规则里的 key 是动作名，value 是主机/网段列表**：

```yaml
h2_inspect_policy:
  default: intercept                    # 未命中任何规则时的动作
  exact:                                # 也可写 exact_match
    bypass: [bypass.example.com]        # key = 动作，value = host 列表（单个值也可以）
    block: [blocked.example.com]
  child:                                # 子域匹配，也可写 child_match
    intercept: [corp.example.com]
  subnet:                               # 目的网段匹配，也可写 subnet_match
    bypass: ["10.0.0.0/8"]
```

动作字符串只有 `block` / `intercept` / `bypass` / `detour`（后者需 `quic` feature），
见 `lib/g3-dpi/src/config/mod.rs:148`。规则体若直接写数组（如 `exact: [a.com]`），
则按该规则的"命中默认动作"处理（DPI 侧默认 `intercept`）。

每个 `intercept()` 的**开头都是同一段四岔分派**，看懂一个就看懂全部
（`src/inspect/smtp/mod.rs:193` 的真实代码）：

```rust
let r = match self.ctx.smtp_inspect_action(self.upstream.host()) {
    ProtocolInspectAction::Intercept => self.do_intercept().await,
    #[cfg(feature = "quic")]
    ProtocolInspectAction::Detour => self.do_detour().await.map(|_| None),
    ProtocolInspectAction::Bypass => self.do_bypass().await.map(|_| None),
    ProtocolInspectAction::Block => self.do_block().await.map(|_| None),
};
match r {
    Ok(obj) => { intercept_log!(self, "finished"); Ok(obj) }
    Err(e)  => { intercept_log!(self, "{e}");     Err(e)  }
}
```

注意只有 `Intercept` 分支可能返回 `Some(下一状态)`，其余三条都是 `.map(|_| None)`——
**绕/放/断都意味着本层检测到此为止**。

新增协议时"策略→动作分派"这条线务必照抄，**不要自创第五种动作**。

---

## 9. 错误与终止

`src/inspect/error.rs:22` 的 `InterceptionError` 只做一件事：把各子模块错误按阶段归类
（`Tls` / `StartTls` / `H1` / `H2`），并有**唯一出口**：

```rust
// error.rs:41
pub(super) fn into_server_task_error(self, protocol: Protocol) -> ServerTaskError {
    ServerTaskError::InterceptionError(protocol, self)   // src/serve/error.rs:122
}
```

于是运行期有两类截然不同的终止：

| 类型 | 来源 | 表现 |
|------|------|------|
| 拦截错误 | `InterceptionError` 包装，各 `intercept()` 内产生 | 协议解析/握手/送检失败，任务以 `InterceptionError` 结束 |
| 转发错误 | `transit_*` 直接返回 `ServerTaskError` | IO 拷贝失败、`Idle` 空闲、`ForbiddenByRule` 被拉黑、服务退出 |

排查时先看是 `InterceptionError` 还是别的——前者说明问题在**协议语义处理**，
后者说明问题在**字节搬运/策略开关**，方向完全不同。

---

## 10. 动手练习：加一个新协议要改哪些地方

建议按 ① → ⑦ 顺序做，前两步只碰 `lib/g3-dpi/`，能最快看到识别日志再动拦截。

| # | 改什么 | 文件与位置 |
|---|--------|-----------|
| ① | DPI 识别函数 + 注册 | `lib/g3-dpi/src/protocol/mod.rs:298`（`mod` 注册）；`MaybeProtocol` 变体 `:20`；`Protocol` 变体 `:149` + `as_str` `:182`；分派表 `protocol/inspect.rs:79`；默认端口表 `protocol/portmap.rs` |
| ② | 状态枚举变体 + 子模块声明 | `src/inspect/mod.rs:459`（加变体）；`mod.rs:59-61` 附近加 `pub(crate) mod <proto>;` |
| ③ | 裸流分发表 | `src/inspect/stream/object.rs:171`，决定用哪种回灌器与 `set_io`（见第 5 节表格） |
| ④ | 驱动循环 match 臂 | `src/inspect/stream/mod.rs:577`，并决定是否要 `reset_state` / `set_no_explicit_ssl` |
| ⑤ | 拦截对象本体 | 新建 `src/inspect/<proto>/mod.rs`，模板抄 `smtp/mod.rs:193`：四岔分派 + `set_io` + `intercept_log!` + `increase_inspection_depth` |
| ⑥ | 策略与配置的贯通 | `src/config/audit/auditor.rs`（字段 `:100`、默认 `:138`、YAML 解析 `:241` 附近）→ `src/audit/handle.rs`（`ProtocolInspectPolicy` `:43`、build `:74`、访问器 `:134`）→ `src/inspect/mod.rs` 加 `<proto>_inspect_action`（仿 `:412`）与 `<proto>_interception`（仿 `:421`） |
| ⑦ | 可选收尾 | `ProtocolInspectionConfig` 超时/开关、`src/log/inspect/mod.rs:12` 的 `InspectSource`、用户级 `prohibit_*` 策略 |

自检清单（每条都是一个静默 bug 的来源）：

- [ ] `--test-config` 能过，且 `--output-mermaid-graph` 里新配置节点挂上了
- [ ] 触发流量后能看到 `inspect` 日志（没有 → ① 识别或采样率问题，与拦截代码无关）
- [ ] `Protocol::Unknown` 分支没有把你的协议误吞（`object.rs:172` 的 FTP 特判在 `_ =>` 之前）
- [ ] 循环里的 `inspector` 状态按第 6 节坑 1 的规则处理了
- [ ] 会话正常结束时返回 `Ok(None)` 而不是错误——否则健康连接会被记成失败
- [ ] `cargo check -p g3proxy` + 若涉及 TLCP，`--features vendored-tongsuo` 也要过

---

## 11. 新手常见卡点

1. **找不到 `transition()`**。它不存在；循环是 `stream/mod.rs:571` 的 `into_loop_inspection`。
2. **以为 `InspectStatus` 是 `intercept()` 的返回值**。它只是归因标签（第 6 节坑 2）。
3. **改了配置但行为不变**。先看 `application_audit_ratio` 采样、`*_inspect_policy` 是否命中、
   用户级 `prohibit_*` 开关，这三层都在 inspect 之前。
4. **`explicit_protocol` 传了值却没效果**。当前 7 个调用点都传 `None`，它不是配置项（第 6 节末）。
5. **TLS 拦截报 `NoFakeCertGenerated`**。伪证书取不到：CA 未配、`g3fcgen`/`g3keymess` 不可达，
   或缓存未命中且源站没返回证书（`modern.rs:194-202`）。若 TLS 流量"看起来正常但没被拦截"，
   则是另一回事——`tls_interception()` 为 `None` 会静默走 bypass（第 7 节）。
6. **改 `tlcp.rs` 后 `cargo check` 通过就以为没问题**。这两个文件在 `vendored-tongsuo` 门控下，
   默认编译不覆盖。
7. **明文协议加 TLS 找不到入口**。STARTTLS 路径在 `start_tls/`，不在 `tls/`；
   因为 TLS 层出现在明文会话之后，需要额外的"不完整读取"缓冲回灌。
8. **FTP 数据通道看起来没被检测**。它是另一条 TCP 连接，靠进程级全局状态跨通道关联
   （`src/serve/ftp_proxy/upload_state.rs` 的 `FtpUploadState`），不是靠识别内容。
9. **担心 `intercept()` 里的缓冲丢失**。已读字节必须回灌，见第 5 节表格——
   忘了把首段塞回去就会丢握手数据或请求行，表现为"间歇性协议错误"。
10. **`cargo fmt` 一把梭**。本仓库工作区有大量并行的本地改动，`cargo fmt -p g3proxy` 会顺带
    重排别人的文件。只对目标文件跑 `rustfmt --edition <workspace edition>`，或用
    `cargo fmt -p g3proxy -- --check` 确认自己的改动干净。

---

## 12. 排查速查表

| 现象 | 先看哪里 |
|------|---------|
| 完全没有检测日志 | `application_audit_ratio`（`src/audit/mod.rs:220` 采样）→ ① DPI 识别 |
| 日志是 `Unknown` | `object.rs:172`；加大 `data0_buffer_size`；看 `lib/g3-dpi/src/protocol/` 识别函数 |
| 日志是 `Timeout` | `data0_read_timeout`（默认 4s）；客户端是否在等服务端 banner |
| 认出协议但没拦截 | `*_inspect_policy` 命中结果是否 `bypass`；`inspect_max_depth`（默认 4）是否超限 |
| 未知协议流量被拒 | 用户级 `prohibit_unknown_protocol`（`stream/mod.rs:485`） |
| TLS 只是被转发、没做 MITM | `ctx.tls_interception()` 返回 `None` 时 `object.rs:239-251` 会**直接落到末尾按 bypass 转发**，不报错；检查 auditor 的 TLS 拦截配置与该 host 是否命中策略 |
| TLS 握手失败 | `tls/modern.rs` 第 6-11 步；`tls_cert_generator` 与 `tls_interception_*` |
| H2 只检了部分流 | `http/v2/mod.rs:197` 内部事件循环；`:305/357` 对客户端 `max_concurrent_streams(1)`、`:402` 对源站 `(0)`（不接受源站发起的流与推送） |
| HTTP 响应被截断 / 报错 | `http/v1/forward/mod.rs`（响应头写出时机、`body_pending` 强制断连） |
| 任务被 `InterceptionError` 结束 | 看错误里的 `Protocol` 判断是哪个子模块，再回到该模块 `intercept()` |
| 偶发协议错乱 | 检查已读字节回灌与 `inspector` 状态维护（第 5、6 节） |

---

**最短上手路径**：跑一次第 2 节 → 读 `stream/mod.rs` 的循环 → 读 `stream/object.rs` 的分发表 →
挑一个熟悉的协议子目录（文本协议推荐 `smtp/`，二进制推荐 `tls/`）通读 → 按第 10 节做练习。
