# g3proxy `src/serve` 模块新手入门

> 面向第一次接触 g3proxy 接入层（serve）的开发者。全文以 `src/serve/` 下的代码为准，标注了 文件:行号，便于对照阅读。
> 建议先浏览 `/data/zf2zf/g3/doc/g3proxy源码架构分析.md` 了解全局，再回到本文读 serve。

---

## 1. serve 在项目中的位置

`src/` 顶层结构（注意：**没有** `src/proxy`、`src/upstream` 目录）：

| 目录 | 一句话职责 |
|------|-----------|
| `serve/` | **接入层**：监听端口、实现面向客户端的协议（HTTP/SOCKS/FTP/SNI…）、任务生命周期、热加载 |
| `module/` | **上游连接语义**：`http_forward`、`tcp_connect`、`udp_relay`、`ftp_over_http` 等报文级封装 |
| `escape/` | **出口层（escaper）**：真正对外建连 `tcp_setup_connection` / `tls_setup_connection` / `udp_setup_*` |
| `inspect/` | **协议深度检测**：http、tls、ftp、smtp、imap、websocket、start_tls 的拦截与解析 |
| `audit/` | 审计事件、datalog、redis/msgpack 上报 |
| `auth/` | 用户组、认证、用户级配置 |
| `config/` | YAML 配置解析 + 各对象 registry |
| `control/` `resolve/` `stat/` `log/` | 控制通道(capnp)、DNS、指标、日志 |

启动调用链：

```
main.rs:47   config::load()            # 加载 YAML
main.rs:163  load_and_spawn()          # 按 resolve → escape → auth → audit → serve 顺序
main.rs:177  serve::ops::spawn_all()   # ops.rs:57
             ├─ config::server::get_all_sorted()      # config/server/mod.rs:298
             ├─ spawn_new_unlocked()                  # ops.rs:290，按 AnyServerConfig 分派
             │    └─ XxxServer::prepare_initial() → registry::add()
             │         └─ server._start_runtime()     # 真正创建监听
             └─ 已存在则 reload_old_unlocked()         # ops.rs:254
```

关键第三方依赖：tokio、h2、http、quinn(`quic` feature)、rustls/tokio-rustls、openssl；自研 crate `g3-daemon`（提供 `ListenTcpRuntime`/`AcceptTcpServer` 等抽象）、`g3-io-ext`、`g3-h2`、`g3-http`、`g3-dpi`、`g3-socks`、`g3-codec`。Go edition 为 2024 / rust-version 1.90。

---

## 2. 一句话记住整个 serve：**两级串联**

g3proxy 把一个客户端连接的处理拆成两级：

```
客户端 → [端口型 server] → [协议型 server] → [escaper] → 上游
          plain_*_port        http_proxy/socks_proxy/...
          只做 TLS 终结 /
          proxy-protocol /
          协议分流
```

- **端口型**（`plain_tcp_port`、`plain_tls_port`、`native_tls_port`、`plain_quic_port`、`intelli_proxy`）自己不处理业务，只做预处理，然后调用 `next_server` 的方法把连接交出去。
- **协议型**（`http_proxy`、`http_rproxy`、`socks_proxy`、`sni_proxy`、`ftp_proxy`、`tcp_stream`、`tls_stream`、`tcp_tproxy`）实现具体协议语义。

因此 `Server` trait 里有**三个**入口方法（`serve/mod.rs:87-89` 与 g3_daemon 的 `run_tcp_task`）：

| 方法 | 谁调用 | 场景 |
|------|--------|------|
| `run_tcp_task(TcpStream)` | 端口层的 accept 回调 | 明文 TCP 直达 |
| `run_rustls_task(TlsStream<TcpStream>)` | `plain_tls_port` / `tls_stream` | rustls 已终结 TLS |
| `run_openssl_task(SslStream<TcpStream>)` | `native_tls_port` | openssl 已终结 TLS |

多数 server 对用不到的那个留**空实现**——看到空函数别以为是 bug。`sni_proxy` 两个 TLS 入口是空的是**故意的**：它必须拿到明文首包才能解析 SNI。

---

## 3. 公共骨架（读任何子模块前先掌握）

### 3.1 trait 体系

- `Server`（`mod.rs:74`）：`BaseServer + AcceptTcpServer + AcceptQuicServer`，外加 `escaper()/user_group()/auditor()`（返回依赖对象的**名字** `NodeName`）、`get_server_stats()`、`alive_count()`、`quit_policy()`。
- `ServerInternal`（`mod.rs:92`）：热加载/生命周期钩子——`_start_runtime`、`_abort_runtime`、`_reload_with_old_notifier`、`_reload_with_new_notifier`、`_update_escaper_in_place` 等。
- `ArcServer = Arc<dyn Server + Send + Sync>`（`mod.rs:120`）。
- `WrapArcServer`（`mod.rs:124`）：适配器，把 `Server` 包装成 g3_daemon 监听运行时需要的 `AcceptTcpServer`。

### 3.2 监听创建范式

每个 server 的 `_start_runtime` 都是同一套写法（例 `tcp_stream/server.rs:329`、`http_proxy/server.rs:363`）：

```rust
let runtime = ListenTcpRuntime::new(WrapArcServer(server.clone()), listen_stats);
runtime.run_all_instances(&config.listen, config.listen_in_worker, &reload_sender)?;
self.runtime = Some(runtime);
```

accept 到新连接 → 回调 `run_tcp_task` → server 内部 `tokio::spawn` 具体任务。
`reload_sender` 是 `broadcast::Sender<ServerReloadCommand>`（`mod.rs:161`），监听协程收到 `ReloadVersion` / `QuitRuntime` 实现**不重开端口**的热更新。

### 3.3 registry：名字的注册表

`registry.rs`：

- `RUNTIME_SERVER_REGISTRY: Mutex<ServerRegistry>`（:18）—— 名字 → 在线 server。
- `OFFLINE_SERVER_SET: Mutex<Vec<..>>`（:19）—— 被替换/删除的旧 server，等存量任务 drain。
- `add()`（:32）先 `_start_runtime()` 再插入；旧的同名 server 进 offline。
- `get_or_insert_default()`（:102）—— **名字找不到时插入 `DummyCloseServer` 占位**（重要，见 §4.7）。
- `retain_offline()`（:115）每分钟回收：存活任务为 0 则丢弃；否则延时触发 `quit_policy.set_force_quit()`。

### 3.4 ops：启动与热加载总控

`ops.rs`：

- `spawn_all()`（:57）：全量对比配置与 registry，新增/重载/删除。
- `reload_old_unlocked()`（:254）：按 `ServerConfigDiffAction` 五种策略决定动作——`NoAction` / `SpawnNew` / `ReloadNoRespawn` / `ReloadAndRespawn` / `UpdateInPlace(flags)`。
- `update_dependency_to_escaper / user_group / auditor`（:182/:206/:230）：下游对象变更时**原地**刷新 server 的 `ArcSwap` 字段，不重建监听。
- `update_dependency_to_server_unlocked()`（:156）：某 server 被 spawn/reload/delete 时，回调所有 `_depend_on_server(name)` 为 true 的 server 的 `_update_next_servers_in_place()`。
- `wait_all_tasks()`（:320）：优雅退出时轮询 offline server 的 `alive_count()`，超时后强制退出。

### 3.5 每任务的公共记录

`task.rs`：

- `ServerTaskStage`（:22）状态机：`Created → Preparing → Connecting → Connected → Replying → LoggedIn → Relaying → Finished`。
- `ServerTaskNotes`（:51）：**绑定单个客户端连接**，含 `cc_info`（客户端/服务端地址、worker id）、uuid、`user_ctx`（认证与用户限额）、`egress_path_selection`（下一跳选择）、并发 `GaugeSemaphorePermit`。源码注释明确警告**不可跨连接共享**（:48-50）。
- `egress_path_*()`（:130-188）：优先取用户配置里的选路，其次取连接级选路——这是 username-params / 自定义头指定代理链的实现基础。

`error.rs`：`ServerTaskError`（:54）统一错误枚举（内部错误 / 客户端协议错 / 上游连接错 / `ForbiddenByRule` / Idle 等），是所有 `run_*_task` 的返回类型别名 `ServerTaskResult` 的载体。

`stats.rs`：`ServerStats` trait（:16）——`conn_total` / `task_total` / `alive_count` / TCP·UDP IO 快照 / forbidden 快照；`ServerForbiddenStats`（:55）三个计数器 `auth_failed` / `dest_denied` / `user_blocked`。

`idle_check.rs`：`ServerIdleChecker`（:13）基于每个 server 自己的 `IdleWheel` 判空闲退出，同时检查"用户被 block"与"server 要求退出"以强制中断。

> ⚠️ 代码里**没有** `ServeTask` 这样的统一任务 trait；任务实体是各协议自己的 `XxxTask` 结构体。存活计数靠 RAII 守卫（`XxxAliveTaskGuard` 的 `Drop`）保证不漏减。

---

## 4. 各协议模块逐个看

### 4.1 `http_proxy/` — 正向 HTTP 代理

支持明文 HTTP 转发、`CONNECT` 隧道、`https://` 绝对 URI 转发、以及用 HTTP 方法承载的 FTP（GET/PUT/DELETE）。

流程要点：

- `server.rs:407` `run_tcp_task`：`add_conn` → `drop_early()`（ingress ACL，:220）→ 若配了 `tls_acceptor` 先 rustls 握手（:414）→ `spawn_stream_task()`（:245）。
- **reader/writer 双协程流水线**：`stream.into_split()` + `mpsc::channel(pipeline_size)`，reader 后台 spawn，writer 在当前协程 await（QUIC 版 :277 每条 bi-stream 两个都 spawn）。
- `task/pipeline/reader.rs:62/81`：等数据 → `HttpProxyRequest::parse()` → 投递 writer；带 body 或 CONNECT 的请求会把读半一起移交，之后靠容量 1 的 `stream_sender` 归还（这就是背压点）。
- `task/pipeline/writer.rs:219` `into_running()`：`do_auth()`（:141，Basic/匿名；连续失败 >1 断开）→ `run()`（:318）→ 按 `HttpProxySubProtocol` 分发到 connect / forward / ftp / untrusted。子协议判定在 `task/protocol/request.rs:78-124`。
- CONNECT 两阶段：`task/connect/task.rs:190` 建连 → :467 `into_running` spawn 双向隧道 → :496 `run_connected()` 回 200 → :550 `relay()` 分流；FTP/FTPS 通道走 `inspect::stream::transit_with_inspection`，识别到上传则走 `ftp_proxy::audit_bridge::run_ftp_upload_audit_or_relay_bidi`（:650）。

关键配置：`listen`（可为 None，仅作被引用对象）、`ingress_net_filter`、`dst_host_filter`/`dst_port_filter`、`pipeline_size`、`timeout.recv_req_header`、`pipeline_read_idle_timeout`、`tcp_sock_speed_limit`、`task_idle_max_count`、`server_tls_config`、`auth_realm`、`username_params`、`egress_path_selection_header`、`server_id` + `echo_chained_info`。

### 4.2 `http_rproxy/` — 反向 HTTP 代理

方向相反：对外是"源站"，按 **Host/SNI** 路由到内部 upstream；**不支持 CONNECT**（`task/protocol/request.rs:51` 显式拒绝）。

- `server.rs:339` `run_tcp_task`：启用 TLS 时用 `LazyConfigAcceptor` **只读 ClientHello**（超时 `client_hello_recv_timeout`），按 SNI 选 `hosts` 里对应主机的 `tls_server`，否则 `global_tls_server`，再完成握手。存在的意义就是**同一 IP 同一端口承载多域名**。
- `task/pipeline/writer.rs:195`：`hosts.get(req.upstream.host())` 查不到直接 400 并断链。
- `task/protocol/request.rs:71-89`：检查并追加 **`Via` 头做环路检测**（`LoopDetected`）。
- `host.rs:14` `HttpHost{config, tls_server, tls_client}`——每个虚拟主机一套独立的服务端/客户端 TLS。

### 4.3 `socks_proxy/` — SOCKS v4a / v5

TCP CONNECT、UDP CONNECT、UDP ASSOCIATE；v5 支持 username/password 认证。

- `server.rs:274` `run_tcp_task` → `server.rs:154` `run_task()`：一条连接一个任务，直接交给 `SocksProxyNegotiationTask::into_running(stream)`，不做 reader/writer 拆分。
- `task/negotiation/task.rs:90`：读首字节判版本，`0x04` → `run_v4`（:119），`0x05` → `run_v5`（:183）；v5 选认证方法 → 校验 → 收请求 → 分发到 `TcpConnectTask` / `UdpAssociateTask` / `UdpConnectTask`（:308-346）。`TcpBind` 一律 `CommandNotSupported`。
- UDP 走 ASSOCIATE 还是 CONNECT 由 `server_config.use_udp_associate || user.socks_use_udp_associate` 决定（:331）。
- TCP 隧道：`task/tcp_connect/task.rs:227` `run()`（限流 → 并发许可 → ACL → `escaper.tcp_setup_connection`）→ :329 `run_connected()` 回成功 → :384 `relay()`（按 `audit_handle.do_task_audit()` 选择带检视或 `transit_transparent`）。
- UDP：`task/udp_associate/task.rs:511` 收首包时与 TCP 控制通道 `select!` 竞争——客户端 TCP 上先出现字节即视为异常断开。

注意：**SOCKS 的 TLS 由端口层提供**，`run_rustls_task`/`run_openssl_task` 直接复用 `run_task`（`server.rs:316`）。v4a 不支持认证，要求 `allow_anonymous`。

### 4.4 `sni_proxy/` — 基于 SNI/协议识别的 L4 路由

不解密、不终结 TLS，只做"看首包猜协议 → 取目标名 → 四层转发"。典型用于单端口汇聚多站点。

- `server.rs:153` `run_task()` → `ClientHelloAcceptTask::into_running(stream)`。
- `task/accept/task.rs:82` `run()`：攒首批数据（`request_wait_timeout`）→ :192 用 `g3_dpi::ProtocolInspector` 判协议 → :231 `fetch_upstream()`：HTTP/1 取 `Host` 头（`accept/http.rs:13`），TLS 取 **SNI**（`accept/tls.rs:14`，支持分片 `HandshakeCoalescer`，上限 `tls_max_client_hello_size`）。
- :122 `allowed_sites` 白名单：命中则 `site.redirect(&upstream)` 改写目标，否则 `ForbiddenByRule` 断连。
- :133 `auth_match`：用 `FactsUserGroup` 按客户端 IP / ServerName 反查用户，构造 `UserContext`——这是"免认证也能按身份下发用户配置"的机制。
- 之后交给 `task/relay/task.rs:94` `TcpStreamTask`：建连 → `relay()`（:263）。开审计时按协议进入 **TLS MITM 拦截**（:306）或 **H1 拦截**（:344），否则 `transit_transparent2`（:368，把已预读的缓冲区作为前缀续传）。

复用 `tcp_stream` 的统计类型（`mod.rs:6`）。`run_rustls_task`/`run_openssl_task` 为空实现（`server.rs:325`）。

### 4.5 `ftp_proxy/` — 原生 FTP/FTPS 代理

客户端把代理当 FTP 服务器；主动改写 PASV/EPSV 把数据通道牵引到代理内部，上传内容可经 ICAP REQMOD 审计。

- `server.rs:184` `run_task_with_stream()`：按 `SelectivePickPolicy::Random` 从 `config.upstream` 选一台 → split → `FtpProxyTask::into_running(clt_r, clt_w)`。
- 回源三种方式（`task.rs:211` 按 `TlsUpstreamType` 三选一）：
  - `connect_plain_ftp`（:226）走 `escaper.tcp_setup_connection`；
  - `connect_implicit_ftps`（:254）走 `escaper.tls_setup_connection`；
  - `connect_explicit_ftps`（:292）**故意绕过 escaper 的流拆分**：先明文连、读 220、发 `AUTH TLS`、期望 234、再在既有 TCP 上做 TLS 握手（因为要在 TLS 前插入 FTP 命令）。
- `relay_control()`（`task.rs:349`）是 `select! { biased }` 三事件循环：① 客户端命令——STOR/APPE/STOU → 上传数据通道；LIST/RETR → 下载数据通道；PASV/EPSV → `parse_pasv_response` 取上游真实地址 + `open_local_data_listener()`（:515，绑 `0.0.0.0:0`）+ **改写应答为本机监听**；② 上游输出透传；③ 空闲/强制退出。

子文件：

| 文件 | 职责 |
|------|------|
| `ctl_common.rs` | 控制通道解析公共件（`is_upload_command:27`、`is_pasv_command:38`、`read_ftp_response:137`、`rewrite_pasv_response:292`），原生模式与 CONNECT 模式共用 |
| `audit_bridge.rs` | ICAP REQMOD 上传审计桥接。`run_ftp_upload_audit_or_relay:100`；**性能关键**：`bidi_half_relay_with_idle:184` 用 8 深度 mpsc 把 read 与 write_all 拆成两任务，避免上游反压导致客户端零窗口、大文件上传卡死（注释 :193-205）；ICAP 建适配器失败则退化为纯转发，绝不阻塞上传（:361） |
| `upload_state.rs` | 跨连接共享状态表（HTTP CONNECT 模式下控制与数据是两条独立 TCP，只能靠 `(client_ip, server_ip)` 关联）。`mark_upload:181` / `consume_upload:243` / `mark_ftps_domain:283` / `save_tls_session:329`；TTL 3600s、上限 4096。**被 http_proxy 与 inspect 共同使用** |
| `connect_bridge.rs` | `FtpOverConnectBridge` — **目前 `#[allow(dead_code)]` 未被调用**（`mod.rs:23`），CONNECT 模式的 FTP 拦截实际由 `src/inspect/ftp/` 承担，读代码时别当生效路径 |

坑：PASV 改写后回给客户端的是 `127.0.0.1` + 本机随机端口（`task.rs:451`），仅适合代理与客户端同机或另有 NAT。ftp_proxy 不使用 `user_group`（`server.rs:363` 返回 Default），认证串由控制通道透传。

### 4.6 `intelli_proxy/` — 协议自适应分流

**不是代理协议，是分流器**：一个端口同时吃 HTTP 与 SOCKS。

- `server.rs:124` `run_task()`：① 可选先读 HAProxy proxy-protocol 头并 `cc_info.set_proxy_addr()` 覆盖客户端地址；② `detection.rs:16` 用 `stream.peek()` 读 **1 字节**——`0x04/0x05` → Socks，`'G''H''P''D''C''O''T'` → Http；③ 未知/超时 → `add_failed()` 丢弃，否则 `self.http_server.run_tcp_task(...)` 或 `socks_server.run_tcp_task(...)`。
- 下一跳持有在 `ArcSwap<ArcServer>`（`server.rs:40`），通过 `get_or_insert_default` 取得。`_depend_on_server()`（:188）声明依赖，因此下游 server 变更时会被回调 `_update_next_servers_in_place()` 就地替换，**无需重建监听**。
- `escaper/user_group/auditor` 均为 Default，`alive_count()` 恒 0——它自己不计量任务，全计到下游。
- 限制：只做一层 peek，**TLS 流量与 QUIC 不支持**。

### 4.7 `dummy_close/` — 占位兜底

接受连接后立即关闭（stream drop）。`_start_runtime` 直接 `Ok(())`（`server.rs:120`，**根本不监听**），`version()`/`alive_count()` 恒 0。

> 🩺 **排障第一原则**：任何"引用别的 server 名字"的配置（`intelli_proxy` 的 `http_server`/`socks_server`、`plain_*_port` 的 `server`、`tcp_stream` 的 `next_server`），**名字拼错 / 引用了未加载或已删除的节点 → 拿到 DummyClose → 连接秒断且日志无提示**。配置看似正常却连不上，先查被引用的名字是否存在。

### 4.8 `tcp_stream` / `tls_stream` / `tcp_tproxy` — 私有 TCP 隧道族

三者结构完全同构：`server.rs`（实现 trait）+ `common.rs`（`CommonTaskContext`）+ `task.rs`（relay 任务）+ `stats/`。

| 模块 | 差异 |
|------|------|
| `tcp_stream` | 静态 upstream 列表 `SelectiveVec<WeightedUpstreamAddr>`，`select_consistent` 按策略挑选（`server.rs:212`）。`task.rs:216` 经 escaper 连上游；`task.rs:303` 若开审计走 `inspect::stream::transit_with_inspection`，否则透明转发。任务实现 `StreamTransitTask` trait（:373）供 inspect 回调 |
| `tls_stream` | 与 tcp_stream 几乎一致，只是**入向由本 server 自己做 rustls 终结**；多出 `tls_acceptor`、`tls_rolling_ticketer`（会话票据轮换，`server.rs:145`）；复用 `tcp_stream::TcpStreamServerStats` |
| `tcp_tproxy` | 透明代理（仅 linux/bsd，`mod.rs:45` cfg）。**无配置 upstream**，目标地址取自 `cc_info.server_addr()`（内核 TPROXY 保留的原目的），`task.rs:61` 直接 `UpstreamAddr::from(target)` |

---

## 5. 端口型 server（`plain_*_port` / `native_tls_port`）

四个都极薄，共同点是持有 `next_server: ArcSwap<ArcServer>`：

| 模块 | 做什么 | 交出方式 |
|------|--------|----------|
| `plain_tcp_port` | 可选 HAProxy proxy-protocol v1/v2 解析并 `set_proxy_addr` | `next_server.run_tcp_task`（`mod.rs:119`） |
| `plain_tls_port` | rustls 终结 TLS | `next_server.run_rustls_task`（`mod.rs:196`） |
| `native_tls_port` | openssl `SslAcceptor` 终结 | `next_server.run_openssl_task`（`mod.rs:211`） |
| `plain_quic_port` | quinn `ServerConfig` | `next_server.run_quic_task`（`mod.rs:322`，需 `quic` feature） |

配置建议：**先定义被引用的协议 server，再定义端口 server**，否则会先插入 DummyClose 占位。

---

## 6. 数据/控制流全景

```
                        serve 层内部
客户端 ──accept──► ListenTcpRuntime(g3_daemon)
                      │ run_tcp_task / run_rustls_task / run_openssl_task / run_quic_task
                      ▼
              XxxServer（协议实现）
                 ├─ drop_early()        ingress ACL
                 ├─ 认证                auth::UserGroup / FactsUserGroup → UserContext
                 ├─ 审计上下文          audit::AuditHandle → AuditContext
                 ├─ tokio::spawn Task   + ServerTaskNotes（阶段机）
                 ▼
              XxxTask::into_running()
                 ├─ 限流 / 并发 permit / dst_host_filter / dst_port_filter
                 ├─ egress_path_*  选下一跳 ──► escape::ArcEscaper.tcp_setup_connection() ──► 上游
                 ├─ 可选：inspect::stream::transit_with_inspection（协议解析/MITM）
                 └─ relay：copy_in_and_out + IdleWheel + IO 统计（RAII 守卫）
```

---

## 7. 新手上手建议路线

1. **先读 `mod.rs` + `registry.rs` + `ops.rs`**（约 400 行），理解"名字 → server → 监听"的关系与热加载五种动作。
2. **再读 `dummy_close/`**（最短），它是所有兜底逻辑的原型，能一遍读完三 trait 的实现骨架。
3. **然后读 `tcp_stream/`**——结构最标准的隧道型 server，`server.rs → common.rs → task.rs` 三件套是这个目录的模板。
4. **接着读 `intelli_proxy/`**，理解"server 引用 server + ArcSwap 原地更新"。
5. 按兴趣深入 `http_proxy`（流水线/CONNECT）或 `socks_proxy`（协商/UDP）或 `ftp_proxy`（控制+数据双通道改写）。
6. 想加新协议：实现 `Server + ServerInternal (+ AcceptQuicServer)`，在 `config::server::AnyServerConfig` 加变体，在 `ops.rs:292` 的 match 加分支，写 `XxxServerConfig`（含 `diff_action`）。

## 8. 常见坑速查

| 现象 | 可能原因 |
|------|----------|
| 连上就断、日志无提示 | 引用的 server 名不存在 → DummyClose（§4.7） |
| TLS 代理不生效 | 协议 server 的 `run_rustls_task` 是空实现——TLS 需由端口层终结 |
| `sni_proxy` 收到 TLS 却握手失败 | 被上游端口层提前终结了 TLS，`sni_proxy` 需要明文首包 |
| 大文件 FTP 上传卡住/重传 | 检查 `audit_bridge.rs:193` 描述的读写拆分是否被改动 |
| reload 后统计"消失" | 旧 server 进 `OFFLINE_SERVER_SET` 等待 drain，正常行为（§3.3） |
| 热改 escaper 无效果 | 需走 `update_dependency_to_escaper` → `_update_escaper_in_place`，检查 `Server::escaper()` 是否返回了正确名字 |
| 存活任务数一直不归零 | `XxxTask` 的 `Drop` / RAII `AliveGuard` 是否被绕过 |
