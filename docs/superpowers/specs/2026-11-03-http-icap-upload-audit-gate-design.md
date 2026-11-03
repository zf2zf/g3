# HTTP 上行 ICAP 送审判定与协议标签

日期：2026-11-03
状态：已与需求方逐条确认，进入实施

## 意图与背景

现场只对"值得看的内容"做 ICAP 上传审计：浏览器上传的文件。现在 HTTP 侧的送审判定是三套互不一致的规则，而且和请求体真实大小无关：

- HTTPS 拦截 h1（`g3proxy/src/inspect/http/v1/mod.rs:302-311`）：`chunked` 一律待定，定长体要求 `CL > req_body_min_size`；`req_hasbody: false` 时连无体请求也走送检分支。
- HTTPS 拦截 h2（`g3proxy/src/inspect/http/v2/forward/mod.rs:299-301`）：必须有体，且 `req_hasbody` 下按 `CL < req_body_min_size` 跳过——边界与 h1 相反（等于阈值时 h1 不审、h2 审）。
- 标准 http_proxy 转发（`g3proxy/src/serve/http_proxy/task/forward/task.rs:902-903`）：只看 `body_type().is_some()`，完全不看大小，登录框、搜索框、埋点这类几十字节的表单照样建一条 ICAP 会话。

同时 `X-Transformed-From` 现在写的是 `HTTP/1.0` / `HTTP/2.0`，那是"封装区报文按哪个协议版本序列化"的协议身份标签，不是需求方想要的"这条流量是明文还是 TLS、走的是 HTTP/1.1 还是 HTTP/2"。审计侧据此分流时拿不到 scheme。

## 目标

1. 三个上行送审点收敛成一条规则，且以 **Content-Length 头**为判据：`CL` 严格大于阈值才送审。
2. `chunked`（无 `Content-Length`）一律送审，字节保持**客户端原始分块帧**原样投递，另加一条标记头让审计侧知道自己拿到的是分块帧。
3. `x-www-form-urlencoded` 表单可按配置跳过——它没有文件内容可审。
4. `X-Transformed-From` 改为 `http` / `https`，协议版本移到新增的 `X-Http-Version`。

## 非目标

- 不做阻断式审计。判决仍在后台读，转发不等它（现有 fail-open 语义原样保留）。
- 不动下行（响应）审计：它由 `icap_respmod_service` 独立开关控制，现场未配置，本来就不审下行。
- 不引入"实测缓冲到阈值再挂 ICAP"那套：`Content-Length` 是判据之后不再需要。
- 不自动调高现场阈值（见"留给操作者的数"）。

## 已确认的规则

`req_hasbody: true`（现场已配）时，按顺序判定：

1. 无请求体 → 不审。
2. `Content-Type: application/x-www-form-urlencoded` 且 `req_skip_urlencoded_form: true` → 不审。
3. `Transfer-Encoding: chunked` → 审，原始帧直传 + `X-Body-Framing: chunked`。
4. 有 `Content-Length` → `CL > req_body_min_size` 才审，`X-Body-Framing: content-length`。
5. 其余（`ReadUntilEnd` 之类无法界定长度的隧道语义）→ 不审。

`req_hasbody: false`（库默认）保持兼容：有体即审，不做阈值与表单过滤。

需求方确认的两点前提：浏览器 `<form enctype=multipart/form-data>` 与 `fetch(body: FormData)` 都会带 `Content-Length`（文件长度客户端已知），所以"按 CL 判阈值"覆盖真实文件上传；拿不到 CL 的只有流式 `ReadableStream` 上传、`curl -T -`/管道、部分分片续传工具，以及 h2 里省略 `content-length` 的客户端——这些正是 chunked 那一档。

## 方案取舍

- **实测字节 + 达到阈值才挂 ICAP**（旁路拷贝先扣在缓冲里，越过阈值再发 ICAP 头并回放前缀）：唯一能在客户端谎报 `Content-Length` 时也准确的方案，但每条在途审计要占住阈值大小的缓冲（阈值 1 MiB × 并发 64 = 最坏 64 MiB），还要改 `bypass/mod.rs` 的中继循环。**否**：需求方指定以 `Content-Length` 为判据。留一条事实备查——g3proxy 转发请求体本来就按 `CL` 成帧（`HttpBodyReader`），"决策用的大小"与"上游实际收到的大小"同一依据，谎报 `CL` 的报文在成帧阶段就散了，审计不是那个缺口。
- **退成"有 body 就审"**：改动最小，但小表单继续进 ICAP，达不到减少送检量的目的。**否**。
- **转发前预读 N 字节再决策**：实现直白，代价是大文件上传的第一个字节要多等攒够 N 字节，慢客户端会占住上游连接。**否**。
- **选定**：决策点按头部声明判定（零缓冲、零额外内存、判定发生在建 ICAP 连接之前），`chunked` 单独全审。

`chunked` 的字节形态另有三选：解掉分块帧后送干净内容 / 保持原始帧加标记头 / 只送头不送体。需求方选**保持原始帧**，理由是不动 tap 的字节路径。代价必须知情：`HttpBodyReader` 刻意保留客户端原始成帧（`g3proxy/src/inspect/http/v1/forward/mod.rs:379-381`），tap 与上游读的是同一个 reader，而 ICAP 侧在外面又套了一层自己的分块帧（`bypass/mod.rs:578-583`），所以审计服务解出来的 body 是 `1a\r\n<数据>\r\n…0\r\n\r\n` 这种带十六进制长度行的原始流，需要自行解帧——`X-Body-Framing: chunked` 就是这件事的信号。带 `Content-Length` 的请求不受影响，body 就是干净的文件字节。

## 配置面

沿用 auditor 段 `h1_interception` 既有两键，新增一键（`lib/g3-dpi/src/config/http.rs`）：

```yaml
h1_interception:
  req_hasbody: true                 # 开启阈值与表单过滤；false 为兼容模式（有体即审）
  req_body_min_size: 8              # CL 严格大于此值才送审，单位字节
  req_skip_urlencoded_form: false   # 新增：跳过 application/x-www-form-urlencoded，默认关
```

新增键默认 `false`，不改任何未显式配置的部署行为；现场要生效就在 `deploy/conf/g3proxy.yaml` 打开。

## ICAP 头变化

同一旁路封装区，`X-Transformed-From` 之后按需追加两行：

```
X-Transformed-From: https          # 原 HTTP/1.0 | HTTP/2.0
X-Http-Version: 1.1                # 新增：0.9 | 1.0 | 1.1 | 2.0 | 3.0
X-Body-Framing: chunked            # 新增：content-length | chunked | stream
```

FTP 数据通道不变：`X-Transformed-From: FTP`，不带版本与成帧标记（那两个字段是 HTTP 专属）。

## scheme 从哪来

`StreamInspectContext` 今天没有 over-tls 标志，明文与 TLS 只能靠 `keylog_buffer` 是否为 `None` 反推——不可靠（keylog 是可单独关掉的配置）。所以给 `H1InterceptObject::new` / `H2InterceptObject::new` 加显式 `over_tls: bool`，六个调用点按实际来源填：`inspect/tls/mod.rs`（true）、`inspect/stream/object.rs`（false）、`serve/sni_proxy/task/relay/task.rs`（false）、`inspect/http/v1/upgrade/mod.rs`（沿用自身已有的 TLS 上下文）。标准 http_proxy 转发任务已有 `is_https` 字段，直接用。

落地时换了更省的做法：`StreamInspectContext` 加 `over_tls` 字段 + `mark_over_tls()`，只在 `TlsInspectObject::prepare_ctx()` 里置真。六个 `new` 调用点因此一个都不用改参数，upgrade→h2 那条克隆 ctx 的路径也自动继承标志。`is_https` 仍然直接用在标准转发任务上——注意它的既有含义是"转发目标是 https"，与拦截路径的"客户端侧是 TLS"是同一条标签的两种来源，取值都对。

## 留给操作者的数

`deploy/conf/g3proxy.yaml:50` 的 `req_body_min_size` 现在是 **8 字节**——等于"只要带体就远超阈值"，阈值实际不起作用。本次**不擅自改动**它（改了等于悄悄缩小审计范围）。要真正减少送检量，需求方按目标量级自己调（例如 4096 / 65536 / 1048576）。

## 一个已知的现有代价（本次不改，但记录）

ICAP 侧那条通道是容量 64 的有界通道且带背压（`bypass/mod.rs:490-496`）：ICAP 服务明显慢于上游时 `send()` 挂起，会反过来拖慢客户端读速率。阈值降低送检量对这件事有缓解，但"旁路绝不影响上传"只在 ICAP 跟得上时成立。

## 实现落点

判定只有一份，三个送审点各自在**建立 ICAP 会话之前**调它：

| 位置 | 调用 | 说明 |
| --- | --- | --- |
| `inspect/http/upload_audit.rs` | `h1_upload_audit` / `h2_upload_audit` / `scheme_tag` / `http_version_tag` | 唯一规则源，本模块 11 条单元测试 |
| `inspect/http/v1/mod.rs` | 主循环里判定，把 `body_type` + 形态一起交给 `H1ForwardTask::adapt_with_io` | 判不过就 `forward_with_io`，不建 ICAP 会话 |
| `inspect/http/v2/forward/mod.rs` | 请求头交给 `ups_req` 之前判定（借不到 `parts.headers` 之后就晚了） | 形态 `content-length` / `stream` |
| `serve/http_proxy/task/forward/task.rs` | `upload_audit_body()` → `take_upload_audit(body_framing)` | 名额与连接都在判定之后才占用 |

协议标签同时给非旁路的 reqmod 适配器（`reqmod/h1`、`reqmod/h2` 新增 `set_protocol_tag`），接入点：`v1/connect`、`v1/upgrade`、`v2/connect`，免得改写路径继续写 `HTTP/1.0`。RESPMOD（下行）的 `X-Transformed-From` 保持原样——本次只做上行。

## 验证记录

单元测试：`g3proxy --lib` 89 通过（含 upload_audit 11 条）、`g3-icap-client --lib` 26 通过、`g3-yaml --lib` 153 通过；`cargo clippy -p g3proxy -p g3-icap-client -p g3-yaml -p g3-dpi --all-targets` 零 error，新增代码零告警（残留的两条 too-many-args 与 doc-list 是改动前就有的）。

端到端（临时实例，未触碰 3128 上的现网进程）：`icap_echo_server` 于 127.0.0.1:1344，阈值 `req_body_min_size: 100`，源站收 POST 并回 200。

| 用例 | 承载 | 预期 | 实测 ICAP 头 |
| --- | --- | --- | --- |
| 57 B `Content-Length` | 明文转发 | 不审 | 无提交 |
| 305 B `x-www-form-urlencoded`，`req_skip_urlencoded_form: true` | 明文转发 | 不审 | 无提交 |
| 457 B `multipart/form-data`（浏览器上传形态） | 明文转发 | 审 | `http` / `1.1` / `content-length` |
| 272 B 分块 | 明文转发 | 审（长度不可先知） | `http` / `1.1` / `chunked` |
| 150 B / 50 B `octet-stream` | TLS 拦截 | 审 / 不审 | `https` / `1.1` / `content-length` |
| 305 B 表单，`req_skip_urlencoded_form` 缺省 | TLS 拦截 | 审 | `https` / `1.1` / `content-length` |

即 `http` 与 `https` 两条标签、表单开关的开与关都跑到了实处。未覆盖：**HTTP/2 送审点**（拦截实例未与客户端协商出 h2 ALPN，curl 回落到 1.1）与 `X-Body-Framing: stream`——这两条只有单元测试与代码走读支撑。现网 `req_body_min_size: 8` 依旧等于不筛，本次没有改动。
