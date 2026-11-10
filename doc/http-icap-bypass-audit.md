# HTTP 旁路上传审计（ICAP bypass upload audit）

面向运维与二线支持：说明 HTTP/HTTPS 上传审计到底审计什么、什么情况下会不审计、
出问题时看哪些日志字段，以及在部署环境怎么把它验一遍。

相关代码：

- `lib/g3-icap-client/src/reqmod/bypass/` —— 协议无关的旁路审计管线（FTP、HTTP/1、HTTP/2 共用）
- `g3proxy/src/serve/http_proxy/task/forward/task.rs` —— 明文 HTTP 正向代理上传
- `g3proxy/src/inspect/http/v1/forward/mod.rs` —— TLS 拦截后的 HTTP/1 上传
- `g3proxy/src/inspect/http/v2/forward/mod.rs` —— TLS 拦截后的 HTTP/2 上传
- `g3proxy/src/serve/audit_bridge.rs` —— 审计结束状态统一落日志（`log_bypass_audit_end`）

---

## 1. 这套审计做什么、不做什么

**只做采集，不做拦截。** 代理把请求头和请求体原样复制一份送给 ICAP，REQMOD 请求里
带 `Allow: 204`，意思是"你只需回一个 204 放行，不必返回改写后的报文"。ICAP 的响应
在后台读取，读完就把连接还给连接池；代理不会因为等 ICAP 的结论而卡住转发。

由此推出几条硬性质，排查问题时可以当作已知条件：

- ICAP 侧任何失败（连不上、写不进、判决慢、判决读不到）都**不会**让上传失败，
  最多是这一次上传少一份审计数据。
- 只有**带请求体**的请求才送检。GET / HEAD / 空体请求完全不碰 ICAP，不占用审计名额。
- **不审计下载方向**（响应体），也不做"只有请求头"的上报；那类通路已删除。
- CONNECT 隧道仍走原来的 reqmod 适配通路，行为未变。

## 2. 三个入口与协议来源标签

ICAP 侧用 `X-Transformed-From` 区分被采集的原始协议：HTTP 流量按客户端侧是否走 TLS
写 `HTTP` / `HTTPS`，FTP 数据通道写 `FTP`。协议版本与请求体成帧形态各占一条新头：

| 入口 | `X-Transformed-From` | `X-Http-Version` | `X-Body-Framing` |
|------|----------------------|------------------|------------------|
| 明文 HTTP 正向代理上传（`serve/http_proxy`） | `HTTP` / `HTTPS` | `1.0` / `1.1` | `content-length` / `chunked` |
| TLS 拦截 HTTP/1 上传（`inspect/http/v1`） | `HTTPS` | `1.0` / `1.1` | `content-length` / `chunked` |
| TLS 拦截 HTTP/2 上传（`inspect/http/v2`） | `HTTPS` | `2.0` | `content-length` / `stream` |
| FTP/FTPS STOR 上传（改造后共用同一管线） | `FTP` | 不发 | 不发 |

`X-Transformed-From` 早先是 `HTTP/1.0` / `HTTP/2.0`——那是"封装区按哪个版本序列化"的身份
标签，审计侧拿不到 scheme。现在 scheme、版本、成帧形态三者分列，取值都由
`g3proxy/src/inspect/http/upload_audit.rs` 一处给出。

`X-Body-Framing` 告诉审计服务 req-body 区里的字节要不要先解一层分块帧：客户端用
`Transfer-Encoding: chunked` 上传时，代理刻意把原始帧原样投给源站（`HttpBodyReader`），
旁路 tap 与上游读的是同一个 reader，于是 ICAP 侧在自己的分块外面又套了一层——审计侧看到
的就是 `1a\r\n<数据>\r\n…0\r\n\r\n` 这种带十六进制长度行的原始流。`content-length` 与
`stream` 两档的 req-body 就是请求体本身。

HTTP/2 送出去的请求头是**伪 HTTP/1.1 报文头**：由 `:method` / `:path` 还原请求行，
`Host` 缺失时用 URI 的 authority 补齐，`TE` 一类的逐跳（hop-by-hop）头剔除。这样做是
为了兼容只认 HTTP/1.x 封装格式的 ICAP 检测模块。

## 3. 一笔请求是否被审计：开关链

按代码里的实际判定顺序（判定全部在 `inspect/http/upload_audit.rs`，三个入口共用，且都发生
在**建立 ICAP 会话之前**）：

1. auditor 配置里有 `icap_reqmod_service`（没有则整条链路不启用）。
2. 请求带请求体。GET / HEAD / 空体请求不建 ICAP 会话。
3. `Content-Type: application/x-www-form-urlencoded` 且
   `h1_interception.req_skip_urlencoded_form: true` → 跳过。登录框、搜索框、埋点这类
   键值对没有文件可审。浏览器上传文件的 `multipart/form-data` 不受本项影响。
4. 若 `h1_interception.req_hasbody: true`：`Content-Length` **严格大于**
   `req_body_min_size` 才送检；长度无法预先得知（`chunked`、h2 省略 `content-length`）
   一律送检。`req_hasbody: false` 是兼容模式——有体即审，阈值不参与。
5. 取并发名额 `upload_audit_max_concurrency`（默认 64，`0` 表示不设限）。
   **名额用尽时不排队**：本笔请求直接走无审计直通转发，并在任务日志里记一次跳过。
6. 从 ICAP 连接池取连接（池空则新建）。取不到 / 建连失败：打一条 warn 日志，
   本笔走无审计直通转发。注意这条路径**不计入跳过数**——跳过数只统计名额耗尽。
7. 进入旁路管线：同一份数据一边写给源站、一边重新分块送给 ICAP。

## 4. ICAP 服务端会收到什么

一次上报的 ICAP 请求形如（示例来自仓库内的线格式断言测试）：

```
REQMOD icap://<icap-host>:1344/<service> ICAP/1.0
Host: <icap-host>
Allow: 204
X-Transformed-From: HTTPS
X-Http-Version: 2.0
X-Body-Framing: content-length
X-Client-Session-ID: 3cfedfcbdce311f1af9c1db8b9f0da3c
X-Client-IP: 203.0.113.7
X-Client-Port: 5555
X-Client-Username: alice
X-Authenticated-User: TG9jYWw6Ly9hbGljZQ==
X-Proxy-IP: 192.0.2.1
X-Proxy-PORT: 8080
X-Remote-IP: 198.51.100.9
X-Remote-PORT: 21
X-Proto-P: 6
X-TLS-VERSION: TLSv1.3
X-TLS-CIPHER-SUITE: 4866
X-TLS-CLIENT-RANDOM: <hex>
X-TLS-SERVER-RANDOM: <hex>
X-TLS-CLIENT-TRAFFIC-SECRET: <hex>
X-TLS-SERVER-TRAFFIC-SECRET: <hex>
X-TLS-CLIENT-HANDSHAKE-TRAFFIC-SECRET: <hex>
X-TLS-SERVER-HANDSHAKE-TRAFFIC-SECRET: <hex>
X-TLS-EXPORTER-SECRET: <hex>
Encapsulated: req-hdr=0, req-body=<offset>

<原始请求头字节，以 \r\n\r\n 结尾>
<hex 长度>\r\n<请求体裸字节>\r\n
...
0\r\n\r\n
```

字段含义：

- `X-Client-Session-ID`：本次上报所属的客户端连接，不带 `-` 的 UUID；同一条长连接
  上的多次上报取值相同，审计侧据此把同一会话的多个请求关联起来。
- `X-Client-IP` / `X-Client-Port`：发起上传的客户端地址。
- `X-Client-Username` 明文用户名；`X-Authenticated-User` 是
  base64(`Local://<用户名>`)，沿用 Squid 系 ICAP 生态的惯例，有些检测模块只认后者。
- `X-Proxy-IP` / `X-Proxy-PORT` / `X-Remote-IP` / `X-Remote-PORT` / `X-Proto-P`：
  连接四元组（代理侧地址与远端地址、协议号，TCP=6），供审计侧关联 repid。
- `X-TLS-*`：TLS 会话的版本、加密套件、两个握手随机数（通用四条）与本次握手的密钥
  （TLS 1.2 的 `X-TLS-MASTER-SECRET`，TLS 1.3 的四条流量密钥加 `X-TLS-EXPORTER-SECRET`），
  审计服务用它解密对应会话。
  只有开启 `tls_keylog` 且该会话产生了 keylog 时才有。
- `Encapsulated:` 的 `req-body` 偏移 = 封装请求头的字节数；请求体是**代理转发给源站的
  同一份字节**（不解包内容编码：上传的是 gzip 就仍是 gzip；客户端用 `Transfer-Encoding:
  chunked` 时分块帧也会原样保留），再按 ICAP 要求的分块格式重新封装一层，结尾固定
  `0\r\n\r\n`。也就是说 ICAP 侧读到的是"线格式"，审计模块如需文件原文，要自己再做一次
  分块解码与内容解码。FTP 通路没有这个问题：它拿到的是数据通道上的裸文件字节。

## 5. 失败面：每种失败代理怎么处理

| 现象 | 代理行为 | 转发是否受影响 |
|------|----------|----------------|
| ICAP 连不上 / 建连失败 | warn 日志 + 无审计直通转发 | 否 |
| 审计名额用尽 | 直通转发，`upload_audit_skipped: true`，累计计数 +1 | 否 |
| 写 ICAP 头 / 体失败 | 停止本笔审计，数据继续送源站 | 否 |
| ICAP 判决慢 | 数据已送完即返回，判决交后台任务读取并回收连接 | 否 |
| 判决读不到 / 报文异常 | 只影响审计日志字段，不回头阻断 | 否 |
| 客户端请求体半程被掐断（空闲看门狗、流被 reset） | 不给源站发结束标记，本条流以错误终止 | **是**（源头数据不完整，不能假装传完） |
| 用户被封禁 / 服务强制退出 | 下一个空闲 tick 掐断本流 | 是（策略行为，与审计无关） |

最后一行是唯一的例外：**请求体本身不完整时转发会终止**。因为 HTTP 请求体的结束由
报文自身的标记（`Content-Length` 用完 / END_STREAM / TRAILERS）表示，代理没有能力
"替客户端编一个结束"。半程掐断只能重置这条流。

## 6. 日志字段与跳过计数

HTTP 转发任务日志里与旁路上报相关的字段：

- `upload_audit_skipped`：本笔请求是否因名额耗尽而没审计（布尔）。
- `upload_audit_skipped_total`：该审计器累计跳过笔数。
- `upload_audit_bytes`：本笔实际送给 ICAP 的字节数。
- `dur_req_send_all`：请求体全部送达源站的耗时（回填自管线的 `dur_ups_send_all`）。

判断"是不是 ICAP 拖了后腿"：

- `upload_audit_skipped_total` 持续增长、而 `upload_audit_bytes` 不再增长 → 名额不足，
  调大 `upload_audit_max_concurrency`，或扩容 / 排查 ICAP 服务处理能力。
- 大量 `bypass ICAP adapter creation failed, forward without audit: ...` → ICAP 不可达
  或连接池耗尽，此时上传照常，但审计数据在缺失。
- 上传延迟本身不会因为 ICAP 变慢而升高：管线是全量转发后再后台读判决。

想直接看送审内容而不再抓包，把 auditor 的 `icap_reqmod_service` 改成 map 形态并打开
`log_audit_header`（别名 `audit_log_header`，默认 false）：

```yaml
    icap_reqmod_service:
      url: icap://127.0.0.1:1344/icap_audit
      log_audit_header: true
```

每发一条送审就打印一条 `Bypass ICAP audit header (...)`，几十行：第一行是字节数，
接着是 ICAP 请求头，再是封装的 HTTP 请求头——正文一个字节都不打，`X-TLS-*` 密钥行的
值屏蔽成 `***`。开关关着时这段内容仍按 debug 级打，开关只是免去逐条改代码或抓包。

这条日志是 info 级，g3proxy 检测到开关打开会自动把库日志的级别门限放到 info，
`journalctl -u g3proxy -f` 直接可见，不用改 `ExecStart` 加 `-v`；开关关着时那条
debug 仍需 `-vv` 才看得到。

想看全一条记录，用 journalctl 自己的过滤，别再管道接 `grep`——管道按行过滤，一条记录
只有第一行带这个串，于是只剩那行字节数，内容看着像没打出来：

```sh
journalctl -u g3proxy -f --grep 'Bypass ICAP audit header' -o cat
# systemd < 247 没有 --grep：journalctl -u g3proxy --since "-10min" | grep -A40 'Bypass ICAP audit header'
```

## 7. 在部署环境把链路验一遍

前置：ICAP 服务可用（例如仓库自带的 `g3icap`，或 c-icap 的示例服务）、代理 auditor 里
`icap_reqmod_service` 指向它、客户端信任代理的拦截 CA。抓 ICAP 侧报文：
`sudo tcpdump -i lo port 1344 -w audit.pcap`（Linux 是 `lo`，BSD 是 `lo0`）。

四组上传场景，四组都应当成功，ICAP 侧都应收到 REQMOD 且三个协议标签都正确：

```sh
# 1) 明文 HTTP/1，带 Content-Length 的请求体
#    -> X-Transformed-From: HTTP, X-Http-Version: 1.1, X-Body-Framing: content-length
curl -x 127.0.0.1:10087 -H 'Content-Type: application/octet-stream' --data-binary @file http://origin.example/upload
# 2) 明文 HTTP/1，分块请求体
#    -> X-Transformed-From: HTTP, X-Http-Version: 1.1, X-Body-Framing: chunked
curl -x 127.0.0.1:10087 -H 'Content-Type: application/octet-stream' -H 'Transfer-Encoding: chunked' --data-binary @file http://origin.example/upload
# 3) TLS 拦截的 HTTP/1 POST
#    -> X-Transformed-From: HTTPS, X-Http-Version: 1.1, X-Body-Framing: content-length
curl -x 127.0.0.1:10087 -H 'Content-Type: application/octet-stream' --cacert proxy-ca.pem --data-binary @file https://origin.example/upload
# 4) TLS 拦截的 HTTP/2 PUT（h2 上传）
#    -> X-Transformed-From: HTTPS, X-Http-Version: 2.0, X-Body-Framing: content-length
curl -x 127.0.0.1:10087 --http2 --cacert proxy-ca.pem -T file https://origin.example/put
```

两个坑，都会让人误判"审计没生效"：

- `curl --data` / `--data-binary` 不给 Content-Type 时自带 `application/x-www-form-urlencoded`，
  开了 `req_skip_urlencoded_form` 就会被表单规则拦掉——想测文件上传形态就显式给一个
  `application/octet-stream`，或者用 `-F`（multipart）/ `-T`。表单判断在成帧判断之前，
  所以分块 + 表单类型同样不送审。
- 第 4 条要真跑出 `2.0`，**源站必须支持 h2**：TLS 拦截时代理把自己与客户端协商的 ALPN
  跟着源站的结果走（`inspect/tls/modern.rs:218-223`），源站只会 HTTP/1.1 时客户端就回落
  到 1.1，标签也就成 `1.1` 了。本地起一个 h2 源站最省事，例如
  `node -e 'require("http2").createSecureServer({key,cert},(q,s)=>{q.resume();q.on("close",()=>{s.writeHead(200);s.end("ok\n")})}).listen(18444,"0.0.0.0")'`。

`X-Transformed-From` 只表示协议方案（`HTTP` / `HTTPS`，与既有的 `FTP` / `SMTP` / `IMAP`
同为大写），版本号一律看 `X-Http-Version`；两者都由客户端侧实际是什么决定，与转发目标
无关。
对照检查：封装区里的请求头字节应与客户端实际发出的请求头一致（h2 是伪 HTTP/1.1 形式），
`req-body` 偏移与请求头长度一致，重组后的分块内容长度应等于上传文件长度。

fail-open 验证：停掉 ICAP（例如 `sudo pkill c-icap`）再跑上面四条。四条都应当照常成功，
代理日志里只出现 warn，且这些请求**不计入** `upload_audit_skipped_total`。

跳过计数验证：把 auditor 配置改成 `upload_audit_max_concurrency: 1` 并重启，并发两笔上传：

```sh
curl -x 127.0.0.1:10087 --data-binary @file http://origin.example/upload &
curl -x 127.0.0.1:10087 --data-binary @file http://origin.example/upload &
wait
```

两笔都应成功返回；日志里其中一笔 `upload_audit_skipped: true`，`upload_audit_skipped_total` 加一。

FTP 回归：按原 FTP 场景跑一次 STOR 上传，ICAP 侧报文应与改造前一致
（`X-Transformed-From: FTP`、同样的四元组与 keylog 头、同样的分块请求体）。

## 8. 仓库内已有的自动化证据

以下行为由单元测试固定，改动这块代码后用这三条命令回归：

```sh
cargo test -p g3-icap-client --lib      # 旁路管线：204 采集、四元组/keylog/用户名头、
                                        # Encapsulated 偏移、chunked 重编码、fail-open 兜底、
                                        # 客户端半程 EOF、慢判决后台化、上游半关闭可关
cargo test -p g3-h2 --lib              # HTTP/2 体收发：TRAILERS 与 END_STREAM 收尾、
                                        # 截断体判定为 Incomplete、送检请求头字节
cargo test -p g3proxy --features vendored-c-ares --lib   # 审计器配置（含
                                        # upload_audit_max_concurrency 默认 64 / 0 不设限 /
                                        # 非法值报错）、名额耗尽跳过计数、日志字段、
                                        # 送审判定规则（inspect/http/upload_audit.rs，12 条）
```

§7 的判定与标签部分已在本机沙箱跑通：`g3icap`（`cargo run -p g3icap`；当时还是
`lib/g3-icap-client` 的 example `icap_echo_server`，现已提升为独立 crate）当 ICAP、
g3fcgen 签发的拦截 CA、本地 HTTP/1.1 与 HTTP/2 源站各一个，共 14 笔请求、9 笔送审，
`HTTP` / `HTTPS`、`1.1` / `2.0`、三种 `X-Body-Framing`、表单开关的开与关都对上了；
真 c-icap 服务与 FTP 实传属于现网复核项，沙箱内没有执行。

回归时若 `g3-icap-client` 里 `reqmod::bypass::tests::test_upstream_half_close_is_optional`
报 `failed to get icap service options: invalid value for header Allow`，那是本仓库改动前
就存在的抖动（约两次里挂一次，挂在同一 client 上第二次建 adapter 的连接池/OPTIONS 复用），
重跑即可，不是这次的改造引入的。
