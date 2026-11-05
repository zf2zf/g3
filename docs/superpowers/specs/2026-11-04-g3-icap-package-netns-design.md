# g3 ICAP 服务端独立 run 包 + 三服务同命名空间部署

## 意图与背景

现网把 g3proxy 装进 VPP 那侧的网络命名空间（默认 `/run/netns/ns-vpp`），但包里只有
`g3proxy.service` 带 `NetworkNamespacePath`：`deploy/systemd/g3proxy.service:9` 的 `@NETNS@`
占位符在打包时展开，`deploy/systemd/g3fcgen.service` 根本没有这个占位符，README/VERSION 也
明确写着"只有 g3proxy 进入，g3fcgen 与 ICAP 留在 host"（`deploy/build_run_package.sh:331`）。

后果是 g3proxy 一进 ns，`127.0.0.1` 就成了该命名空间自己的回环，它两个回环依赖全都落在
host：`tls_cert_generator` 连的 g3fcgen(2999) 和 `icap_reqmod_service` 连的 ICAP(1344)。
文档只能把这条写成"vpp 侧自己配一套，或者把地址改成能跨命名空间到达的"
（`doc/deploy-run-package.md` 1.6 节），`install.sh` 也只检查命名空间存不存在
（`deploy/install.sh:168`），检查不了里面的服务通不通。

本次要求：**g3proxy、g3fcgen、ICAP 服务端三者部署在同一个网络命名空间里**，回环地址直接
通用。ICAP 服务端作为**另一个安装包**交付，并且和 g3 包一样要考虑目标机的 glibc 与依赖库
问题（Kylin V10 / RHEL8 那一档，glibc 2.28，装完报 `version 'GLIBC_2.34' not found`）。

现状事实：本仓库唯一的 ICAP 服务端是 `lib/g3-icap-client/examples/icap_echo_server.rs`
（基于第三方 `icap-rs`，默认监听 `127.0.0.1:1344`，注册 echo/reqmod/respmod）。它只是
example，没有构建与安装路径。本次把它**提升为正式的 workspace crate 与服务形态**，
不再放在 examples 下。

## 目标

- `g3icap` 成为独立 crate 与可执行服务：有自己的 CLI 参数、能被打包、能被 systemd 托管、
  收 SIGINT 优雅收尾。
- `deploy/build_run_package.sh` 能产出两个包：g3（g3proxy + g3proxy-ctl + g3fcgen）与
  icap（g3icap），两者共用同一套 `--portable/--static`、同一套命名空间展开、同一个自解压
  `.run` 生成逻辑。
- 三个单元（g3proxy / g3fcgen / g3icap）的 `NetworkNamespacePath` 由同一个 `NETNS_PATH`
  决定；`--netns=no` 时三个都不带命名空间指令。
- 安装阶段拦住"不同命名空间"这种装法：两个包的安装脚本都要判定路径一致，不一致就失败并
  给出可执行的修法。
- 包内说明（README/VERSION/`doc/deploy-run-package.md`）改口径：三个服务同 ns，
  `127.0.0.1:2999/1344` 在 ns 内可达才是正确状态。

## 非目标

- 不做 ICAP 服务端的生产化改造：不加 TLS(ICPS)、不加配置文件、不做连接池/配额、不替代
  真实审计引擎。它是"审计链路末端的回显与旁路确认"服务，形态上按服务交付，行为保持
  example 时代的逐段打印。
- 不接管命名空间的创建：ns 仍由 vpp 侧或 `ip netns add` 建，systemd 只负责进去。
- 不把 ICAP 包并进 g3 包（明确要求"另一个安装包"）。
- 不动现网 :3128 上的 g3proxy 进程；不改 `deploy/conf/g3proxy.yaml` 里
  `icap://127.0.0.1:1344/echo` 这个地址。

## 方案取舍

**怎么给 ICAP 打第二个包**

- **A. 同一个脚本加 `--component=g3|icap`（采用）**：portability 开关、`--static` 的
  `RUSTFLAGS`/`--target` 补齐、命名空间展开、单元渲染、静态链接断言、`.run` 自解压头部
  全部只有一份。两个包的"能在老 glibc 上跑"这件事不会各自漂移。代价是 g3 专属步骤
  （CA、两份 yaml、`g3proxy -t -c` 自检、feature 裁剪清单）要按 component 分支。
- **B. 另写 `deploy/build_icap_package.sh`**：脚本更短更直白，但 `--static` 的规则和自检
  断言要复制一份。需求里"也要考虑 glibc 及依赖库"恰恰是要这个规则单点定义，复制等于埋雷。
- **C. 一个包三个服务**：与"另一个安装包"冲突。而且带 CA 私钥的 g3 包和不带任何敏感物的
  ICAP 包分发约束不同，生命周期也不该绑在一起。

**g3icap 的代码放哪**

- **提升为顶层 crate `g3icap/`（采用）**：仓库惯例就是一个可交付程序一个顶层 crate
  （`g3proxy/`、`g3fcgen/`、`g3mkcert/`、`g3bench/`）。`icap-rs` 从 `g3-icap-client` 的
  dev-dependencies 移出来，`g3-icap-client` 回到"纯客户端库"的定位。
- 在 `lib/g3-icap-client` 里加 `[[bin]]`：改动小，但要把 `icap-rs`、`tracing-subscriber`
  变成库的正式依赖，下游拿客户端库会被塞进一个服务端依赖。
- 继续用 `cargo build --example`：零改动，但产物路径在 `target/.../examples/`，一个要装到
  客户机器上的服务不该由 example 供给——这也是这次要解决的问题本身。

## 设计

### 1. g3icap crate

```
g3icap/
├── Cargo.toml          # name = "g3icap"，version 对齐 g3proxy 的 1.13.0 线？见"留给实现"
└── src/main.rs         # 由 examples/icap_echo_server.rs 提升而来
```

- workspace `members` 加 `"g3icap"`；`icap-rs`、`tracing-subscriber` 进
  `[workspace.dependencies]`，`lib/g3-icap-client` 的 dev-dependencies 删掉这两项
  （`icap_perf_test.rs` 两者都不用到，已核实）。
- CLI 换成 clap（仓库统一 `clap` + `g3-clap`）：
  - `--listen <addr>`，默认 `127.0.0.1:1344`；
  - `--service <a,b,c>`，默认 `echo,reqmod,respmod,icap_audit`。加 `icap_audit` 是因为
    FTP 审计侧配置用的是 `icap://127.0.0.1:1344/icap_audit`
    （`etc/g3proxy/ftp/auditor.d/ftp_auditor.yaml:26`），默认服务表要能同时接住 HTTP 与
    FTP 两条链路；
  - `--max-body-print <N>`，默认 512（取代 `G3_ICAP_ECHO_MAX_BODY` 环境变量，日志截断长度
    属于运维参数而不是环境变量后门）；
  - `--version` / `--help`。
- 监听地址与服务的 positional 旧用法**不做兼容**：这是新交付形态，第一次打包就定下来。
- 信号：SIGINT/SIGTERM 走 `run_until` 的优雅收尾（现在只有 ctrl_c，即 SIGINT；SIGTERM 是
  systemd 默认停止信号，要一并接住）。
- 日志：`tracing-subscriber`，`with_ansi(false)`，请求 dump 保持打印到 stdout，由 journald
  收（配置风格与 g3proxy 的 `log: stdout` 一致）。

### 2. 单元模板与命名空间展开

- `deploy/systemd/g3fcgen.service`：在 `[Service]` 里加一行 `@NETNS@`（位置与 g3proxy 一致）。
- 新增 `deploy/systemd/g3icap.service`：`Type=simple`、
  `ExecStart=@PREFIX@/bin/g3icap --listen @ICAP_LISTEN@`、`@NETNS@`、
  `ExecStop=/bin/kill -INT $MAINPID`、`Restart=on-failure`、
  `RestartPreventExitStatus=255`。没有控制套接字，不需要 `RuntimeDirectory` 与 `-G`。
- `build_run_package.sh` 现有的 `NETNS_LINES`/`render_systemd_unit()` 一处展开、三个单元共用，
  逻辑不变，只是渲染的目标从 1 个变 2 个（g3 包）+ 1 个（icap 包）。
- `NETNS_NOTE`/VERSION 行从 `network namespace (g3proxy only)` 改成
  `network namespace (g3proxy+g3fcgen)` / `(g3icap)`，值都是同一个 `NETNS_PATH`。

### 3. 打包脚本的 component 维度

```
deploy/build_run_package.sh                      # 默认 --component=g3，行为与现在一致
deploy/build_run_package.sh --component=icap --static   # ICAP 包，静态
```

component 决定这几件事，其余（`--profile/--target/--dist-dir/--netns/--portable/--static`）
两个包共用：

| 项 | g3 | icap |
| --- | --- | --- |
| 编译目标 | `-p g3proxy -p g3proxy-ctl -p g3fcgen` | `-p g3icap` |
| 进包可执行 | `g3proxy g3proxy-ctl g3fcgen` | `g3icap` |
| 单元 | `g3proxy.service` `g3fcgen.service` | `g3icap.service` |
| 配置 | `g3proxy.yaml` `g3fcgen.yaml` + CA | 无（参数写在单元里） |
| 包名 | `g3-run-<ver>-<sha>-<arch>-<date>` | `g3icap-run-<ver>-<sha>-<arch>-<date>` |
| 安装前缀 | `/opt/zf/g3` | `/opt/zf/icap` |
| 打包自检 | `g3proxy -t -c conf/g3proxy.yaml` | `g3icap --version`（证明包里这个二进制能在构建机跑起来） |
| 静态自检 | 对 `RUN_BINS` 逐个断言 | 同一套断言，只是 `RUN_BINS` 只有 `g3icap` |

`--portable` 在 icap 组件下**不追加任何 feature**：`g3icap` 依赖是纯 Rust
（`icap-rs` + `tokio` + `tracing-subscriber` + `http`），既没有 pyo3/lua54 要裁，也没有
OpenSSL/c-ares 要内置。开关照旧接受，只为让两个包的命令行保持一致；glibc 那层（`--static`）
才是它对老系统的实际手段。

### 4. 安装脚本

- **g3 `deploy/install.sh`**：命名空间检查从"只读 g3proxy 单元"改为"读包内两个单元的
  `NetworkNamespacePath`"，要求两者都有且相等（不等就是打包出了岔子），存在性检查照旧；
  报错文案里"127.0.0.1 的 g3fcgen 与 ICAP 必须在 ns 里可达"改为"ICAP 请用 g3icap 包装进
  同一个命名空间"。g3fcgen 起不来的现有兜底（CA 检查）不动。
- **icap `deploy/icap-install.sh`**：装 `bin/g3icap` + `g3icap.service` 到 `/opt/zf/icap`，
  然后：
  1. 命名空间路径存在性检查（同 g3）；
  2. **跨包一致性检查**：若 `/etc/systemd/system/g3proxy.service` 或 `g3fcgen.service` 已
     存在，取它们的 `NetworkNamespacePath` 与本包比较，不一致直接失败退出——不一致的后果是
     g3proxy 在自己 ns 里连 `127.0.0.1:1344` 打到空气上，审计静默丢失，比装不上更难查；
  3. g3 单元还没装时跳过比较，打印安装顺序提示；
  4. 启动 `g3icap`，`enable --now`。
- **两个包共用的可选连通性自检**：目标机有 `nsenter` 时，在 ns 内试连 `127.0.0.1:2999` 与
  `127.0.0.1:1344`，把通/不通打出来，**不作为失败条件**（谁先装谁后装都合法，装第一个包时
  另一个必然还没起）。这是把今天"检查不了里面的服务通不通"补成"至少能看一眼"。
- **卸载**：`deploy/icap-uninstall.sh` 只停/摘 `g3icap.service` 与删 `/opt/zf/icap`，绝不
  碰 g3 的单元和目录。g3 的 `uninstall.sh` 也不反向碰 icap。

### 5. 文档

`doc/deploy-run-package.md`：1.6 命名空间一节改写成"三服务同 ns"契约 + 两个包的命令行；
新增一节讲 `g3icap` 包（用途：验证审计链路末端、压测旁路、真实 ICAP 未就位时的占位）；
包内结构、安装流程步骤、`--netns` 参数表、README 样例段落同步。
`doc/http-icap-bypass-audit.md:225` 与 `doc/g3-icap-client新手入门.md` 里对
`cargo run --example icap_echo_server` 的引用改为 `cargo run -p g3icap`。
脚本头注释（`-h` 输出）里"g3fcgen 与 ICAP 服务不进 ns"那句是错的，一并改。

## 留给实现者的判断

- `g3icap/Cargo.toml` 的 `version`：按 `g3fcgen` 那样独立起号（0.1.0）还是对齐 g3proxy
  线。取**独立起号 0.1.0**——包名里的版本串取自 `g3proxy/Cargo.toml`（现有逻辑），icap 包
  沿用同一个来源，避免同一批交付出现两个版本号语义。故 `g3icap` 自身 version 用 0.1.0，
  包名版本仍走 g3proxy 的 1.13.0。**（我的判断）**
- icap 包的 `--listen` 默认值写死在单元模板里（`127.0.0.1:1344`），与 `g3proxy.yaml` 的
  `icap://127.0.0.1:1344/echo` 对齐；端口要改就走 `systemctl edit g3icap`，不在 install.sh
  里做交互。**（我的判断：g3 包只对 g3proxy 监听端口做了首次安装交互，ICAP 是调试/占位
  服务，不值得同样待遇）**
- 跨包一致性检查在"g3 已装但单元里没有命名空间指令"（NETNS=no 的包）时的处理：视为
  host，与本包的 ns 不一致 → 失败，并提示用 `--netns=no` 重打 icap 包。**（我的判断）**

## 验证口径

1. `cargo build -p g3icap` + `cargo run -p g3icap`，`icap_perf_test` 连上取一次 204/200 闭环。
2. `deploy/build_run_package.sh --component=icap --static --netns=/run/netns/ns-vpp`，
   产物 `ldd` 为 `statically linked`、`objdump -T | grep -c GLIBC_` 为 0（脚本自检已覆盖）。
3. `sh -n` 全部脚本；`--component=g3` 默认路径产物与改动前对比：单元多一行 `@NETNS@` 展开，
   其余结构不变。
4. 命名空间契约：本机 `ip netns add` 建一个临时 ns，装 icap 包（PREFIX/SYSTEMD_DIR 后门
   指向临时目录）→ 断言单元里 `NetworkNamespacePath` 正确、g3 单元不一致时安装失败、
   `nsenter` 连通性自检能报出 1344 在 ns 内监听。
5. 现网 :3128 不重启、不替换；临时进程装完清理（端口驱动的 `ss -lntp` 扫尾）。

## 复核（builder check）之后的三处落定

评审提的三个问题，以及最终实现采用的答案：

1. **跨包检查必须双向**。原稿只给 icap 包写了"看已装的 g3 单元"，反过来 g3 包先装、icap
   后装时没人核对。实现里 `deploy/install.sh` 与 `deploy/icap-install.sh` 各自既查本包内单元
   之间一致（g3 包要求包内 `g3proxy` 与 `g3fcgen` 的 `NetworkNamespacePath` 相等，不等即
   "这个包自己就不对"），也查目标机上已装的对端单元，任一侧不一致都在**写任何系统目录之前**
   失败。谁先装都拦得住。
2. **`.run` 头部保持一份**。安装器头部脚本只认包内的 `install.sh`/`uninstall.sh` 两个名字，
   不为第二个组件复制一份头部：icap 组件把 `deploy/icap-install.sh`、`deploy/icap-uninstall.sh`
   以 `install.sh`/`uninstall.sh` 的名字打进包，头部里唯一的差异（默认前缀、一句话的装法说明）
   用 `@PKG_SUMMARY@`/`@INSTALL_PREFIX@` 占位符由组件表填。头部只做"解包 → 调 install.sh"。
3. **包名与版本号的语义**。包名与 `VERSION` 的 `g3proxy version:` 仍取 `g3proxy/Cargo.toml`
   （一次交付一个版本串），`g3icap` crate 自己按 `g3fcgen` 的做法独立起号 0.1.0；
   `VERSION` 增加 `component:`、`install prefix:`、`cargo features:`、`network namespace:`
   四行，把"这份包属于哪个组件、装到哪、进哪个 ns"写在产物里。icap 包的自检相应换成
   `g3icap --version`。

## 验证结果（2026-11-04）

- `cargo build -p g3icap` / `cargo clippy -p g3icap` 通过；`g3-icap-client` 的
  `icap_perf_test` 去掉 example 依赖后仍可编译；实跑 ICAP OPTIONS/REQMOD 闭环、SIGTERM
  优雅退出（本轮实现前的沙箱验证）。
- `deploy/build_run_package.sh --component=icap --static`：产物 `g3icap` 为
  `statically linked` 且 `objdump -T` 无 `GLIBC_` 版本要求；`--component=g3 --static` 默认
  路径产物结构与改动前一致，只是 `g3fcgen.service` 现在也带上了 `NetworkNamespacePath`。
- `sh -n` 全部脚本通过；`.run` 能正确解包并派发（尾部负载 `tar tzf` 可独立解开，
  头部拒绝命令行参数）。
- 命名空间契约用临时 ns（`/run/netns/g3pkgtest`）+ `systemctl` 桩跑了 11 组用例：包内两单元
  不等、跨包不等（含对端在 host 而本包在 ns 的方向）、命名空间不存在（失败且未写任何文件）、
  同 ns 正常装成（单元占位符展开、`ExecStart` 指向安装前缀）、ns 内 2999/1344 探测只提示、
  对端未装只提示、包结构自检、icap 卸载只摘 `g3icap.service` 且保留 g3 单元与目录、
  在包目录里执行卸载脚本时整包原样保留。全部通过。
- 现网 `g3proxy` :3128 全程未接触：所有 `systemctl` 调用都走桩，测试完临时 ns 已删除。
