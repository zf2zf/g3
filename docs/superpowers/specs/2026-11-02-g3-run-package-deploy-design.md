# g3 run 包编译与部署设计

日期：2026-11-02
状态：已实现并在真实 Linux 机（本机兼构建机/目标机）完成 §11 的 V1–V7 验证（debug 包；
正式发布用 release 包，同一脚本同一链路）
范围：`deploy/`（新增构建脚本、安装脚本、卸载脚本、systemd 单元模板、入口配置）、`doc/deploy-run-package.md`、`.gitignore`
需求来源：需求方明确要求——"增加编译部署脚本，部署程序最终以 run 包的方式提供，包含必要的
可执行程序（如 g3proxy、g3fcgen 等），一个配置文件，以 service 方式部署；二进制程序和配置文件
部署在同一个目录 `/opt/zf/g3/` 下，放 bin、conf 等"。
同日补充三条修订（覆盖本文档初版的对应决定）：

1. 交付物是**一个可执行的 `.run` 自解压安装器**，目标机直接运行即完成安装，不是"解包目录
   后再跑 install.sh"；
2. 安装**固定目录与内容，不提供任何命令行选项**；卸载脚本随安装落到 `/opt/zf/g3/uninstall.sh`；
3. **g3fcgen 是必须的服务，默认安装并启动**（核实：auditor 的 `tls_cert_generator` 运行时连
   `127.0.0.1:2999` 向 g3fcgen 按 SNI 取 MITM 证书，缺它 HTTPS 拦截整体失效）。CA 由**构建**
   保证随包：`deploy/conf/` 有成套 `myCA.*` 就用，没有则构建时 `g3mkcert` 自动生成一份自签根
   写回 `deploy/conf/` 复用——安装时不提醒、不要求现场准备 CA。
   另：入口配置**扁平化为单个 `g3proxy.yaml`**（server/auditor 内联，g3proxy 的
   `HybridParser` 原生支持内联数组），不再有 `conf/server.d/`、`conf/auditor.d/`。

## 1. 意图与背景

HTTP 旁路上传审计（见 `docs/superpowers/specs/2026-11-01-http-icap-bypass-upload-audit-design.md`）
落地后，交付仍是手工的：`cargo build` 完再 scp 二进制、手抄一份配置、手写 systemd 单元。三个问题
暴露出来——编译时的 feature 组合没人记录（换台机器就缺库）、目标机上的配置和仓库里的样例漂移、
服务生命周期（reload / 优雅下线 / 配置错误反复重启）没有统一约定。

run 包是解决这个交付环节的形态：一条命令在构建机上产出一个可执行的 `.run` 文件——自解压
安装器，里面是可执行程序 + 单一配置 + systemd 单元 + 安装/卸载脚本；目标机把它拷过去直接
`sudo ./xxx.run` 运行，程序与配置统一落在 `/opt/zf/g3`（`bin`、`conf`），g3proxy 与 g3fcgen
两个服务由 systemd 托管并立即启动。这个形态与上游已有的 deb/rpm 打包（`scripts/build_deb_from_git.sh`
等）并存，不替代它们。

## 2. 目标 / 非目标 / 反目标

**目标**

- G1：一条命令产出可分发 run 包（自解压 `.run` + 同名 tar.gz 与目录），包含 `g3proxy`、
  `g3proxy-ctl`、`g3fcgen`，程序集与 feature 组合可覆盖。
- G2：目标机一条命令完成安装并以 systemd 托管——`.run` 直接运行即安装，`enable --now`，
  固定前缀 `/opt/zf/g3` 下 `bin`、`conf` 分区清晰，**不提供任何命令行选项**；
  g3proxy 与 g3fcgen 两个服务都默认安装、默认启动。
- G3：包是自描述的——目标机上不看仓库也能操作（`README.md` 说明 + `VERSION` 记录版本、git sha、
  构建机、profile、feature、是否带 CA）；卸载走安装目录里的 `uninstall.sh`。
- G4：升级安全——现网配置绝不被覆盖，差异落到 `*.new`，回滚有依据。
- G5：配置错误不变成重启循环（`-t` 前置校验 + `RestartPreventExitStatus=255`）。
- G6：入口配置扁平化为**单个 `g3proxy.yaml`**——server、auditor 全部内联，现场只看一个文件
  就能改端口、ICAP 地址、拦截开关。

**非目标**

- N1：不做容器化/K8s 交付，不做多机编排、灰度、集中配置分发。
- N2：不取代 deb/rpm 打包形态。
- N3：不做 Ansible/shell 自动化装机（无 preseed、无依赖安装）——目标机的 OpenSSL、Lua、Python
  运行库由环境自身保证，脚本只检测、只提示。
- N4：不改 g3proxy 自身的配置 schema 与命令行参数。
- N5：ICAP 服务地址沿用仓库样例（生产必须改，见 L3）。CA 私钥不进仓库，但**随包分发**：
  构建时 `deploy/conf/` 没有成套 CA 就自动生成（自签根），有就用现成的；带 CA 的 `.run`
  按私钥级别走受控渠道分发。

**反目标**

- A1：绝不覆盖或改写目标机上已有的配置文件（哪怕只差一个空格）。
- A2：绝不把仓库测试 CA 私钥打进交付包（私钥不外发）。
- A3：绝不产生"装上了但起不来、且 systemd 在后台反复重启"的交付物。
- A4：绝不在脚本里联网、下载、或把目标机的任何数据外发。

## 3. 约束

- 脚本是 POSIX `sh`（目标机不假设有 bash），`set -eu`，与仓库 `scripts/`、`g3proxy/service/` 下
  现有脚本风格一致（tab 缩进、`$(CDPATH= cd -- …)`）。
- 交付物里的 g3proxy 命令行只能用现有参数：`-c/--config-file`、`-t/--test-config`、`-s/--systemd`、
  `-G/--group-name`、`-C/--control-dir`；`g3fcgen` 只支持 `-c/-s/-t/-G`（**没有** `--control-dir`）；
  `g3proxy-ctl` 用 `-C`、`-G`、`-p/--daemon-pid` 与 `offline`/`reload`/`reload-*`/`list` 子命令。
- g3proxy 默认 feature 为 `lua54, python, c-ares, quic, rustls-ring`；一次 `-p` 多个包时，cargo 要求
  feature 写成 `包名/feature`（`g3proxy-ctl` 没有 `[features]`，裸名直接报错）。
- c-ares 的可用性判定与 `scripts/package/detect_c-ares_feature.sh` 保持一致；Lua 判定参考
  `scripts/package/detect_lua_feature.sh`。
- 二进制按构建机的动态库链接，跨 OS/架构不保证可运行——构建机必须与目标机同 OS 同架构。
- 本仓库是 g3 fork（上游 v1.13.0），新增交付资产集中在 `deploy/` 新目录，对上游文件零改动。

## 4. 方案与取舍

- **方案 A（采纳）**：仓库内 `deploy/` 放三个脚本——构建打包脚本（产出 `.run`）+ 包内安装脚本 +
  包内卸载脚本，systemd 单元用占位符模板（`@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@`）由安装脚本
  `sed` 渲染；入口配置在 `deploy/conf/g3proxy.yaml`，server/auditor 内联，单一文件。
  `.run` 的自解压机制：几十行 POSIX sh 头部（记录 payload 起始行号）+ 尾部 tar.gz，运行时
  `tail -n +N` 取负载解进 `mktemp` 临时目录（0700、trap 删除）再调用包内 `install.sh`——
  不用 makeself 之类的构建机依赖。
  代价：包内二进制与构建机环境绑定，必须在同 OS/架构机器上打包；带 CA 的 `.run` 是敏感物，
  分发渠道要受控。
  收益：形态正好对上需求（一条命令直接安装 + service + 同一目录）；脚本可读、可手改，目标机无依赖；
  单元随前缀走，测试机换前缀（`PREFIX` 环境变量，仅测试用）也能装。
- **方案 B（不采纳）**：扩展现有 deb/rpm 打包。
  不采纳原因：包管理器会把程序放 `/usr/bin`、配置放 `/etc`，与"二进制和配置都在 `/opt/zf/g3`
  下分 bin/conf"的硬要求冲突；且目标机需要 dpkg/rpm 与仓库签名流程，现场交付更重。
- **方案 C（不采纳）**： musl 静态单二进制 + 极简安装。
  不采纳原因：静态链路要放弃系统 OpenSSL/Lua/Python（g3proxy 的审计器、脚本引擎都依赖动态库），
  功能裁剪的代价远大于"打包机要与目标机同环境"这一条约束。
- **方案 D（不采纳）**：容器镜像。
  不采纳原因：与"以 service 方式部署到 `/opt/zf/g3`"不符，代理需要 host 网络与特权端口，镜像
  反而多一层。

## 5. 包结构与产物

```
dist/g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>.run   # 交付物：自解压安装器
dist/g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>.tar.gz # 同内容归档（手动解包通道）
dist/g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>/
├── bin/g3proxy  bin/g3proxy-ctl  bin/g3fcgen
├── conf/g3proxy.yaml          # 入口配置（deploy/conf，server/auditor 内联）
├── conf/g3fcgen.yaml          # MITM 签发服务配置（deploy/conf）
├── conf/myCA.crt  myCA.key    # 必带：deploy/conf 有成套就用，没有则构建时自动生成（0600）
├── systemd/g3proxy.service    # 模板，含 @PREFIX@ 等占位符
├── systemd/g3fcgen.service
├── install.sh                 # 复制自 deploy/install.sh，由 .run 调用
├── uninstall.sh               # 复制自 deploy/uninstall.sh，安装时落到 ${PREFIX}/
├── README.md                  # 构建时生成：目标机操作说明
└── VERSION                    # 构建时生成：版本/sha/构建机/profile/feature/是否带 CA
```

`.run` = 头部 sh 脚本（内嵌包名与 payload 起始行号）+ 上述 tar.gz 原样追加。
`dist/` 已进 `.gitignore`（构建产物，不入库）；`deploy/conf/myCA.*` 同样不入库。

包内路径统一以 `<PKG_NAME>/` 开头，自解压即得到 `install.sh` 期望的目录结构。

## 6. 构建脚本（`deploy/build_run_package.sh`）

可覆盖变量：`RUN_BINS`（进包程序）、`BUILD_PACKAGES`（编译哪些包）、`PROFILE`、`TARGET`、
`EXTRA_FEATURES`、`G3_BUILD_ARGS`、`DIST_DIR`。

关键决定：

- **feature 一律加包名前缀**（`g3proxy/vendored-c-ares`），无名的 `EXTRA_FEATURES` 补成 `g3proxy/`；
  要动其他包的 feature 必须写全名。
- **c-ares 自动判定**：`pkg-config --atleast-version 1.18.0 libcares` 通过用系统库，否则
  `vendored-c-ares`。
- **`PROFILE=debug` 走 cargo 的 dev profile**（`debug` 是保留名，不能 `--profile debug`），
  但产物目录仍是 `target/debug`；其他自定义 profile 用 `--profile`。
- **缺 Lua/Python 开发库只警告不失败**（打到 stderr 的提示 + `doc/deploy-run-package.md` 里给出
  `--no-default-features` 的裁剪写法）。脚本不替操作者擅自砍掉默认 feature——那会静默改变程序能力。
- **CA 必带，构建时确定**：`deploy/conf/` 下有成套 `myCA.crt`/`myCA.key` 就直接进包（私钥
  0600）；一套都没有时脚本先补编 `g3mkcert`（同 profile/target），自动生成自签根 CA
  （RSA 2048，CN "g3 MITM Root CA"）写回 `deploy/conf/`——下次打包自动复用，正式环境把
  自己的 CA 放进该目录即覆盖这条路。只有半套视为操作者放错，直接报错。交叉编译时若
  `g3mkcert` 产物不能在构建机运行，生成失败会明确提示"先在同架构机器生成 CA 再打包"。
- **打包前自检**：`TARGET` 为空时，用**包里的二进制**加载**包里的配置**
  （`bin/g3proxy -t -c conf/g3proxy.yaml`）。交叉编译时跳过（产物不能在构建机运行），并明确打印
  跳过原因。自检失败不出 `.run`，包目录保留供排查。
- **`.run` 组装**：头部 heredoc 生成（含包名、payload 起始行号两个占位符），`sed` 替换后
  `cat` 追加 tar.gz；占位符替换不动行数，行号在写头部时一次算定；成品先 `sh -n` 自检再发布。
- `README.md`/`VERSION` 在构建时生成，内容包含包名、g3proxy 版本、git sha、构建机、profile、
  在默认 feature 之外额外启用的项、以及 `ca bundled: 0/1`。

## 7. 安装与卸载（`deploy/install.sh`、`deploy/uninstall.sh`）

`install.sh` 由 `.run` 解压后调用，**不接受任何命令行参数**；`PREFIX`/`SYSTEMD_DIR`
环境变量仅留测试后门，现场不设置。前置检查顺序：先确认"确实在 run 包目录里"
（`bin`/`conf`/`systemd`/`install.sh`/`uninstall.sh` 同级），再要求 root，再要求 `systemctl`
存在，再检查 CA。顺序是有意的——进错目录比不是 root 更常见，先给可操作的提示。

CA 兜底检查：正常构建的包必带 CA（§6），这条只防手工改动的包——包里与 `${PREFIX}/conf`
都拿不到成套 CA 时在写任何系统目录**之前**中止。理由：g3fcgen 是必须服务，没 CA 它必起不来，
放过去就违背 A3。

行为：

1. `bin/*` → `${PREFIX}/bin`（0755），`README.md`/`VERSION` → `${PREFIX}/`（文档每次覆盖，
   保证是当前版本的说明）；
2. `conf/*` → `${PREFIX}/conf`（`g3proxy.yaml`、`g3fcgen.yaml`、随包的 `myCA.crt`/`myCA.key`），
   **逐文件走"绝不覆盖"规则**：已存在且内容相同 → 只打"配置未变化"；已存在且不同 → 新内容写
   `${dest}.new`，原文件不动；不存在 → 安装。随包 CA 私钥落盘后 chmod 0600。
   **监听端口交互（2026-11-02 五修）**：仅当 `g3proxy.yaml` 是新装的（目标机上原本没有）时，
   交互式问一行"g3proxy 监听端口 [模板默认 10087]："——回车/EOF 用默认，数字 1–65535 则
   `sed` 写进刚装好的文件（默认值从模板 `"[::]:<端口>"` 现取，模板改了不用改脚本），非法输入
   重问；已有配置（未变化或落 `.new`）不询问，端口以现网文件为准，升级流程零打扰。
   端口写在校验（第 3 步）之前，坏输入过不了 `-t`；
3. 用**刚装好的**二进制校验**刚装好的**配置，失败则不装单元、不启服务、退出码非 0；
4. `sed` 渲染两个单元 → `/etc/systemd/system/`，`daemon-reload`；
5. `uninstall.sh` 复制到 `${PREFIX}/uninstall.sh`；
6. `systemctl enable --now g3fcgen`（**失败即整体失败**，退出码非 0——它是必须服务，
   不再像初版那样"警告但继续"），再 `systemctl enable --now g3proxy`。

`uninstall.sh` 装完独立存在于 `${PREFIX}` 下，同样无参数：`disable --now` 两个服务、摘单元、
`daemon-reload`，最后**删除 `${PREFIX}`**——配置与 CA 一并清除，唯一副本要先自行备份。
删除是脚本最后一步（shell 经已打开的 fd 继续读脚本，inode 删了不影响收尾）；包里那份
有守卫：安装目录里没有 `install.sh`，在包目录里跑（`install.sh` 与 `uninstall.sh` 同级）
会识别出来、原样保留，不会误删构建产物。

## 8. systemd 单元

沿用上游 `g3proxy/service/g3proxy@.latest.service` 的既有做法（`Type=exec`、`g3proxy-ctl` 做
reload/stop、`KillMode=none`），改成非模板实例 + 占位符渲染：

```
Type=exec
RuntimeDirectory=g3 / RuntimeDirectoryMode=0700 / RuntimeDirectoryPreserve=yes
ExecStart=@PREFIX@/bin/g3proxy -c @PREFIX@/conf/g3proxy.yaml --control-dir @CONTROL_DIR@ -s -G @GROUP@
ExecReload=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G @GROUP@ reload
ExecStop=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G @GROUP@ -p $MAINPID offline
KillMode=none
Restart=on-failure
SuccessExitStatus=SIGQUIT
RestartPreventExitStatus=255
TimeoutStartSec=10 / TimeoutStopSec=60 / LimitNOFILE=10485760
Documentation=file://@PREFIX@/README.md
```

- **控制套接字目录交给 systemd**（`RuntimeDirectory=g3` → `/run/g3`），不写进配置文件；`-G`
  group name 与 `--control-dir` 在 Start/Reload/Stop 三处必须一致，否则 `g3proxy-ctl` 找不到套接字。
- **停止走 `g3proxy-ctl offline`** 而不是信号杀进程（`KillMode=none`），让在途连接收尾。
- **配置错误不重启**：g3proxy 配置/启动失败以 255 退出，`RestartPreventExitStatus=255` 挡住循环，
  报错留在 journal。
- `g3fcgen.service` 没有控制套接字，`ExecStop=/bin/kill -INT $MAINPID`。
- 沙箱：本期不做 `User=`/`AmbientCapabilities=` 收敛，服务以 root 运行，在文档里写明这是待办。

## 9. 入口配置

`deploy/conf/g3proxy.yaml` 是刻意最小化的**单一文件**：`runtime.thread_number: 2`、
`log: stdout`、`controller.local`，`auditor:` 与 `server:` 都直接内联成数组
（g3proxy 的 `HybridParser` 对这两个键同时接受"路径字符串"或"内联数组"，schema 不动），
初版经由 `server.d`/`auditor.d` 的样例内容全部搬了进来；`resolver:`/`escaper:` 也内联
定义出来（`resolver` c-ares、`escaper` `direct_fixed` 直连，都叫 `default`）。

- **`log: stdout`**：日志进 journald，`journalctl -u g3proxy` 是运维唯一入口，包内不带文件日志与
  轮转配置。
- **一个文件就是全部现场可调面**：监听端口在 `server:` 段，ICAP 审计地址、拦截开关在
  `auditor:` 段；`tls_cert_generator: { }` 留空即连本机 `127.0.0.1:2999` 的 g3fcgen，
  指别机就在里面写 `query_peer_addr`。不再有"目录必须与 yaml 同级"的隐性约束。
- **`resolver.d`/`escaper.d` 默认注释**：指向不存在目录的这两行会让 `-t` 失败（实测报错
  "failed to parse value of key resolver … No such file or directory"）。要用先建目录，
  或者直接内联。这是自检阶段暴露并被修掉的第一个真实缺陷。
- `deploy/conf/g3fcgen.yaml` 只有 `backend.ca_certificate: myCA.crt` / `ca_private_key: myCA.key`
  （相对配置目录）；CA 材料按 §7 的前置规则要么随包、要么已在目标机上。

## 10. 失败面：每种情况脚本怎么处理

| 情况 | 行为 |
|------|------|
| 构建机缺 c-ares | 自动 `vendored-c-ares`，打一行说明 |
| 构建机缺 Lua/Python 开发库 | 默认 feature 仍会失败；stderr 给提示并指向文档的裁剪写法，脚本不擅自砍 feature |
| `RUN_BINS` 里有包没编 | 打包时找不到二进制 → 报错退出，指出检查 `RUN_BINS`/`BUILD_PACKAGES` |
| `deploy/conf` 只有半套 CA | 打包直接报错，不出缺 CA 或散件的包 |
| 交叉编译 | 跳过包内自检并说明原因；配置校验留给目标机 |
| 包内配置自检失败 | 不出 `.run`/tar.gz，包目录保留 |
| 给 `.run` 传了参数 | 拒绝执行，说明默认行为与卸载方式（`install.sh` 同样无参数） |
| payload 解不开（缺 tar / 文件损坏） | 报错退出；临时目录 trap 删除 |
| 非 root / 无 systemd | 拒绝执行并说明脚本要写哪些系统目录 |
| 包里和目标机上都没有 CA（仅手工改动包才可能） | 兜底检查：写任何系统目录**之前**中止 |
| 目标机已有同名配置（含 CA） | 相同→"未变化"；不同→写 `*.new`，原件不动 |
| 装完配置校验失败 | 不装单元、不启服务，退出非 0 |
| 配置不合法的进程 | 255 退出 + `RestartPreventExitStatus=255`，不进重启循环 |
| g3fcgen 启动失败 | 视为安装失败，退出非 0，提示查 CA 材料与 `g3fcgen.yaml` |

## 11. 验证方案

初版（tar.gz + install.sh 形态）曾在 macOS 构建机上验证过构建、包内自检与 `sh -n`/分支实跑，
这些结论随形态变更不再逐条适用。修订后的验证以真实 Linux 机为准，构建机即目标机
（Ubuntu 系、x86_64、systemd、系统 Lua 5.4/Python3/c-ares≥1.18 齐备，走默认 feature）：

- V1：`sudo ./g3-run-<...>.run` 全链路——CA 随包（验证时借用 `etc/g3fcgen/ftp` 的样例 CA
  临时放 `deploy/conf/`，仅测试、不发布）、写 `/opt/zf/g3`、渲染并 `daemon-reload`、
  g3fcgen 与 g3proxy 双双 `enable --now` 进入 active、journald 收日志；
- V2：`systemctl reload g3proxy` 走 `g3proxy-ctl reload` 的不停机重载实际生效；
- V3：`ExecStop` 的 offline 优雅下线（`TimeoutStopSec=60` 是否够）；
- V4：`RuntimeDirectoryMode=0700` 下 `g3proxy-ctl` 与守护进程对 `/run/g3` 的读写；
- V5：升级场景——已有配置时 `*.new` 落地且服务不受影响；
- V6：缺 CA 场景——不带 CA 的包在全新目标机上于写系统目录前中止，退出非 0；
- V7：`uninstall.sh` 停服务、摘单元、删除目录，之后重跑 `.run` 可恢复；包内那份在包目录
  里执行时保留整包。

构建脚本自身的验证：`sh -n` 三个脚本与生成的 `.run`；`.run` 头部行号正确性由构建时的
`sh -n`（只做头部、先于追加载荷）加 V1 实跑双重兜底；`VERSION` 记录 `ca bundled`。

### 验证结果（2026-11-02，本机 Linux x86_64 + systemd，PROFILE=debug 包）

- V1 通过：`sudo ./g3-run-1.13.0-02f6c450-linux-x86_64-20261102.run`（CA 借用
  `etc/g3fcgen/ftp` 样例随包）退出 0；`/opt/zf/g3` 落盘齐全，双服务 `enable --now` 后
  active+enabled，g3proxy 监听 10087，g3fcgen 监听 `127.0.0.1:2999/udp`（cert-agent 协议
  本就是 UDP，与 auditor 默认查询地址严丝合缝），日志进 journald；
- V2 通过：`systemctl reload g3proxy` 后 MainPID 不变，journal 里 `g3proxy-ctl: notice: success`；
- V3 通过：`systemctl stop` 走 `ExecStop` 的 `g3proxy-ctl offline`，Deactivated successfully，
  耗时远小于 `TimeoutStopSec=60`；
- V4 通过：`/run/g3` 为 0700，`g3proxy-ctl list server/auditor` 返回 `cds`/`https-up`；
- V5 通过：改过的 `g3proxy.yaml` 保持原样、新内容落 `*.new`，未动的 `g3fcgen.yaml`/CA 打
  "配置未变化"，重跑 `.run` 不重启在跑的服务（PID 不变）；
- V6 通过：不带 CA 的包在全新机器上于写任何系统目录前中止（exit 1），`/opt/zf` 与
  `/etc/systemd/system` 零改动；`.run` 传参数被拒绝并提示默认行为；
- V7 通过（删除语义复测）：`/opt/zf/g3/uninstall.sh` 停双服务、摘单元并删净 `/opt/zf/g3`；
  重跑 `.run` 恢复；在包目录里跑包里那份 `uninstall.sh` 只摘单元、整包原样保留。
- V7b（原 feature 项）通过：本机默认 feature（系统 lua5.4/python3/c-ares≥1.18）全量编译打包，
  未走 vendored 路径。

测试后本机已卸载并删除 `/opt/zf/g3`、`deploy/conf/myCA.*`（样例 CA 不外发，A2），`dist/`
重建为不带 CA 的干净包（`ca bundled: 0`）。首轮验证还暴露并修掉两个真实缺陷：`sh -n`
误校验整个 `.run`（二进制负载必报错，改为追加载荷前只验头部）、头部缺显式 `exit`
（否则 shell 会继续把 payload 首行当命令读）。

## 12. 遗留与待跟踪

- L1：已闭环——本机 V1–V7 全部通过，结果见 §11；换正式目标机时按同一清单复跑即可。
- L2：单元目前 root 运行，未做 `User=`/`AmbientCapabilities=` 与目录属主收敛；降权需同时验证
  `/run/g3` 权限与监听端口能力。
- L3：入口配置里 `icap_reqmod_service: icap://127.0.0.1:1344/echo` 沿用样例，生产必须改；
  是否给 run 包加"首次安装提示改审计地址"或直接留空，待需求方定。
- L4：日志走 journald，无文件日志与轮转；如果交付环境要求落盘日志需另设计。
- L5：`g3tiles`、`g3keymess` 等其他守护进程是否进同一个 run 包（`RUN_BINS`/`BUILD_PACKAGES`
  已可扩展，但入口配置与单元要一并补）。
- L6：升级目前靠人工 `diff *.new`；若要自动化（备份-比对-切换）是独立一轮设计。
- L7：已定（2026-11-02 四修，推翻"永远保留"）——`uninstall.sh` 摘完单元直接删除
  `/opt/zf/g3`，配置与 CA 一并清除；确需留存请在卸载前把 `conf/` 备份出去。
- L9：`.run` 带 CA 即带私钥，是否需要进一步做包级校验（如发布前 checksum/签名清单）待
  交付流程确定；当前约定是"带 CA 的 .run 按私钥级别走受控渠道"。
- L8：deb/rpm 与 run 包两条形态并存，长期是否统一待定。
