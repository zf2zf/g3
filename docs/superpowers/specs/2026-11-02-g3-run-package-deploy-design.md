# g3 run 包编译与部署设计

日期：2026-11-02
状态：已实现，待在真实 Linux 目标机上完成部署验证
范围：`deploy/`（新增构建脚本、安装脚本、systemd 单元模板、入口配置）、`doc/deploy-run-package.md`、`.gitignore`
需求来源：需求方明确要求——"增加编译部署脚本，部署程序最终以 run 包的方式提供，包含必要的
可执行程序（如 g3proxy、g3fcgen 等），一个配置文件，以 service 方式部署；二进制程序和配置文件
部署在同一个目录 `/opt/zf/g3/` 下，放 bin、conf 等"

## 1. 意图与背景

HTTP 旁路上传审计（见 `docs/superpowers/specs/2026-11-01-http-icap-bypass-upload-audit-design.md`）
落地后，交付仍是手工的：`cargo build` 完再 scp 二进制、手抄一份配置、手写 systemd 单元。三个问题
暴露出来——编译时的 feature 组合没人记录（换台机器就缺库）、目标机上的配置和仓库里的样例漂移、
服务生命周期（reload / 优雅下线 / 配置错误反复重启）没有统一约定。

run 包是解决这个交付环节的形态：一条命令在构建机上产出一个 tar.gz，里面是可执行程序 + 配置 +
systemd 单元 + 安装脚本；目标机解包后跑一次 `./install.sh`，程序与配置统一落在 `/opt/zf/g3`
（`bin`、`conf`），服务由 systemd 托管。这个形态与上游已有的 deb/rpm 打包（`scripts/build_deb_from_git.sh`
等）并存，不替代它们。

## 2. 目标 / 非目标 / 反目标

**目标**

- G1：一条命令产出可分发 run 包（目录 + tar.gz），包含 `g3proxy`、`g3proxy-ctl`、`g3fcgen`，
  程序集与 feature 组合可覆盖。
- G2：目标机一条命令完成安装并以 systemd 托管，安装即 `enable --now`；`/opt/zf/g3` 下
  `bin`、`conf` 分区清晰。
- G3：包是自描述的——目标机上不看仓库也能操作（`README.md` 说明 + `VERSION` 记录版本、git sha、
  构建机、profile、feature）。
- G4：升级安全——现网配置绝不被覆盖，差异落到 `*.new`，回滚有依据。
- G5：配置错误不变成重启循环（`-t` 前置校验 + `RestartPreventExitStatus=255`）。
- G6：与仓库既有资产同源，不另抄一份配置：`server.d`/`auditor.d` 取自 `etc/g3proxy/http`。

**非目标**

- N1：不做容器化/K8s 交付，不做多机编排、灰度、集中配置分发。
- N2：不取代 deb/rpm 打包形态。
- N3：不做 Ansible/shell 自动化装机（无 preseed、无依赖安装）——目标机的 OpenSSL、Lua、Python
  运行库由环境自身保证，脚本只检测、只提示。
- N4：不改 g3proxy 自身的配置 schema 与命令行参数。
- N5：本期包内不带 CA 证书/私钥、不带 ICAP 服务地址的真实值（沿用仓库样例）。

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

- **方案 A（采纳）**：仓库内 `deploy/` 放两个脚本——构建打包脚本 + 包内安装脚本，systemd 单元用
  占位符模板（`@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@`）由安装脚本 `sed` 渲染，配置来源复用
  `etc/g3proxy/http`。
  代价：包内二进制与构建机环境绑定，必须在同 OS/架构机器上打包。
  收益：形态正好对上需求（run 包 + service + 同一目录）；脚本可读、可手改，目标机无依赖；
  单元随前缀走，测试机换 `--prefix` 就能装。
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
dist/g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>/
├── bin/g3proxy  bin/g3proxy-ctl  bin/g3fcgen
├── conf/g3proxy.yaml          # 入口配置（deploy/conf）
├── conf/g3fcgen.yaml          # MITM 签发服务模板（deploy/conf）
├── conf/server.d/*.yaml       # 复制自 etc/g3proxy/http/server.d
├── conf/auditor.d/*.yaml      # 复制自 etc/g3proxy/http/auditor.d
├── systemd/g3proxy.service    # 模板，含 @PREFIX@ 等占位符
├── systemd/g3fcgen.service
├── install.sh                 # 复制自 deploy/install.sh
├── README.md                  # 构建时生成：目标机操作说明
└── VERSION                    # 构建时生成：版本/sha/构建机/profile/feature
```

同名的 `.tar.gz` 落在 `dist/`；`dist/` 已进 `.gitignore`（构建产物，不入库）。

包内路径统一以 `<PKG_NAME>/` 开头，解包即得到 `install.sh` 期望的目录结构。

## 6. 构建脚本（`deploy/build_run_package.sh`）

可覆盖变量：`RUN_BINS`（进包程序）、`BUILD_PACKAGES`（编译哪些包）、`PROFILE`、`TARGET`、
`EXTRA_FEATURES`、`G3_BUILD_ARGS`、`DIST_DIR`、`CONF_DIR`、`CONF_SUBDIRS`。

关键决定：

- **feature 一律加包名前缀**（`g3proxy/vendored-c-ares`），无名的 `EXTRA_FEATURES` 补成 `g3proxy/`；
  要动其他包的 feature 必须写全名。
- **c-ares 自动判定**：`pkg-config --atleast-version 1.18.0 libcares` 通过用系统库，否则
  `vendored-c-ares`。
- **`PROFILE=debug` 走 cargo 的 dev profile**（`debug` 是保留名，不能 `--profile debug`），
  但产物目录仍是 `target/debug`；其他自定义 profile 用 `--profile`。
- **缺 Lua/Python 开发库只警告不失败**（打到 stderr 的提示 + `doc/deploy-run-package.md` 里给出
  `--no-default-features` 的裁剪写法）。脚本不替操作者擅自砍掉默认 feature——那会静默改变程序能力。
- **打包前自检**：`TARGET` 为空时，用**包里的二进制**加载**包里的配置**
  （`bin/g3proxy -t -c conf/g3proxy.yaml`）。交叉编译时跳过（产物不能在构建机运行），并明确打印
  跳过原因。自检失败不出包，包目录保留供排查。
- `README.md`/`VERSION` 在构建时生成，内容包含包名、g3proxy 版本、git sha、构建机、profile、
  在默认 feature 之外额外启用的项。

## 7. 安装脚本（`deploy/install.sh`）

前置检查顺序：`install` 模式下先确认"确实在 run 包目录里"（`bin`/`conf`/`systemd`/`install.sh`
同级），再要求 root，再要求 `systemctl` 存在。顺序是有意的——进错目录比不是 root 更常见，先给
可操作的提示。

行为：

1. `bin/*` → `${PREFIX}/bin`（0755），`README.md` → `${PREFIX}/README.md`（文档每次覆盖，
   保证是当前版本的说明）；
2. `conf/*` → `${PREFIX}/conf`，**逐文件走"绝不覆盖"规则**：已存在且内容相同 → 只打
   "配置未变化"；已存在且不同 → 新内容写 `${dest}.new`，原文件不动；不存在 → 安装；
3. 用**刚装好的**二进制校验**刚装好的**配置，失败则不装单元、不启服务、退出码非 0；
4. `sed` 渲染单元 → `/etc/systemd/system/`，`daemon-reload`；
5. `systemctl enable --now g3proxy`；`--with-fcgen` 时同样装 g3fcgen，若
   `${PREFIX}/conf/myCA.key` 不存在先给警告（起不来是可预期的，失败不阻断整个安装，打提示走）。

模式与参数：`install`（默认）、`uninstall`、`--prefix=`、`--with-fcgen`、`--purge`。
`uninstall` 摘两个单元并 `disable --now`，默认**保留** `/opt/zf/g3`，`--purge` 才删——删目录是不可
逆动作，必须显式说要 purge。

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

`deploy/conf/g3proxy.yaml` 是刻意最小化的：`runtime.thread_number: 2`、`log: stdout`、
`controller.local`、`server: server.d/`、`auditor: auditor.d/`，`resolver:`/`escaper:` 注释掉。

- **`log: stdout`**：日志进 journald，`journalctl -u g3proxy` 是运维唯一入口，包内不带文件日志与
  轮转配置。
- **`server:`/`auditor:` 的值相对配置文件所在目录**，因此 `server.d`、`auditor.d` 必须与
  `g3proxy.yaml` 同级——打包已经保证；这也意味着目标机不能只拷一个 yaml 文件。
- **`resolver.d`/`escaper.d` 默认注释**：目录不存在时打开这两行会让 `-t` 失败（实测报错
  "failed to parse value of key resolver … No such file or directory"）。要用先建目录。
  这是自检阶段暴露并被修掉的第一个真实缺陷。
- `deploy/conf/g3fcgen.yaml` 只带模板（`backend.ca_certificate: myCA.crt` / `ca_private_key: myCA.key`，
  相对配置目录），CA 材料不进包。

## 10. 失败面：每种情况脚本怎么处理

| 情况 | 行为 |
|------|------|
| 构建机缺 c-ares | 自动 `vendored-c-ares`，打一行说明 |
| 构建机缺 Lua/Python 开发库 | 默认 feature 仍会失败；stderr 给提示并指向文档的裁剪写法，脚本不擅自砍 feature |
| `RUN_BINS` 里有包没编 | 打包时找不到二进制 → 报错退出，指出检查 `RUN_BINS`/`BUILD_PACKAGES` |
| 交叉编译 | 跳过包内自检并说明原因；配置校验留给目标机 |
| 包内配置自检失败 | 不打 tar.gz，包目录保留 |
| 在 run 包目录外执行 install.sh | 立刻报错，指出缺哪个目录，提示先打包 |
| 非 root / 无 systemd | 拒绝执行并说明脚本要写哪些系统目录 |
| 目标机已有同名配置 | 相同→"未变化"；不同→写 `*.new`，原件不动 |
| 装完配置校验失败 | 不装单元、不启服务，退出非 0 |
| 配置不合法的进程 | 255 退出 + `RestartPreventExitStatus=255`，不进重启循环 |
| g3fcgen 缺 CA 私钥 | 警告 + 尝试启动，失败不阻断（`systemctl status g3fcgen` 自查） |

## 11. 验证方案

已在本机（macOS，Darwin x86_64）执行并通过：

- `PROFILE=debug sh deploy/build_run_package.sh` 退出 0；产物目录逐项核对为 §5 的结构，
  `VERSION` 记录 git sha `df2d6e66`、profile、`extra features: vendored-c-ares`；
- **包内自检**（包内 `g3proxy -t` 加载包内 `conf/g3proxy.yaml`）退出 0；
- `sh -n` 两个脚本干净；包内 `install.sh` `sh -n` 干净；
- 两个单元模板按 install.sh 的 `sed` 渲染，`ExecStart/ExecReload/ExecStop/Documentation/RuntimeDirectory`
  与 `-c/-C/-G/-s`、`-p $MAINPID`、`g3proxy-ctl` 子命令逐项核对（`g3proxy-ctl --help` 确认
  `-p, --daemon-pid`、`reload`、`reload-server`、`reload-auditor`、`list` 存在）；
- `install.sh` 的四条分支实跑：`--help`、未知参数（非 0 退出）、非 root（拒绝）、
  不在包目录（先给可操作提示）。

未验证（必须在真实 Linux 目标机补）：

- V1：`sudo ./install.sh` 全链路——写 `/opt/zf/g3`、渲染并 `daemon-reload`、`enable --now`、
  journald 收日志。
- V2：`systemctl reload g3proxy` 走 `g3proxy-ctl reload` 的不停机重载实际生效。
- V3：`ExecStop` 的 offline 优雅下线（`TimeoutStopSec=60` 是否够）。
- V4：`RuntimeDirectoryMode=0700` 下 `g3proxy-ctl` 与守护进程对 `/run/g3` 的读写。
- V5：升级场景——已有配置时 `*.new` 落地且服务不受影响。
- V6：`--with-fcgen` 与自有 CA 的组合。
- V7：Linux 构建机上带系统 Lua/Python/c-ares 的默认 feature 打包（本机走的是 vendored 路径）。

本机跑不了 V1–V7 的原因：macOS 无 systemd，且 Auto Mode 禁止在本机安装系统服务。

## 12. 遗留与待跟踪

- L1（首要）：真实 Linux 目标机上跑完 §11 的 V1–V7，把结果回写本节。
- L2：单元目前 root 运行，未做 `User=`/`AmbientCapabilities=` 与目录属主收敛；降权需同时验证
  `/run/g3` 权限与监听端口能力。
- L3：`etc/g3proxy/http` 的样例含 `icap_reqmod_service: icap://127.0.0.1:1344/echo`，生产必须改；
  是否给 run 包加"首次安装提示改审计地址"或直接留空，待需求方定。
- L4：日志走 journald，无文件日志与轮转；如果交付环境要求落盘日志需另设计。
- L5：`g3tiles`、`g3keymess` 等其他守护进程是否进同一个 run 包（`RUN_BINS`/`BUILD_PACKAGES`
  已可扩展，但入口配置与单元要一并补）。
- L6：升级目前靠人工 `diff *.new`；若要自动化（备份-比对-切换）是独立一轮设计。
- L7：`--purge` 的破坏性与是否需要备份配置目录，待运维流程确定。
- L8：deb/rpm 与 run 包两条形态并存，长期是否统一待定。
