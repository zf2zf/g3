# g3 run 包编译与部署 Implementation Plan

> **For agentic workers：** 本计划的 Task 1–5 已实现并提交（`7ec35f59`），勾选框记录实际完成与
> 实际验证过的内容；Task 6 起为未做完的跟踪项，按顺序推进。跟踪用 `- [ ]` 语法。
>
> **2026-11-02 修订二：** 需求方改定了交付形态——Task 1/2/4 的产物已被重做：交付物是
> **自解压 `.run`**（目标机一条命令直接安装）、安装**无参数**、**g3proxy+g3fcgen 双服务默认
> 安装启动**、CA 成为安装前置、入口配置**扁平化为单个 `g3proxy.yaml`**（无 server.d/auditor.d）、
> 卸载脚本落在 `/opt/zf/g3/uninstall.sh`。下文 Task 1–4 的勾选记录的是初版（tar.gz 形态）的
> 验证事实，不再逐条适用；修订后的实现与验证见 Task 8。Spec §11 的 V1–V7 以 Task 8 为准。
>
> **2026-11-02 修订四：** `uninstall.sh` 由"永远保留目录"改为**卸载即删除 `/opt/zf/g3`**
> （配置与 CA 一并清除）；包内那份带守卫，在包目录里执行不会误删构建产物。V7 按新语义
> 复测，见 Task 8。

**Goal:** 一条命令在构建机产出 g3 run 包（可执行程序 + 配置 + systemd 单元 + 安装/卸载脚本），
目标机对 `.run` 直接 `sudo` 运行即装到 `/opt/zf/g3`，g3proxy 与 g3fcgen 由 systemd 托管并启动。

**Architecture:** `deploy/` 下三个 POSIX sh 脚本：`build_run_package.sh` 负责 cargo 编译、feature
判定与包组装，出包前用包内二进制校验包内配置，最后把包目录打成 tar.gz 并拼装成自解压 `.run`
（sh 头部 + 尾部负载）；`install.sh` 进包、由 `.run` 解压后调用，做 CA 前置检查、"绝不覆盖
配置"的安装、`-t` 前置校验、`sed` 渲染 systemd 单元模板并 `enable --now` 双服务；
`uninstall.sh` 进包、安装时复制到 `/opt/zf/g3/uninstall.sh`。配置单一来源是 `deploy/conf`
（扁平的单文件 `g3proxy.yaml`），CA 经 `deploy/conf/myCA.*`（gitignore）随包。

**Tech Stack:** POSIX sh / cargo / systemd unit 模板 / g3proxy `-c -t -s -G -C` / g3proxy-ctl
`offline reload reload-* list -p` / g3fcgen `-c -t -s -G`。

**Spec:** `docs/superpowers/specs/2026-11-02-g3-run-package-deploy-design.md`

## Global Constraints

- 脚本只用 POSIX sh 构造，`set -eu`，tab 缩进，风格对齐 `scripts/` 与 `g3proxy/service/`。
- 不得覆盖目标机上已有配置（反目标 A1）；差异只写 `*.new`。
- 不得把仓库测试 CA 私钥打进包（A2）；脚本不得联网、不得外发目标机数据（A4）。
- feature 传给 cargo 时必须写成 `包名/feature`；`g3fcgen` 无 `--control-dir`，单元里不能加。
- 构建机与目标机需同 OS 同架构；交叉编译时跳过包内自检并说明。
- `dist/` 为构建产物，不入库。

---

## Task 1: 构建打包脚本

**Files:** Create `deploy/build_run_package.sh`

- [x] Step 1：c-ares 判定（`pkg-config --atleast-version 1.18.0 libcares` → `g3proxy/c-ares`，否则
  `g3proxy/vendored-c-ares`），Lua/Python 缺库只警告不擅自砍 feature
- [x] Step 2：feature 统一加 `g3proxy/` 前缀、`PROFILE=debug` 映射到 cargo dev、`TARGET` 透传
- [x] Step 3：组装 `bin/conf/systemd/install.sh/README.md/VERSION`，`conf` 的 `server.d`/`auditor.d`
  复用 `etc/g3proxy/http`
- [x] Step 4：出包前用包内二进制 `-t` 校验包内配置，失败不出包
- [x] Step 5：`PROFILE=debug sh deploy/build_run_package.sh` 退出 0，产物树逐项核对，tar 包内路径
  以 `<PKG_NAME>/` 开头

## Task 2: 目标机安装脚本

**Files:** Create `deploy/install.sh`

- [x] Step 1：前置检查顺序（在包目录 → root → systemctl），四条分支实跑行为正确
- [x] Step 2：`install_config_file` 的三态（未变化 / 写 `.new` / 安装），现网配置零覆盖
- [x] Step 3：装完二进制后先用 `${PREFIX}/bin/g3proxy -t ${PREFIX}/conf/g3proxy.yaml` 校验，失败
  不装单元不启服务
- [x] Step 4：`sed` 渲染 `@PREFIX@/@CONTROL_DIR@/@GROUP@` → `/etc/systemd/system`，`daemon-reload`
  + `enable --now`；`--with-fcgen` 缺 CA 私钥时警告不阻断
- [x] Step 5：`uninstall`（保留目录）与 `uninstall --purge`（删目录）
- [x] Step 6：`sh -n` 通过；`--help`/未知参数/非 root/进错目录四条路径输出符合预期
- [ ] Step 7：**未在真实 Linux 上执行**——`install.sh` 写系统目录与 systemd 交互的整条路径本机跑不了

## Task 3: systemd 单元模板

**Files:** Create `deploy/systemd/g3proxy.service`、`deploy/systemd/g3fcgen.service`

- [x] Step 1：对齐上游 `g3proxy/service/g3proxy@.latest.service` 的 `Type=exec`、
  `KillMode=none`、`g3proxy-ctl` reload/stop、`LimitNOFILE`，改为非模板实例 + 占位符
- [x] Step 2：`RuntimeDirectory=g3`（0700，preserve）承载控制套接字，三处 `-G`/`--control-dir` 一致
- [x] Step 3：`RestartPreventExitStatus=255` 挡住配置错误的重启循环；`Documentation` 指向安装后的
  `README.md`（因此 README 必须真装到 `${PREFIX}`）
- [x] Step 4：渲染结果与 `g3proxy --help`、`g3proxy-ctl --help`、`g3fcgen --help` 的参数逐项核对
- [ ] Step 5：`systemd-analyze verify` 未跑（本机无 systemd）

## Task 4: 入口配置

**Files:** Create `deploy/conf/g3proxy.yaml`、`deploy/conf/g3fcgen.yaml`

- [x] Step 1：最小可用入口配置（`thread_number`、`log: stdout`、`controller.local`、`server`、
  `auditor`）
- [x] Step 2：`resolver:`/`escaper:` 默认注释——目录不存在会让 `-t` 失败，注释里写明先建目录再打开
  （这条是自检阶段暴露的真实缺陷）
- [x] Step 3：g3fcgen 模板只引用 `myCA.crt`/`myCA.key`，CA 材料不进包

## Task 5: 文档与入库

**Files:** Create `doc/deploy-run-package.md`、修改 `.gitignore`

- [x] Step 1：运维文档覆盖构建机要求、环境变量表、feature 裁剪、包结构、安装、日常操作、升级回滚、
  配置注意、安全说明
- [x] Step 2：`.gitignore` 加 `dist/`
- [x] Step 3：`git add` 只加 `deploy/`、`doc/`、`.gitignore`，确认无密钥类文件；提交 `7ec35f59`

## Task 6: 真实 Linux 目标机验证（未完成，对应 Spec §11 V1–V7）

- [ ] V1 `sudo ./install.sh` 全链路（写 `/opt/zf/g3`、渲染单元、`enable --now`、journald 收日志）
- [ ] V2 `systemctl reload g3proxy` 的不停机重载实际生效
- [ ] V3 `ExecStop` 走 offline 优雅下线，`TimeoutStopSec=60` 是否够用
- [ ] V4 `RuntimeDirectoryMode=0700` 下守护进程与 `g3proxy-ctl` 对 `/run/g3` 的读写
- [ ] V5 升级场景：已有配置时 `*.new` 落地、服务不受影响
- [ ] V6 `--with-fcgen` 配自有 CA
- [ ] V7 Linux 构建机上带系统 Lua/Python/c-ares 的默认 feature 打包（本机走的是 vendored 路径）
- [ ] 结果回写 Spec §11 与 Spec §12

## Task 7: 待决策项（Spec §12）

- [ ] L2 降权运行（`User=`/`AmbientCapabilities=` + `/run/g3` 属主 + 特权端口）
- [ ] L3 生产 ICAP 审计地址：样例是 `icap://127.0.0.1:1344/echo`，交付时改还是留空
- [ ] L4 是否需要文件日志与轮转（当前只进 journald）
- [ ] L5 `g3tiles`/`g3keymess` 是否进同一个 run 包
- [ ] L6 升级自动化（备份-比对-切换）
- [x] L7 已定（修订四）：`uninstall.sh` 摘完单元直接删除 `/opt/zf/g3`，不做自动备份，
  留存靠操作者卸载前自己拷走 `conf/`
- [ ] L8 deb/rpm 与 run 包两条形态长期是否统一

## Task 8: 修订二——.run 自解压形态 + 扁平配置 + g3fcgen 必装（本机实现）

**Files:** 重写 `deploy/build_run_package.sh`、`deploy/install.sh`、`deploy/conf/g3proxy.yaml`；
新增 `deploy/uninstall.sh`；`.gitignore` 加 `deploy/conf/myCA.*`；同步 Spec 与 `doc/`。

- [x] Step 1：`g3proxy.yaml` 扁平化——`server:`/`auditor:` 内联数组（`HybridParser` 原生支持），
  打包脚本删 `CONF_DIR`/`CONF_SUBDIRS`，包内不再有 `server.d`/`auditor.d`
- [x] Step 2：`install.sh` 去掉全部参数——固定 `/opt/zf/g3`，CA 前置检查（包内或目标机成套
  存在，否则写系统目录前中止），双服务默认 `enable --now`，g3fcgen 启动失败即安装失败；
  `uninstall.sh` 独立成文件并安装到 `${PREFIX}/uninstall.sh`（修订四：摘单元后删除
  `${PREFIX}`；包内那份识别到 `install.sh` 同级即知是包目录，原样保留）
- [x] Step 3：构建脚本 CA 必带——`deploy/conf` 有成套就打进包（私钥 0600），没有则补编
  `g3mkcert` 自动生成自签根（RSA 2048）写回 `deploy/conf` 复用；半套报错；`VERSION` 记
  `ca bundled`、README 重写为 `.run` 一条命令流程（2026-11-02 三修：CA 从"安装时提醒"
  改为"构建时自动生成并随包"）
- [x] Step 4：`.run` 组装——POSIX sh 头部（包名+payload 行号占位符，`sed` 替换不动行数）+
  `cat` 追加 tar.gz；头部拒绝一切参数；`mktemp -d` 0700 临时目录 + trap 删除；成品 `sh -n` 自检
- [x] V1 本机 `sudo ./g3-run-<...>.run` 全链路（CA 借用 `etc/g3fcgen/ftp` 样例，仅测试）：
  写 `/opt/zf/g3`、渲染单元、`enable --now` 双服务 active、journald 收日志
  （2026-11-02 通过；g3fcgen 实际监听 `127.0.0.1:2999/udp`，与 auditor 默认一致）
- [x] V2 `systemctl reload g3proxy` 不停机重载生效（MainPID 不变，ctl 返回 success）
- [x] V3 `ExecStop` offline 优雅下线（Deactivated successfully，耗时远小于 60s）
- [x] V4 `RuntimeDirectoryMode=0700` 下 `g3proxy-ctl` 与守护进程对 `/run/g3` 读写
  （`list server`/`list auditor` 返回 `cds`/`https-up`）
- [x] V5 升级：已有配置落 `*.new`、服务不受影响（重跑 `.run` PID 不变）
- [x] V6 缺 CA：无 CA 包在全新机于写系统目录前中止、退出非 0；`.run` 拒绝一切参数
- [x] V7（修订四复测）`uninstall.sh` 摘单元并删净 `/opt/zf/g3`；重跑 `.run` 可恢复；
  包目录里跑包里那份只摘单元、整包保留（2026-11-02 实跑通过，收尾本机已卸净）
- [x] 结果回写 Spec §11/§12；删除临时放进 `deploy/conf/` 的样例 CA，本机卸载并删净
  `/opt/zf/g3`，`dist/` 重建为 `ca bundled: 0` 的干净包

首轮验证修掉的两个缺陷（已进 `build_run_package.sh`）：`sh -n` 必须在追加载荷前只验头部；
自解压头部结尾必须有显式 `exit`，否则 shell 会把 payload 首行当命令读。

## Task 9: 修订五——首次安装交互式指定监听端口

**Files:** `deploy/install.sh`（新增 `configure_listen_port`）、`deploy/build_run_package.sh`
（README 部署段）、Spec §7、`doc/deploy-run-package.md` §3。

- [x] Step 1：`install.sh` 仅在 `g3proxy.yaml` **新装**时问一行"g3proxy 监听端口
  [模板默认 10087]："——回车/EOF 用默认，1–65535 数字 `sed` 写进新文件，非法重问；
  默认值从模板 `"[::]:<端口>"` 现取；已有配置（未变化 / `.new`）不询问、不改动
- [x] Step 2：交互写在校验 `-t` 之前，端口错不了还过不了校验就中止；README/文档同步
- [x] V9a 交互输入 10088（前置 `abc`/`0`/`70000` 三次非法均重问）：`g3proxy.yaml` 落
  `[::]:10088`，服务 active 且 `ss` 显示监听 10088（本机 NETNS=no 打包实跑，2026-11-02）
- [x] V9b 非交互（stdin 到 EOF）：问一行后直接落默认 10087，服务监听 10087
- [x] V9c 升级（已有 10088 配置）：不出现端口询问，模板差异只落 `.new`，MainPID 不变
