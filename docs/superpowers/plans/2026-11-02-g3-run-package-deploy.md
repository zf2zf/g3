# g3 run 包编译与部署 Implementation Plan

> **For agentic workers：** 本计划的 Task 1–5 已实现并提交（`7ec35f59`），勾选框记录实际完成与
> 实际验证过的内容；Task 6 起为未做完的跟踪项，按顺序推进。跟踪用 `- [ ]` 语法。

**Goal:** 一条命令在构建机产出 g3 run 包（可执行程序 + 配置 + systemd 单元 + 安装脚本），目标机
解包后一条命令装到 `/opt/zf/g3` 并由 systemd 托管。

**Architecture:** `deploy/` 下两个 POSIX sh 脚本：`build_run_package.sh` 负责 cargo 编译、feature
判定与包组装，并在出包前用包内二进制校验包内配置；`install.sh` 复制进包，在目标机做"绝不覆盖
配置"的安装、`-t` 前置校验、`sed` 渲染 systemd 单元模板并 `enable --now`。配置单一来源仍是
`etc/g3proxy/http`，`deploy/conf` 只放入口配置。

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
- [ ] L7 `--purge` 前是否需要自动备份配置目录
- [ ] L8 deb/rpm 与 run 包两条形态长期是否统一
