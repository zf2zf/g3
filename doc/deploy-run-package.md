# g3 run 包：编译与部署

run 包是把 g3 一次编译、一次安装交付到目标机的形态：一个 tar.gz，里面是可执行程序、
一份配置、systemd 单元和安装脚本。装完程序与配置统一落在 `/opt/zf/g3` 下，服务由 systemd
托管。

- 打包脚本：`deploy/build_run_package.sh`
- 安装脚本：`deploy/install.sh`（会被复制进包里，在目标机执行）
- 单元模板：`deploy/systemd/g3proxy.service`、`deploy/systemd/g3fcgen.service`
- 配置来源：`deploy/conf/`（入口配置）+ `etc/g3proxy/http/`（`server.d`、`auditor.d`）

## 1. 编译 run 包

```sh
deploy/build_run_package.sh                                    # 默认 release
PROFILE=debug        deploy/build_run_package.sh               # 排障用的调试包
RUN_BINS="g3proxy g3proxy-ctl" deploy/build_run_package.sh      # 精简程序集
```

产物在 `dist/`：目录 `g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>/` 和同名 `.tar.gz`。

**构建机必须与目标机同 OS、同架构。** 二进制按构建机的动态库链接（OpenSSL、c-ares、Lua、
Python），换台机器就可能起不来。打包前可以确认一下：

```sh
ldd dist/g3-run-*/bin/g3proxy | grep 'not found'   # 应该没有输出
```

要交叉编译就设 `TARGET`（例如 `TARGET=x86_64-unknown-linux-musl`），此时包内自检会被跳过
——产物不能在构建机上运行，配置校验得在目标机做。

可覆盖的环境变量：

| 变量 | 默认值 | 作用 |
|------|--------|------|
| `RUN_BINS` | `g3proxy g3proxy-ctl g3fcgen` | 拷进包 `bin/` 的可执行程序 |
| `BUILD_PACKAGES` | `g3proxy g3proxy-ctl g3fcgen` | 一起编译的 workspace 包 |
| `PROFILE` | `release` | cargo profile；`debug` 走 cargo 的 dev profile |
| `TARGET` | 空 | cargo `--target`，非空时跳过自检 |
| `EXTRA_FEATURES` | 空 | 追加 cargo feature |
| `G3_BUILD_ARGS` | 空 | 原样附加给 cargo 的参数（逃生口） |
| `DIST_DIR` | `<仓库>/dist` | 产物目录 |
| `CONF_DIR` | `etc/g3proxy/http` | `server.d`/`auditor.d` 的来源 |
| `CONF_SUBDIRS` | `server.d auditor.d` | 从 `CONF_DIR` 复制的配置子目录 |

脚本自己判断 c-ares：`pkg-config --atleast-version 1.18.0 libcares` 通过就用系统库，否则退回
`vendored-c-ares`，与 `scripts/package` 里现有打包脚本的判定一致。

### feature 裁剪

feature 一律写成 `包名/feature`（一次 `-p` 多个包时，裸 feature 名会撞上 `g3proxy-ctl` 没有
feature 而报错）。默认 feature 都会编进来，缺 Lua 或 Python 开发库时 `lua54`/`python` 会失败，
需要关掉默认 feature 重来：

```sh
G3_BUILD_ARGS=--no-default-features \
EXTRA_FEATURES="quic rustls-ring vendored-openssl" \
deploy/build_run_package.sh
```

`EXTRA_FEATURES` 里不带包名的会补成 `g3proxy/`；c-ares 一项脚本已经加了，不用重复写。注意这样
编出来的二进制没有 Lua/Python 审计模块，配置里用到 `lua`/`python` 审计器的 server 会校验失败；
`--no-default-features` 也不能省掉 TLS 后端（`rustls-ring` 或 `rustls-aws-lc` 选一）。

### 自检

`TARGET` 为空时，脚本用**包里的二进制**加载**包里的配置**：

```
==> 自检：g3proxy -t -c conf/g3proxy.yaml
```

这一步失败不会打出 tar.gz，包目录留在 `dist/` 里供排查。

## 2. 包内结构

```
g3-run-<...>/
├── bin/g3proxy  bin/g3proxy-ctl  bin/g3fcgen
├── conf/g3proxy.yaml        # 入口配置
├── conf/g3fcgen.yaml        # MITM 证书签发服务的模板
├── conf/server.d/           # 复用 etc/g3proxy/http/server.d
├── conf/auditor.d/          # 复用 etc/g3proxy/http/auditor.d
├── systemd/g3proxy.service  systemd/g3fcgen.service   # 含 @PREFIX@ 等占位符
├── install.sh
├── README.md                # 目标机上的操作说明
└── VERSION                  # 版本、git sha、构建机、profile、feature
```

`server.d`/`auditor.d` 直接取自 `etc/g3proxy/http`，不在 `deploy/` 下再抄一份：改仓库里的样例
配置，run 包跟着变。

## 3. 安装

```sh
tar xzf g3-run-<...>.tar.gz
cd g3-run-<...>
sudo ./install.sh                    # 只装 g3proxy
sudo ./install.sh --with-fcgen       # 顺带装 g3fcgen
sudo ./install.sh --prefix=/data/g3  # 换前缀
```

脚本要求 root 和 `systemctl`，非 systemd 的机器不支持。做的事：

1. `bin/*` 装到 `/opt/zf/g3/bin`（0755），`README.md` 装到 `/opt/zf/g3/README.md`；
2. 配置装到 `/opt/zf/g3/conf`（含 `server.d`、`auditor.d`）；
3. 用 `/opt/zf/g3/bin/g3proxy -t -c /opt/zf/g3/conf/g3proxy.yaml` 校验配置，**失败就不装单元、不启服务**；
4. `sed` 渲染单元里的 `@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@`，写到 `/etc/systemd/system/`，`daemon-reload`；
5. `systemctl enable --now g3proxy`（带 `--with-fcgen` 时再启 g3fcgen）。

**配置文件绝不覆盖。** 目标机上已有的配置一律保持原样：内容相同打一行"配置未变化"，内容不同
把新内容写成同名的 `*.new`，由操作者自己比对合并。这是升级时的回滚依据（见第 6 节）。

## 4. 服务形态

`g3proxy.service` 关键项：

```
Type=exec
RuntimeDirectory=g3                     # /run/g3 由 systemd 创建，控制套接字放这里
ExecStart=@PREFIX@/bin/g3proxy -c @PREFIX@/conf/g3proxy.yaml --control-dir @CONTROL_DIR@ -s -G g3
ExecReload=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G g3 reload
ExecStop=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G g3 -p $MAINPID offline
KillMode=none                           # 停止只走 g3proxy-ctl，不让 systemd 直接杀
RestartPreventExitStatus=255            # 配置不合法时进程以 255 退出，不反复重启
```

`-s` 是 systemd 模式、`-G g3` 是 group name，两者与 `--control-dir` 必须一致，否则
`g3proxy-ctl` 找不到套接字。配置里 `log: stdout`，日志进 journald。

`g3fcgen.service` 用 `ExecStop=/bin/kill -INT $MAINPID` 停止。

## 5. 日常操作

```sh
systemctl status g3proxy
journalctl -u g3proxy -f
systemctl reload g3proxy          # 不停机重载（server/auditor/resolver/escaper/user-group）
systemctl restart g3proxy         # 整份配置重载
sudo ./install.sh uninstall       # 停服务、摘单元，保留 /opt/zf/g3
sudo ./install.sh uninstall --purge   # 连 /opt/zf/g3 一起删
```

reload 走 `g3proxy-ctl reload`，可以只重载某一类：

```sh
/opt/zf/g3/bin/g3proxy-ctl --control-dir /run/g3 -G g3 reload-server
/opt/zf/g3/bin/g3proxy-ctl --control-dir /run/g3 -G g3 reload-auditor
/opt/zf/g3/bin/g3proxy-ctl --control-dir /run/g3 -G g3 list
```

配置改完先校验再重载：

```sh
/opt/zf/g3/bin/g3proxy -t -c /opt/zf/g3/conf/g3proxy.yaml
```

## 6. 升级与回滚

升级就是拿新包再跑一次 `install.sh`：二进制直接覆盖，配置只落到 `*.new`，所以现网配置不会被动。
比对后自己决定怎么合：

```sh
diff /opt/zf/g3/conf/server.d/default.yaml{,.new}
```

回滚：保留旧包（或旧机上的 `/opt/zf/g3`），用旧包重新 `install.sh`，再把 `.new` 删掉。因为
`VERSION` 文件记了 git sha 和构建 feature，出问题时先核对它确认装的是哪一份。

## 7. 配置注意

- 入口配置里 `server: server.d/`、`auditor: auditor.d/` 是**相对本文件所在目录**的路径，所以这两
  个目录必须和 `g3proxy.yaml` 同级；打包已经保证这点。
- `resolver:`、`escaper:` 在入口配置里默认注释掉。**目录不存在时打开这两行会让配置校验失败**，
  先建 `resolver.d`/`escaper.d` 再取消注释。
- 上传审计相关：`auditor.d/default.yaml` 里的 `icap_reqmod_service` 决定旁路审计发给哪个 ICAP
  服务；同文件的 `upload_audit_max_concurrency`（默认 64，0 表示不设限，样例里是注释掉的）控制
  同时进行的上传审计条数，名额用尽时新上传直接退化为直通转发并计入跳过数，不排队。详见
  `doc/http-icap-bypass-audit.md`。
- `g3fcgen.yaml` 里的 `myCA.crt`/`myCA.key` 也是相对配置目录的路径。CA 私钥**不打进 run 包**，
  仓库里的测试私钥不外发；用自己的 CA，放到 `/opt/zf/g3/conf/` 后再 `systemctl restart g3fcgen`。

## 8. 安全说明

- 单元没有做 `User=`/`PrivateNetwork=` 之类的沙箱收敛，服务以 root 运行——g3proxy 需要绑定监听
  端口并写 `/run/g3`，若要降权请自行加 `User=`/`AmbientCapabilities=` 并验证。
- `uninstall --purge` 会 `rm -rf` 整个安装前缀，配置全在里面，执行前确认没有唯一副本。
- `install.sh` 只在目标机本地读写，不联网、不外发任何数据。
