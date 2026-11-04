# g3 run 包：编译与部署

run 包是把 g3 一次编译、一次安装交付到目标机的形态：一个可执行的 `.run` 自解压安装器，
里面是程序、一份配置、systemd 单元和安装/卸载脚本。目标机上直接运行它——不用解包、
不用挑参数——装完程序与配置统一落在 `/opt/zf/g3`，g3proxy 与 g3fcgen 两个服务由 systemd
托管并立即启动。

- 打包脚本：`deploy/build_run_package.sh`
- 安装脚本：`deploy/install.sh`（进包，由 `.run` 解压后调用，不单独使用）
- 卸载脚本：`deploy/uninstall.sh`（进包，安装时落到 `/opt/zf/g3/uninstall.sh`）
- 单元模板：`deploy/systemd/g3proxy.service`、`deploy/systemd/g3fcgen.service`
- 配置来源：`deploy/conf/`——入口配置全部内联在 `g3proxy.yaml` 一个文件里，
  没有 `server.d`、`auditor.d` 子目录

g3fcgen 是必须的服务：auditor 配置里的 `tls_cert_generator` 会在运行时连
`127.0.0.1:2999` 向它按 SNI 取中间人证书。它没有 CA 材料就起不来，所以 CA 是安装的
前置条件（见第 1、3 节）。

## 1. 编译 run 包

```sh
deploy/build_run_package.sh                                    # 默认 release，g3proxy 进 ns-vpp
deploy/build_run_package.sh --profile=debug                     # 排障用的调试包
deploy/build_run_package.sh --bins="g3proxy g3proxy-ctl"        # 精简程序集
deploy/build_run_package.sh --netns=no                          # g3proxy 不进网络命名空间
deploy/build_run_package.sh --netns=/run/netns/ns-other         # 指定命名空间
deploy/build_run_package.sh --portable                          # 跨发行版：去 Lua/Python，内置 OpenSSL/c-ares
deploy/build_run_package.sh --static                            # 在 --portable 之上把 glibc 也静态进去
```

产物在 `dist/`：

- `g3-run-<版本>-<git短sha>-<os>-<arch>-<日期>.run` —— 交付用的自解压安装器；
- 同名 `.tar.gz` 与目录 —— 内容相同，留作不便执行 `.run` 时的手动解包通道。

包里永远有 CA，构建时按这个顺序确定：

1. `deploy/conf/` 下有成套的 `myCA.crt`/`myCA.key` → 直接打进包（正式 CA 就放这里）；
2. 没有 → 构建脚本自动用 `g3mkcert` 生成一份自签根 CA（RSA 2048）写回 `deploy/conf/`，
   随包并供下次打包复用；
3. 只有半套 → 视为放错，打包报错。

`deploy/conf/myCA.*` 已在 `.gitignore` 里：CA 私钥只进包、不入库。自动生成的 CA 适合
测试；正式环境发布前把自己/机构的 CA 放进 `deploy/conf/` 替换掉再打包。

**默认构建的包只能装在与构建机同 OS、同架构的机器上。** 二进制按构建机的动态库链接
（OpenSSL、c-ares、Lua、Python），换台机器就可能起不来。症状是安装脚本走到"校验配置"就断：

```
/opt/zf/g3/bin/g3proxy: error while loading shared libraries: libpython3.10.so.1.0: cannot open shared object file: No such file or directory
配置校验失败，服务未启动；请检查上面 g3proxy 给出的报错
```

`libpython3.10.so.1.0` 只是这一串 `DT_NEEDED` 里第一个找不到的（`python` feature 用 pyo3
`auto-initialize` 把解释器嵌进 g3proxy），补上它还会接着缺 `liblua5.4.so.0`、
`libcares.so.2`、`libssl.so.3`/`libcrypto.so.3`。

**缺库只是第一层，底下还有一层 glibc 符号版本的地板。** 目标机上再 `ldd` 一次，往往会看到
`/usr/lib64/libc.so.6: version 'GLIBC_2.34' not found` 这样的行——那是构建机的 glibc（Ubuntu
22.04 是 2.35）写进二进制的符号版本要求，目标机的 glibc 更老（Kylin V10、RHEL8/CentOS8 那一档
是 2.28）就装不上 python/lua/openssl 也照样起不来。两层都只能在构建机上解决：按下一节
「feature 裁剪」加 `--portable` / `--static` 重打，不要在目标机凑库。

打包前可以确认一下：

```sh
ldd dist/g3-run-*/bin/g3proxy | grep 'not found'   # 应该没有输出
```

注意这一条只证明**构建机**上库是齐的，不代表目标机齐——同一条命令在目标机上跑，才能看出
那边缺什么。

要交叉编译就设 `--target`（例如 `--target=x86_64-unknown-linux-musl`）。只有当它和构建机
三元组不一致时才跳过包内自检——产物跑不起来，配置校验得在目标机做。`--static` 自己补上的
`--target` 就是构建机三元组，所以自检照跑。

配置项用 `--参数=值`（同名环境变量仍可覆盖，仅留作兼容与测试后门）：

| 参数 | 环境变量 | 默认值 | 作用 |
|------|----------|--------|------|
| `--bins=` | `RUN_BINS`+`BUILD_PACKAGES` | `g3proxy g3proxy-ctl g3fcgen` | 编译并拷进包 `bin/` 的可执行程序 |
| `--packages=` | `BUILD_PACKAGES` | 同上 | 只改编译范围、不改 `bin/` 拷贝 |
| `--profile=` | `PROFILE` | `release` | cargo profile；`debug` 走 cargo 的 dev profile |
| `--target=` | `TARGET` | 空 | cargo `--target`，与构建机三元组不同时跳过自检 |
| `--features=` | `EXTRA_FEATURES` | 空 | 追加 cargo feature |
| `--portable` | `PORTABILITY=portable` | 关 | 跨发行版裁剪：去 Lua/Python，OpenSSL 与 c-ares 内置编译 |
| `--static` | `PORTABILITY=static` | 关 | 在 `--portable` 之上把 glibc 也静态进去 |
| `--netns=no` / `--netns=<绝对路径>` | `NETNS`/`NETNS_PATH` | `yes`、`/run/netns/ns-vpp` | g3proxy 单元是否写 `NetworkNamespacePath=` 及路径 |
| `--build-args=` | `G3_BUILD_ARGS` | 空 | 原样附加给 cargo 的参数（逃生口） |
| `--dist-dir=` | `DIST_DIR` | `<仓库>/dist` | 产物目录 |

脚本自己判断 c-ares：`pkg-config --atleast-version 1.18.0 libcares` 通过就用系统库，否则退回
`vendored-c-ares`，与 `scripts/package` 里现有打包脚本的判定一致。`--portable` / `--static`
不看 `pkg-config`，直接强制内置编译。

### feature 裁剪

feature 一律写成 `包名/feature`（一次 `-p` 多个包时，裸 feature 名会撞上 `g3proxy-ctl` 没有
feature 而报错）。默认 feature 都会编进来，缺 Lua 或 Python 开发库时 `lua54`/`python` 会失败，
需要关掉默认 feature 重来。

**跨发行版第一档：`--portable`**（目标机的 glibc 不低于构建机）。开关做三件事：关掉 cargo 的
默认 feature（`lua54` 与 `python` 就不再链构建机的 `liblua5.4.so.0`、`libpython3.10.so.1.0`）、
补回 `quic` 与 TLS 后端 `rustls-ring`、把 OpenSSL 与 c-ares 改成内置编译（`vendored-openssl`、
`g3fcgen/vendored-openssl`、`vendored-c-ares`——c-ares 这一项不再走 pkg-config 探测，跨发行版的
包不能碰构建机的 `libcares.so.2`）：

```sh
deploy/build_run_package.sh --portable --netns=no --dist-dir=dist-portable
```

`g3fcgen/vendored-openssl` 是开关自带的：g3fcgen 一样链 OpenSSL，只裁 g3proxy 会给它留下
`libssl.so.3`/`libcrypto.so.3`。产物没有 Lua/Python 的用户认证模块（`auth` 里 `type: lua` /
`type: python` 那种动态用户名来源）——当前内联配置里根本没有 `auth`，用不到它们；裁剪后请自行
确认目标配置。这样打出来的二进制只剩 glibc 那套动态依赖：

```sh
ldd dist-portable/g3-run-*/bin/g3proxy \
  | grep -vE 'linux-vdso|libc\.so|libm\.so|libgcc_s|ld-linux'   # 应该没有输出
```

**跨发行版第二档：`--static`**（目标机 glibc 比构建机老——Kylin V10、RHEL8/CentOS8 那一档，
`ldd` 会报 `version 'GLIBC_2.34' not found`）。第一档只解决缺 `.so`，解决不了 glibc 符号版本的
地板，得把 glibc 也静态进去：

```sh
deploy/build_run_package.sh --static --netns=no --dist-dir=dist-static
```

开关在第一档之上加 `RUSTFLAGS=-C target-feature=+crt-static`，并自动把 `--target` 填成构建机
自己的三元组（`rustc -Vv` 里的 `host:`）。**这个 `--target` 必须有**：只有显式指定 target，
cargo 才把 rustflags 只施加给目标工件，构建脚本与 proc-macro 走宿主编译；漏掉的话
`tokio-macros`、`async-recursion` 也会吃 `+crt-static`，cargo 直接报
`cannot produce proc-macro for ... as the target ... does not support these crate types`。
早先手写这行配方时要手工补 `--target` 还要另外跑自检，就是被这个坑绊的；现在开关自己处理，
自检也照跑（补出来的 target 就是本机三元组，产物能跑），并额外逐个可执行程序验一遍：

```
==> 自检：g3proxy -t -c conf/g3proxy.yaml
==> 自检：静态链接
  g3proxy: statically linked，无 GLIBC 版本要求
  g3proxy-ctl: statically linked，无 GLIBC 版本要求
  g3fcgen: statically linked，无 GLIBC 版本要求
```

任一条不是 `statically linked`、或者还带着 `GLIBC_` 符号版本要求，打包直接失败——这种包发到
老 glibc 的机器上就是白跑一趟，在构建机拦住比在目标机报错好。手工复核（在目标机上也该用这两条
判断包对不对）：

```sh
ldd bin/g3proxy bin/g3fcgen bin/g3proxy-ctl                    # 都该是 statically linked
objdump -T bin/g3proxy | grep -c 'GLIBC_'                      # 该是 0
```

静态 glibc 的常规代价是 `getaddrinfo` 走不了 NSS（要 dlopen `libnss_*.so`）。这里碰不到：g3proxy
的域名解析只走 `g3-resolver` 的 `c_ares` / `hickory` 两个驱动（自己发 UDP 查询），
`g3proxy/src`、`lib/g3-types`、`lib/g3-daemon` 里没有一处 `getaddrinfo`/`ToSocketAddrs`。实测在
构建机上用这个静态二进制起实例，代理一笔 `http://<主机名>:<端口>/` 能正常解析并按 DPI 规则
放行/拦截。要是哪天改用依赖系统解析器的配置，这条得重新评估。

### 自检

`--target` 为空、或者与构建机三元组一致时，脚本用**包里的二进制**加载**包里的配置**：

```
==> 自检：g3proxy -t -c conf/g3proxy.yaml
```

`--static` 在这之后再加一轮静态链接断言（`ldd` 必须是 `statically linked`，`objdump -T` 里
不能有任何 `GLIBC_` 符号版本要求），见上一节。

只有真正交叉编译（`--target` 是别的三元组）才会打印跳过信息、跳过配置自检。
这两步失败都不会出 `.run`，包目录留在 `--dist-dir`（默认 `dist/`）里供排查。

### 网络命名空间（NETNS）

`deploy/systemd/g3proxy.service` 模板里有一行 `@NETNS@` 占位符，**打包时**就展开：

- 默认（或显式 `--netns=yes` / `--netns=<绝对路径>`）→ 展开成 `NetworkNamespacePath=<路径>`
  （默认 `/run/netns/ns-vpp`）与 `PrivateNetwork=no`；
- `--netns=no` → 这一整行删掉，单元里没有任何命名空间指令。

`--netns=no` 是给非 VPP 宿主机的：默认包在单元里写死了 `/run/netns/ns-vpp`，目标机没有这个
命名空间时，安装会在装完单元之后被 `install.sh` 的存在性检查拦住。

所以进包的 `systemd/g3proxy.service` 在这一项上已经是成品，`install.sh` 只负责
`@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@` 这些目标机才知道的路径。`PrivateNetwork=no` 是
systemd 的默认值，写出来是为了表明意图：只是把进程搬进一个**已存在**的命名空间，
不是做网络隔离。命名空间由 vpp 侧（或 `ip netns add`）先建好，systemd 只负责进去。

生效以后 g3proxy 看到的是 ns-vpp 的网络栈，**`127.0.0.1` 变成该命名空间的回环**，而
g3proxy 的两个回环依赖都不进 ns：

- `tls_cert_generator` 连 g3fcgen 的 `127.0.0.1:2999`（TLS 拦截取中间人证书）；
- `icap_reqmod_service` 的 `icap://127.0.0.1:1344/echo`（旁路审计）。

也就是说：这两条地址必须在 ns-vpp 里取到东西（vpp 侧自己有一套 g3fcgen/ICAP，或者用
`query_peer_addr` 等配置指向能跨命名空间到达的地址），否则 TLS 拦截会在握手时失败、
审计请求发不出去。`install.sh` 只检查命名空间存不存在，检查不了里面的服务通不通。

## 2. 包内结构

```
g3-run-<...>/
├── bin/g3proxy  bin/g3proxy-ctl  bin/g3fcgen
├── conf/g3proxy.yaml        # 入口配置：server、auditor 全部内联
├── conf/g3fcgen.yaml        # MITM 证书签发服务的配置
├── conf/myCA.crt  myCA.key  # 必带：deploy/conf 里的成套 CA，没有则构建时自动生成
├── systemd/g3proxy.service  systemd/g3fcgen.service   # g3proxy.service 已展开 NETNS，余下占位符待安装时替换
├── install.sh               # 由 .run 调用
├── uninstall.sh             # 安装时复制到 /opt/zf/g3/uninstall.sh
├── README.md                # 目标机上的操作说明
└── VERSION                  # 版本、git sha、构建机、profile、feature、是否带 CA、NETNS 取值
```

`.run` 就是在这个结构上做的自解压：一个几十行的 POSIX sh 头部脚本 + 尾部 tar.gz 负载。
运行时 `tail -n +<行号>` 取出负载解进 `mktemp` 临时目录（0700，退出即删——里面可能有
CA 私钥），然后执行包内 `install.sh`。

## 3. 安装

把 `.run` 拷到目标机，一条命令：

```sh
sudo ./g3-run-<...>.run
```

没有任何参数（给了参数会直接拒绝并说明卸载方式）。要求 root 和 `systemctl`，非 systemd
的机器不支持。做的事：

1. 检查包结构、root、systemd，再兜底检查 CA：正常构建的包必带 CA（见第 1 节），只有包被
   手工改动时才可能缺失——那时在写任何系统目录**之前**中止；
2. `bin/*` 装到 `/opt/zf/g3/bin`（0755），`README.md`/`VERSION` 落到 `/opt/zf/g3/`；
3. 配置装到 `/opt/zf/g3/conf`（`g3proxy.yaml`、`g3fcgen.yaml`、随包的 CA）。**首次安装**
   （目标机上还没有 `g3proxy.yaml`）会问一行"g3proxy 监听端口 [10087]："：直接回车或输入
   空行用默认，填别的数字则写进刚装好的 `g3proxy.yaml`，非法输入会重问；非交互执行
   （stdin 到 EOF）自动落默认值。已有配置时不询问，端口以现网文件为准，改端口直接编辑
   `/opt/zf/g3/conf/g3proxy.yaml` 再重启；
4. 用 `/opt/zf/g3/bin/g3proxy -t -c /opt/zf/g3/conf/g3proxy.yaml` 校验配置，**失败就不装单元、不启服务**；
5. `sed` 渲染单元里的 `@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@`（`@NETNS@` 已在打包时展开掉了），写到 `/etc/systemd/system/`，`daemon-reload`；
6. 把 `uninstall.sh` 复制到 `/opt/zf/g3/uninstall.sh`；
7. 单元里写了 `NetworkNamespacePath=` 时，检查该路径在目标机存在——命名空间不存在就直接
   失败并给出三条出路（建命名空间 / `systemctl edit` 现场置空 / `--netns=no` 重打包），
   不留一个起不来的 g3proxy 让操作者去翻 journal；
8. `systemctl enable --now g3fcgen`（失败即整体失败退出），再 `enable --now g3proxy`。

**配置文件绝不覆盖。** 目标机上已有的配置（含 CA）一律保持原样：内容相同打一行
"配置未变化"，内容不同把新内容写成同名的 `*.new`，由操作者自己比对合并。这是升级时
的回滚依据（见第 6 节）。

## 4. 服务形态

`g3proxy.service` 关键项：

```
Type=exec
NetworkNamespacePath=/run/netns/ns-vpp  # 打包时展开，NETNS=no 时这两行不存在
PrivateNetwork=no                       # 显式声明只做命名空间迁移、不做网络隔离（systemd 默认值）
RuntimeDirectory=g3                     # /run/g3 由 systemd 创建，控制套接字放这里
ExecStart=@PREFIX@/bin/g3proxy -c @PREFIX@/conf/g3proxy.yaml --control-dir @CONTROL_DIR@ -s -G g3
ExecReload=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G g3 reload
ExecStop=@PREFIX@/bin/g3proxy-ctl --control-dir @CONTROL_DIR@ -G g3 -p $MAINPID offline
KillMode=none                           # 停止只走 g3proxy-ctl，不让 systemd 直接杀
RestartPreventExitStatus=255            # 配置不合法时进程以 255 退出，不反复重启
```

`-s` 是 systemd 模式、`-G g3` 是 group name，两者与 `--control-dir` 必须一致，否则
`g3proxy-ctl` 找不到套接字。配置里 `log: stdout`，日志进 journald。

`g3fcgen.service` 用 `ExecStop=/bin/kill -INT $MAINPID` 停止，同样带
`RestartPreventExitStatus=255`。

`NetworkNamespacePath=` 需要 systemd ≥ 246；命名空间必须已经存在（`ip netns list` 能看见），
systemd 不会代你创建。g3fcgen 单元不带这两行，它留在 host 网络——因此 g3proxy 进了 ns 之后
两者不在同一个回环上，取舍见第 1 节。

## 5. 日常操作

```sh
systemctl status g3proxy g3fcgen
journalctl -u g3proxy -u g3fcgen -f
systemctl reload g3proxy          # 不停机重载（server/auditor/resolver/escaper/user-group）
systemctl restart g3proxy         # 整份配置重载
sudo /opt/zf/g3/uninstall.sh      # 停服务、摘单元，并删除 /opt/zf/g3
```

卸载停服务、摘 systemd 单元，最后**删除整个 `/opt/zf/g3`**——配置与 CA 一并清除，
确认没有唯一副本再跑（要留就先拷走 `conf/`）。包里那份 `uninstall.sh` 有守卫：在包
目录里执行时识别出 `install.sh` 同级，只摘单元、整包原样保留。

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

升级就是拿新的 `.run` 再跑一次：二进制直接覆盖，配置只落到 `*.new`，所以现网配置不会
被动。比对后自己决定怎么合：

```sh
diff /opt/zf/g3/conf/g3proxy.yaml{,.new}
```

回滚：直接拿旧包的 `.run` 再跑一次（二进制覆盖、现网配置不动），再把 `.new` 删掉；
不必先卸载——`uninstall.sh` 会把 `/opt/zf/g3` 整个删掉。`VERSION` 文件记了 git sha、
构建 feature 和是否带 CA，出问题时先核对它确认装的是哪一份。

## 7. 配置注意

- 入口配置 `/opt/zf/g3/conf/g3proxy.yaml` 里 `server:`、`auditor:` 都是**内联数组**，
  改端口、ICAP 审计地址、拦截开关只动这一个文件。
- `resolver:`、`escaper:` 已在入口配置里内联定义（`resolver` 用 c-ares、`escaper`
  用 `direct_fixed` 直连出口，名字都叫 `default`）。**`server:` 段引用的 `escaper: default`
  必须有对应定义**，否则 g3proxy 会拿内置 `DummyDeny` 占位，所有请求以
  `ForbiddenByRule / method unavailable` 拒绝——浏览器配了代理却打不开任何页面就是这一条。
  要按域名/地址分流换成 `fail_over`/`route_*`，或改走 `escaper.d/` 目录（先建目录再指向）。
- HTTPS 走的是 MITM 拦截：证书由随包 CA 签发，客户端（浏览器/系统信任库/`curl`）必须信任
  `myCA.crt`，否则报 `self-signed certificate in certificate chain`、握手失败（日志里是
  `InterceptionError … ssl3_read_bytes`）。排查转发本身通不通时可临时用 `curl -x … -k` 绕过校验。
  客户端信任 `myCA.crt` 可用仓库里的 Windows 脚本：`deploy/windows-install-ca.bat`（与
  `myCA.crt` 放同目录双击，自动提权导进本机"受信任的根证书颁发机构"并校验；Firefox 仍需
  在它自己的证书管理器里单独导入）。
- 内网源站自己的 TLS 参数也会让拦截失败，症状同样是 `reason: InterceptionError`，但出错的是
  g3proxy 当 TLS 客户端这一侧（`tls_interception_client`，默认只信系统根 CA、OpenSSL 安全级别 1）。
  FTP 最典型：客户端发 `AUTH TLS` 后日志依次是 `protocol: ftp_control` → `FtpConnection` →
  `StartTlsHandshake`，接着 `upstream handshake failed: … certificate verify failed`，HTTP 却一切正常
  （公网站点证书是可信的）。两条成因各自独立，缺一不可：`certificate verify failed` 是源站自签，
  `dh key too small` 是源站 dhparams 只有 1024 位。逐台 `ca_certificate` 追加信任锚不可持续
  ——内网源站无法预先枚举，今天堵 FTP 一台自签，明天又是别台——所以入口配置直接
  `insecure: true`（不校验源站证书）+ `security_level: 0`（放行弱参数）。只配 `insecure` 的话
  FTP 仍连不上，握手会接着报 `dh key too small`。
  **代价**：这一份 TLS 客户端上下文整个 auditor 共用，g3proxy→源站段从此发现不了证书被冒充或
  降级，被拦截的公网 HTTPS 也一并不再校验源站证书；启动日志那句 `Tls Insecure Mode: Tls Peer
  (server) cert vertification is no longer enforced` 是这件事的自述，不是故障。要收紧就单独给内网
  协议开一个 `server:` 段（另听一个端口）配一个专用 `auditor:`，只在那个 auditor 上设 `insecure`，
  公网流量继续走带校验的那个；或者改源站（2048 位 dhparams、`ssl_ciphers` 优先 ECDHE、内网长期
  CA 签服务器证书），那之后两个键都可以删。
  想先确认某台源站占了哪几条，直连探一次即可：`openssl s_client -connect 20.20.136.42:21
  -starttls ftp` 会同时报 `verify error:num=18:self-signed certificate` 与
  `tls_process_ske_dhe: dh key too small`。修好的标志：`StartTlsHandshake` 落 `ok`，客户端看到的
  FTP 证书签发者变成 `g3 MITM Root CA`。
- 上传审计相关：`auditor` 段里的 `icap_reqmod_service` 决定旁路审计发给哪个 ICAP
  服务；`upload_audit_max_concurrency`（默认 64，0 表示不设限，样例里是注释掉的）控制
  同时进行的上传审计条数，名额用尽时新上传直接退化为直通转发并计入跳过数，不排队。详见
  `doc/http-icap-bypass-audit.md`。
- 默认打包让 g3proxy 进 `ns-vpp`：`g3proxy.yaml` 里写 `127.0.0.1` 的 g3fcgen(2999) 与
  ICAP(1344) 指的是 ns-vpp 的回环，不是 host 的。vpp 里没有这两个服务时，要么在 ns-vpp 里
  起一套，要么把地址改成能跨命名空间到达的（`tls_cert_generator` 的 `query_peer_addr`、
  `icap_reqmod_service` 里的地址）。
- `g3fcgen.yaml` 里的 `myCA.crt`/`myCA.key` 是相对配置目录的路径。CA 由构建保证随包：
  `deploy/conf/` 有成套就用它，没有则 `g3mkcert` 自动生成（正式环境发布前换成自己的再打包）。
  仓库里的测试私钥不外发；带 CA 的 `.run` 本身就是敏感物，分发必须走受控渠道。

## 8. 安全说明

- 单元没有做 `User=` 之类的沙箱收敛，服务以 root 运行——g3proxy 需要绑定监听
  端口并写 `/run/g3`，若要降权请自行加 `User=`/`AmbientCapabilities=` 并验证。默认的
  `NetworkNamespacePath=` 只是把进程搬进 vpp 那侧已经存在的网络命名空间（systemd 需要
  `CAP_SYS_ADMIN`，root 服务本就有），`PrivateNetwork=no` 表示没有做网络隔离，不是安全加固；
  要完全关掉就在打包时 `--netns=no`。
- 带 CA 的 `.run` 含私钥：临时目录 0700、退出即删，但**文件本身的保管与分发要按私钥的
  级别来**。`deploy/conf/myCA.*` 已进 `.gitignore`，不要把私钥提交进仓库。
- `uninstall.sh` 会 `rm -rf` 整个安装目录 `/opt/zf/g3`，配置与 CA 全在里面，执行前确认
  没有唯一副本。
- 安装/卸载脚本只在目标机本地读写，不联网、不外发任何数据。

## 9. 设计与跟踪

- 设计（含方案取舍与遗留待决策项）：`docs/superpowers/specs/2026-11-02-g3-run-package-deploy-design.md`
- 实施与验证清单：`docs/superpowers/plans/2026-11-02-g3-run-package-deploy.md`
