# g3 run 包：编译与部署

run 包是把 g3 一次编译、一次安装交付到目标机的形态：一个可执行的 `.run` 自解压安装器，
里面是程序、一份配置、systemd 单元和安装/卸载脚本。目标机上直接运行它——不用解包、
不用挑参数——装完程序与配置统一落在 `/opt/zf/g3`，g3proxy 与 g3fcgen 两个服务由 systemd
托管并立即启动。

同一套脚本还打**第二个包**：ICAP 审计服务端 `g3icap`（交互选 icap，装到
`/opt/zf/icap`）。分两个包是因为它不是 g3proxy 的必需品（现场多半接自己的 ICAP 设备），
但**装了三者就必须同一个网络命名空间**（见第 1 节"网络命名空间"）。

- 打包脚本：`deploy/build_run_package.sh`
- 安装脚本：`deploy/install.sh`（g3 包）、`deploy/icap-install.sh`（icap 包）。进包后都叫
  `install.sh`，由 `.run` 解压后调用，不单独使用
- 卸载脚本：`deploy/uninstall.sh`、`deploy/icap-uninstall.sh`（进包后都叫 `uninstall.sh`，
  安装时复制到各自前缀下）
- 单元模板：`deploy/systemd/g3proxy.service`、`g3fcgen.service`、`g3icap.service`
- 配置来源：`deploy/conf/`——入口配置全部内联在 `g3proxy.yaml` 一个文件里，
  没有 `server.d`、`auditor.d` 子目录

g3fcgen 是必须的服务：auditor 配置里的 `tls_cert_generator` 会在运行时连
`127.0.0.1:2999` 向它按 SNI 取中间人证书。它没有 CA 材料就起不来，所以 CA 是安装的
前置条件（见第 1、3 节）。

`g3icap` 是审计链路的末端：auditor 配置里的 `icap_reqmod_service` 指向
`icap://127.0.0.1:1344/icap_audit`（HTTP 与 FTP 两条链路都用这个名字）。它由
`lib/g3-icap-client` 的 example 提升为独立 crate
（`g3icap/`），只做回显 + 逐段打印送审报文，用来在没接真实 ICAP 设备时把链路打通、
看清明面上到底送了什么。接真实 ICAP 服务（c-icap、检测网关等）时不必装这个包。

## 1. 编译 run 包

```sh
deploy/build_run_package.sh                                    # 默认 release + portable 裁剪，安装时默认进 ns-vpp
deploy/build_run_package.sh --profile=debug                     # 排障用的调试包
deploy/build_run_package.sh --bins="g3proxy g3proxy-ctl"        # 精简程序集
deploy/build_run_package.sh --portable=no                       # 按构建机动态库链接（目标机与构建机同系统）
deploy/build_run_package.sh --static                            # 在 --portable 之上把 glibc 也静态进去
deploy/build_run_package.sh --static                            # 交互选 icap：老 glibc 目标机的 ICAP 包
```

脚本启动时交互选择编译哪个组件：输 `1`/`g3`（默认，回车即用）或 `2`/`icap`；
非交互（stdin 是 EOF，如管道/自动化）落默认 g3，`COMPONENT` 环境变量可预置默认值
（仅测试后门）。

产物在 `dist/`，只有交付用的自解压安装器：

- `g3-<arch>-<日期><裁剪标签>.run` / `g3icap-<...>.run`，如
  `g3-x86_64-20261112-portable.run`。版本、git sha 与精确构建时间不进包名，
  记在包内 `VERSION` 文件里

组装包用的目录和中间 `.tar.gz` 都在工作区 `target/pkg/`（`WORK_DIR` 可改），`.run` 一生成就
清掉——`dist/` 下不会留下第二份拷贝。不便执行 `.run`、只想要裸目录时，从 `.run` 里解出负载：

```sh
L=$(sed -n 's/^PAYLOAD_LINE=\(.*\)/\1/p' g3-xxx.run)   # 头部脚本占多少行
tail -n +"$L" g3-xxx.run | tar xzf -                   # 解出 g3-xxx/
```

g3 包里永远有 CA，构建时按这个顺序确定：

1. `deploy/conf/` 下有成套的 `myCA.crt`/`myCA.key` → 直接打进包（正式 CA 就放这里）；
2. 没有 → 构建脚本自动用 `g3mkcert` 生成一份自签根 CA（RSA 2048）写回 `deploy/conf/`，
   随包并供下次打包复用；
3. 只有半套 → 视为放错，打包报错。

`deploy/conf/myCA.*` 已在 `.gitignore` 里：CA 私钥只进包、不入库。自动生成的 CA 适合
测试；正式环境发布前把自己/机构的 CA 放进 `deploy/conf/` 替换掉再打包。

**下面这一整段"库依赖 / glibc 地板"只针对 g3 包。** `g3icap` 的依赖树是纯 Rust
（`icap-rs` + tokio + tracing），不链 OpenSSL/c-ares/Lua/Python，缺 `.so` 那一层根本不会
出现；`--portable` 对它是空操作（接受这个参数只为两条命令行长得一样）。老 glibc 的
目标机（Kylin V10、RHEL8 那一档）要打 `--static` 并交互选 icap，见"feature 裁剪"。

**默认构建就是 `--portable` 裁剪包**：OpenSSL/c-ares 静态进二进制、去掉 Lua/Python，
运行时只剩目标机的 glibc 那一层动态依赖，同架构不同发行版可装（glibc 不低于构建机）。
只有显式 `--portable=no` 才按构建机的动态库链接（OpenSSL、c-ares、Lua、Python），
**那样的包只能装在与构建机同 OS、同架构的机器上**，换台机器就可能起不来。症状是安装脚本走到"校验配置"就断：

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
是 2.28）就装不上 python/lua/openssl 也照样起不来。两层都只能在构建机上解决：
用默认的 `--portable`（glibc 不低于构建机）或 `--static`（glibc 更老）重打，不要在目标机凑库。

打包前可以确认一下：

```sh
ldd target/release/g3proxy | grep 'not found'   # 应该没有输出（打进包的就是这个二进制）
```

注意这一条只证明**构建机**上库是齐的，不代表目标机齐——同一条命令在目标机上跑，才能看出
那边缺什么。

要交叉编译就设 `--target`（例如 `--target=x86_64-unknown-linux-musl`）。只有当它和构建机
三元组不一致时才跳过包内自检——产物跑不起来，配置校验得在目标机做。`--static` 自己补上的
`--target` 就是构建机三元组，所以自检照跑。

配置项用 `--参数=值`（同名环境变量仍可覆盖，仅留作兼容与测试后门）：

| 参数 | 环境变量 | 默认值 | 作用 |
|------|----------|--------|------|
| `--bins=` | `RUN_BINS`+`BUILD_PACKAGES` | g3 包 `g3proxy g3proxy-ctl g3fcgen`；icap 包 `g3icap` | 编译并拷进包 `bin/` 的可执行程序 |
| `--packages=` | `BUILD_PACKAGES` | 同上 | 只改编译范围、不改 `bin/` 拷贝 |
| `--profile=` | `PROFILE` | `release` | cargo profile；`debug` 走 cargo 的 dev profile |
| `--target=` | `TARGET` | 空 | cargo `--target`，与构建机三元组不同时跳过自检 |
| `--features=` | `EXTRA_FEATURES` | 空 | 追加 cargo feature（写成 `包名/feature`） |
| `--portable` | `PORTABILITY=portable` | **默认开** | 跨发行版裁剪：去 Lua/Python，OpenSSL 与 c-ares 内置编译（对 icap 包是空操作） |
| `--portable=no` / `--static=no` | `PORTABILITY=no` | — | 退回按构建机动态库链接，仅目标机与构建机同系统时用 |
| `--static` | `PORTABILITY=static` | 关 | 在 `--portable` 之上把 glibc 也静态进去 |
| `--build-args=` | `G3_BUILD_ARGS` | 空 | 原样附加给 cargo 的参数（逃生口） |
| `--dist-dir=` | `DIST_DIR` | `<仓库>/dist` | 产物目录，只放最终的 `.run` |
|  | `WORK_DIR` | `<仓库>/target/pkg` | 组装工作区：包目录与中间归档，成功后清空 |

脚本自己判断 c-ares：只有 `--portable=no` 模式下，`pkg-config --atleast-version 1.18.0 libcares`
通过就用系统库，否则退回 `vendored-c-ares`，与 `scripts/package` 里现有打包脚本的判定一致。
默认的 `--portable` 与 `--static` 不看 `pkg-config`，直接强制内置编译。

### feature 裁剪

feature 一律写成 `包名/feature`（一次 `-p` 多个包时，裸 feature 名会撞上 `g3proxy-ctl` 没有
feature 而报错）。

**默认就是 `--portable` 裁剪**（目标机的 glibc 不低于构建机）。它做三件事：关掉 cargo 的
默认 feature（`lua54` 与 `python` 就不再链构建机的 `liblua5.4.so.0`、`libpython3.10.so.1.0`）、
补回 `quic` 与 TLS 后端 `rustls-ring`、把 OpenSSL 与 c-ares 改成内置编译（`vendored-openssl`、
`g3fcgen/vendored-openssl`、`vendored-c-ares`——c-ares 这一项不再走 pkg-config 探测，跨发行版的
包不能碰构建机的 `libcares.so.2`）：

```sh
deploy/build_run_package.sh --dist-dir=dist-portable            # 默认即 portable
```

`g3fcgen/vendored-openssl` 是开关自带的：g3fcgen 一样链 OpenSSL，只裁 g3proxy 会给它留下
`libssl.so.3`/`libcrypto.so.3`。产物没有 Lua/Python 的用户认证模块（`auth` 里 `type: lua` /
`type: python` 那种动态用户名来源）——当前内联配置里根本没有 `auth`，用不到它们；裁剪后请自行
确认目标配置。这样打出来的二进制只剩 glibc 那套动态依赖：

```sh
ldd target/release/g3proxy \
  | grep -vE 'linux-vdso|libc\.so|libm\.so|libgcc_s|ld-linux'   # 应该没有输出
```

显式 `--portable=no` 退回按构建机动态库链接：默认 feature 都会编进来，缺 Lua 或 Python
开发库时 `lua54`/`python` 会失败，需要装开发库或改回 portable。仅目标机与构建机同一套
系统时用。

**跨发行版第二档：`--static`**（目标机 glibc 比构建机老——Kylin V10、RHEL8/CentOS8 那一档，
`ldd` 会报 `version 'GLIBC_2.34' not found`）。第一档只解决缺 `.so`，解决不了 glibc 符号版本的
地板，得把 glibc 也静态进去：

```sh
deploy/build_run_package.sh --static --dist-dir=dist-static
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
老 glibc 的机器上就是白跑一趟，在构建机拦住比在目标机报错好。

> **`--static` 的包在 HTTPS 拦截下会崩，2026-11-09 实测（Ubuntu 22.04 / glibc 2.35 / x86-64-v3 构建机）。**
> 现象是装完 40 秒内 g3proxy 反复 core-dump，glibc 报 `malloc(): unaligned tcache chunk detected`、
> `free(): double free detected in tcache`、`malloc_consolidate(): invalid chunk size` 几种堆损坏变体，
> 栈顶落在 OpenSSL 的 `tls_process_server_certificate → X509_new_ex → CRYPTO_malloc`（这里只是第一个
> 撞上已损坏堆元数据的分配点，不是真凶），崩溃时另一线程正在 `x509_pubkey_ex_d2i_ex → OSSL_DECODER →
> BIO_free` 上解证书。崩溃循环撞满 systemd 的默认速率上限后 unit 直接 failed，3128 无人监听。
>
> 同一份流量做的 2×2 差分把这个变量钉死了，而且**与这几天改的 keylog / ICAP / 上传审计代码无关**：
> Nov-4 的老代码 `0dcc6c72` 打成的静态包同样在 20 秒内崩（`free(): too many chunks detected in tcache`），
> 而动态 glibc 的包（`--portable`，内置 OpenSSL 4.0.2）跑 3360 条任务零崩溃、零解密错误。
>
> **静态产物还有第二个、更早出现的症状**：每一轮静态压测都带 `tlsv1 alert decrypt error`——客户端报告
> 密钥材料错误，说明静态包在崩之前就已经在真实 TLS 会话上算错了密钥。实测比例（任务数：错误数）
> 2:6、4:13、10:52、14:38、36:420、58:912；动态产物 0:3360。
>
> 崩溃点不固定，一次是 SIGSEGV 落在 `ossl_provider_ctx` 读 `prov->provctx`（入口已有 NULL 检查，
> 传进来的指针非空但是悬垂），其余是 glibc 的 `malloc()/free()` 堆元数据断言。下面这些解释都已被
> 实测否证，别再往里猜：
>
> - **不是 static-PIE 的自定位 / IRELATIVE**：改用 `-C relocation-model=static` 编出非 PIE 的普通静态
>   二进制，2 轮内同样 `malloc(): unaligned tcache chunk`。
> - **不是静态 TLS 模型不匹配**：`readelf -r` 里 `R_X86_64_TLSGD`/`TDESC` 数量为 0，静态产物根本不走
>   `__tls_get_addr`。
> - **不是 OpenSSL CPU 能力探测选错汇编路径**：`OPENSSL_ia32cap=0x0:0x0` 之后，崩溃与解密错误都照旧
>   （这台机是 QEMU 虚拟 CPU，只有 `sse4_1 sse4_2 aes`，本来就容易踩这类坑）。
> - **不是 glibc 分配器的可调项**：`GLIBC_TUNABLES=glibc.malloc.arena_max=1` 与
>   `glibc.malloc.tcache_count=0` 都拦不住崩溃。
> - **不是两份 OpenSSL 绑定共存**：`Cargo.lock` 只锁 `variant-ssl 0.17.37`（registry 里的 0.18.1 是
>   别的项目留下的）；两个产物内都是单份 OpenSSL 4.0.2 符号。
> - **不是普通的越界写 / use-after-free**：valgrind memcheck（自带分配器 + redzone）在静态产物上灌完
>   472 条任务，`Invalid write/read/free` 一条都没有；仅有的"读未初始化值"聚类落在 glibc 的静态启动
>   路径（`_dl_non_dynamic_init`/`_dl_init_paths`/`_dl_get_origin`、`getrandom`），属于启动噪声。
>   写入目标始终是**仍然存活的对象**，所以 memcheck 结构上就看不见它。
> - **和并行执行强相关**：`runtime.thread_number: 1` 时 456 条任务不崩；把 8 个 worker 的静态进程用
>   `taskset -c 0` 绑到单个 CPU（并发连接数不变，只是没有真并行）420 条任务不崩——但解密错误照旧出现。
>
> 结论：这是**只在静态产物里出现、被真并行放大的内存损坏**，具体坏在哪一行仍未定位。要继续查只能上
> ASAN/TSAN（本机 stable 1.95 不支持 `-Zsanitizer=address`，需要 nightly + `-Zbuild-std`，并且 vendored
> OpenSSL 也要带 sanitizer 重编一遍）。在定位之前，**给 HTTPS 拦截场景用 `--static` 就是不可接受的**：
> 它不是"偶尔 core dump"，而是先静默算错会话密钥。
>
> 因此：**目标机 glibc 不比构建机老就别用 `--static`，用 `--portable`**（一样内置 OpenSSL/c-ares，只是
> 不静态 glibc）。真要给老 glibc 目标机出静态包，上线前必须按上面的方法压一遍：至少 2 个 worker 线程、
> 几十路并发 HTTPS 拦截，确认既没有 core-dump、也没有 `alert decrypt error` 再装。单元里也已经加了 `StartLimitIntervalSec=0` +
> `RestartSec=2s` + `KillMode=mixed`：崩了会自己带退避重启、不会把端口永久留在 dead 状态，`systemctl
> stop` 也会连带收掉残留进程（`KillMode=none` 时那个残留能挂着好几天不放客户端连接）。
>
> 手工复核（在目标机上也该用这两条判断包对不对）：

```sh
ldd bin/g3proxy bin/g3fcgen bin/g3proxy-ctl                    # 都该是 statically linked
objdump -T bin/g3proxy | grep -c 'GLIBC_'                      # 该是 0
```

ICAP 包同样吃这一档，而且它才是老目标机上更常用的一档——`g3icap` 没有 C 依赖，需要静态的
只有 glibc 本身：

```sh
deploy/build_run_package.sh --static   # 交互选 icap
```

```
==> 自检：g3icap --version
g3icap 0.1.0
==> 自检：静态链接
  g3icap: statically linked，无 GLIBC 版本要求
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

icap 包没有配置可加载，这一轮换成 `g3icap --version`（同样能确认产物在构建机上跑得起来）。

`--static` 在这之后再加一轮静态链接断言（`ldd` 必须是 `statically linked`，`objdump -T` 里
不能有任何 `GLIBC_` 符号版本要求），见上一节。

只有真正交叉编译（`--target` 是别的三元组）才会打印跳过信息、跳过配置自检。
这两步失败都不会出 `.run`，包目录留在工作区（`WORK_DIR`，默认 `target/pkg/`）里供排查——
成功了反倒会把它删掉，`dist/` 只留那个 `.run`。

### 网络命名空间：安装时选择，三个服务必须在一个里

`deploy/systemd/` 下三个单元模板（`g3proxy.service`、`g3fcgen.service`、`g3icap.service`）
都有一行 `@NETNS@` 占位符，原样进包，**安装时**展开。安装器会问一行：

```
网络命名空间 [/run/netns/ns-vpp]（输 no 留在 host 网络）：
```

- 回车用默认值：新装是 `/run/netns/ns-vpp`；升级取已装单元正在用的命名空间（不把服务
  搬走）；新装时已装对端包就跟随对端的命名空间；
- 输绝对路径（`/run/netns/<名字>`）进别的命名空间；
- 输 `no` → 这一整行删掉，单元里没有任何命名空间指令，服务留在 host 网络（给非 VPP
  宿主机用的）；
- 非交互安装（stdin 是 EOF，如管道/自动化）直接落默认值，不卡住。

选定的路径展开成 `NetworkNamespacePath=<路径>` 与 `PrivateNetwork=no`；命名空间在目标机
不存在时安装会失败（在写任何系统目录**之前**就拦下，不留半装状态）。
`PrivateNetwork=no` 是 systemd 的默认值，写出来是为了表明意图：
只是把进程搬进一个**已存在**的命名空间，不是做网络隔离。命名空间由 vpp 侧（或
`ip netns add`）先建好，systemd 只负责进去。

**为什么 g3fcgen 与 g3icap 也要进去。** g3proxy 进 ns 之后，它眼里的 `127.0.0.1` 就是那个
命名空间的回环，而它两个依赖全写在回环上：

- `tls_cert_generator` 连 g3fcgen 的 `127.0.0.1:2999`（TLS 拦截取中间人证书）；
- `icap_reqmod_service` 的 `icap://127.0.0.1:1344/icap_audit`（旁路审计）。

这两个服务留在 host 时，两条地址在 ns-vpp 里都是空的：TLS 拦截在握手时失败，审计请求静默
丢掉——服务全都 `active (running)`，日志里却什么送审都没有，比装不上难查得多。所以约定是
**g3proxy、g3fcgen、g3icap 三个服务共用一个命名空间**，两个包安装时选同一个命名空间。
不想动配置的话就都得进去；要让 g3proxy 跨命名空间取东西，改的是配置（`tls_cert_generator`
的 `query_peer_addr`、`icap_reqmod_service` 的地址），不是单元。

安装脚本按这个约定拦两种错，两个包的脚本对称：

1. **跨包**：读目标机上已装的兄弟单元（g3 包看 `g3icap.service`，icap 包看
   `g3proxy.service`/`g3fcgen.service`），与本次选的命名空间不一致就失败并给出三条出路
   （重装选同一个命名空间 / `systemctl edit` 现场改 / 两边都退回 host）。目标机上还没装
   对端时只提示一句，不拦——两个包谁先装都行；
2. **存在性**：选的命名空间路径在目标机不存在就失败（systemd 不会代你建）。

g3 包内两个单元用同一个选值展开，包内自己不一致的情况不再存在。

装完之后，如果确实进了命名空间，脚本再用 `nsenter --net=<路径>` 探一次回环
（`exec 3<>/dev/tcp/127.0.0.1/2999` 与 `:1344`），把可达/不可达逐条打印出来。这一步
**只提示、不作为安装失败条件**：另一个包可能还没装，目标机也可能没 `nsenter`。现场
核对三个服务在不在同一个命名空间，一条命令就够：

```sh
systemctl show -p NetworkNamespacePath g3proxy g3fcgen g3icap    # 三行应当一致
```

## 2. 包内结构

g3 包（交互选 g3，默认）：

```
g3-<...>/
├── bin/g3proxy  bin/g3proxy-ctl  bin/g3fcgen
├── conf/g3proxy.yaml        # 入口配置：server、auditor 全部内联
├── conf/g3fcgen.yaml        # MITM 证书签发服务的配置
├── conf/myCA.crt  myCA.key  # 必带：deploy/conf 里的成套 CA，没有则构建时自动生成
├── systemd/g3proxy.service  systemd/g3fcgen.service
├── install.sh               # 由 .run 调用，装 /opt/zf/g3
├── uninstall.sh             # 安装时复制到 /opt/zf/g3/uninstall.sh
├── README.md                # 目标机上的操作说明
└── VERSION                  # 版本、git sha、构建机、profile、feature、是否带 CA
```

ICAP 包（交互选 icap）：

```
g3icap-<...>/
├── bin/g3icap
├── systemd/g3icap.service
├── install.sh               # 装 /opt/zf/icap；包里那份叫 icap-install.sh，进包统一改名
├── uninstall.sh             # 安装时复制到 /opt/zf/icap/uninstall.sh
├── README.md
└── VERSION
```

没有 `conf/`：`g3icap` 的参数（监听地址、注册的服务名、打印正文的上限）全在命令行为主，
单元里写死 `--listen 127.0.0.1:1344`，要改就 `systemctl edit g3icap`。两个包单元里的
`@NETNS@` 都在安装时展开（安装器询问命名空间，默认 `/run/netns/ns-vpp`），其余占位符
也在安装时替换；`VERSION` 里额外记了
`component:` 与所用 crate 的版本（`g3icap` 自己的 0.1.0 与 g3proxy 的包版本是两个数）。

`.run` 就是在这个结构上做的自解压：一个几十行的 POSIX sh 头部脚本 + 尾部 tar.gz 负载。
运行时 `tail -n +<行号>` 取出负载解进 `mktemp` 临时目录（0700，退出即删——里面可能有
CA 私钥），然后执行包内 `install.sh`。

## 3. 安装

把 `.run` 拷到目标机，一条命令：

```sh
sudo ./g3-<...>.run
```

没有任何参数（给了参数会直接拒绝并说明本包装法与卸载方式）。要求 root 和 `systemctl`，
非 systemd 的机器不支持。g3 包做的事：

1. 检查包结构、root、systemd，再兜底检查 CA：正常构建的包必带 CA（见第 1 节），只有包被
   手工改动时才可能缺失——那时在写任何系统目录**之前**中止；
2. **选网络命名空间并做契约检查**（在写任何系统目录之前）：交互问一行，回车用默认
   `/run/netns/ns-vpp`（升级取已装单元正在用的值，已装对端时跟随它），输 `no` 留在
   host 网络，非交互落默认。选的值必须与目标机上已装的 `g3icap.service` 一致，且路径
   在目标机必须已经存在，不满足就失败退出，并给出出路（重装选同一个命名空间 /
   `systemctl edit` 现场改 / 退回 host）。理由见第 1 节：
   装在两个命名空间里表面正常，审计与取证书静默丢掉，比装不上难查得多；
3. `bin/*` 装到 `/opt/zf/g3/bin`（0755），`README.md`/`VERSION` 落到 `/opt/zf/g3/`；
4. 配置装到 `/opt/zf/g3/conf`（`g3proxy.yaml`、`g3fcgen.yaml`、随包的 CA）。**首次安装**
   （目标机上还没有 `g3proxy.yaml`）会问一行"g3proxy 监听端口 [3128]："：直接回车或输入
   空行用默认，填别的数字则写进刚装好的 `g3proxy.yaml`，非法输入会重问；非交互执行
   （stdin 到 EOF）自动落默认值。已有配置时不询问，端口以现网文件为准，改端口直接编辑
   `/opt/zf/g3/conf/g3proxy.yaml` 再重启；
5. 用 `/opt/zf/g3/bin/g3proxy -t -c /opt/zf/g3/conf/g3proxy.yaml` 校验配置，**失败就不装单元、不启服务**；
6. 单元里的 `@NETNS@` 展开成安装时选的命名空间，`sed` 渲染 `@PREFIX@`/`@CONTROL_DIR@`/`@GROUP@`，写到 `/etc/systemd/system/`，`daemon-reload`；
7. 把 `uninstall.sh` 复制到 `/opt/zf/g3/uninstall.sh`；
8. `systemctl enable --now g3fcgen`（失败即整体失败退出），再 `enable --now g3proxy`；
9. 进了命名空间时，`nsenter` 探一次 ns 内的 `127.0.0.1:2999` 与 `:1344` 并打印结果（只提示，
   不影响退出码）；目标机上没有 `g3icap.service` 时提醒一句 ICAP 在另一个包里。

ICAP 包（`sudo ./g3icap-<...>.run`）是同一套流程的裁剪版：先做对称的命名空间检查
（与目标机上已装的 `g3proxy`/`g3fcgen` 比对，对端还没装只提示不拦），然后装
`bin/g3icap` 到 `/opt/zf/icap`、渲染 `g3icap.service`、复制 `uninstall.sh`、
`systemctl enable --now g3icap`（失败即退出，提示去看 `journalctl -u g3icap`）。它没有
配置目录，也没有 CA。两个包谁先装都行，后装的那一个负责把不一致拦下来。

**配置文件绝不覆盖。** 目标机上已有的配置（含 CA）一律保持原样：内容相同打一行
"配置未变化"，内容不同把新内容写成同名的 `*.new`，由操作者自己比对合并。这是升级时
的回滚依据（见第 6 节）。

## 4. 服务形态

`g3proxy.service` 关键项：

```
Type=exec
NetworkNamespacePath=/run/netns/ns-vpp  # 安装时展开，选 no 时这两行不存在
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
`RestartPreventExitStatus=255`，第 9 行也是 `@NETNS@`——它跟 g3proxy 进同一个命名空间，
`127.0.0.1:2999` 才在 g3proxy 那一侧可达。

`g3icap.service`（另一个包）形状与 g3fcgen 一致：`Type=exec`、第 9 行同一个 `@NETNS@`、
`ExecStop=/bin/kill -INT $MAINPID`，启动命令是

```
ExecStart=@PREFIX@/bin/g3icap --listen 127.0.0.1:1344
```

`--listen` 写在单元里而不是配置文件里，要换地址/端口就 `systemctl edit g3icap` 覆盖这一行；
`--service`（注册给 OPTIONS 的服务名，默认 `echo,reqmod,respmod,icap_audit`）与
`--max-body-print`（送审正文打印上限，默认 512 字节）同样可以在这里改。服务名两边要对齐：
随包配置与仓库里 `etc/g3proxy/http/auditor.d/default.yaml`、
`etc/g3proxy/ftp/auditor.d/ftp_auditor.yaml` 都送 `/icap_audit`，`g3icap` 默认注册列表是
`icap_audit,echo,reqmod,respmod`——`echo` 等留着当别名，因为升级从不覆盖现网
`g3proxy.yaml`，老配置指向 `/echo` 也照样接得住。接真实 ICAP 设备时按设备暴露的服务名改
`icap_reqmod_service` 即可。

`NetworkNamespacePath=` 需要 systemd ≥ 246；命名空间必须已经存在（`ip netns list` 能看见），
systemd 不会代你创建。三个单元由同一个 `@NETNS@` 机制展开，每个包只渲染自己那几个单元，
所以两个包安装时要各选一次同一个命名空间（都输 no 就都留在 host）；三个服务都留在 host 时回环依赖天然可达，
但也就和 vpp 那侧的转发不在一起了。

## 5. 日常操作

```sh
systemctl status g3proxy g3fcgen
journalctl -u g3proxy -u g3fcgen -f
systemctl reload g3proxy          # 不停机重载（server/auditor/resolver/escaper/user-group）
systemctl restart g3proxy         # 整份配置重载
sudo /opt/zf/g3/uninstall.sh      # 停服务、摘单元，并删除 /opt/zf/g3
```

装了 ICAP 包的话，另加三条：

```sh
systemctl status g3icap
journalctl -u g3icap -f           # 每笔送审的 ICAP 请求行、头部、正文逐段打在这里
sudo /opt/zf/icap/uninstall.sh    # 只停 g3icap、摘它的单元、删 /opt/zf/icap，不碰 g3
sudo systemctl edit g3icap        # 覆盖 ExecStart 换 --listen / --service / --max-body-print
```

卸载停服务、摘 systemd 单元，最后**删除整个 `/opt/zf/g3`**——配置与 CA 一并清除，
确认没有唯一副本再跑（要留就先拷走 `conf/`）。包里那份 `uninstall.sh` 有守卫：在包
目录里执行时识别出 `install.sh` 同级，只摘单元、整包原样保留。两个包的卸载脚本各删各的，
卸 icap 不会动 g3 的单元与目录，反之也一样。

审计链路"一条都没收到"时，先确认三个服务在同一个命名空间，再看监听地址：

```sh
systemctl show -p NetworkNamespacePath g3proxy g3fcgen g3icap   # 三行应当一致
ss -lntp | grep -E '1344|2999'                                 # 监听在该命名空间的回环上
```

不想抓包、也不想只看 g3icap 那侧，可以让代理自己把送审的头部打出来：把 auditor 的
`icap_reqmod_service` 改成 map 形态，加 `log_audit_header: true`，再重载 auditor 即可。
它每送一条就打一条 `Bypass ICAP audit header (...)`——几十行一条：第一行是字节数，
接着是 ICAP 请求头，再是封装的 HTTP 请求头。正文一个字节不打，`X-TLS-*` 密钥行的值
屏蔽成 `***`。这条记录是 info 级，g3proxy 检测到开关打开会自动把库日志的级别门限放到
info，不用给进程加 `-v`：

```sh
journalctl -u g3proxy -f --grep 'Bypass ICAP audit header' -o cat
```

**别用 `journalctl | grep 'Bypass ICAP audit header'`**：管道按行过滤，一条记录只有第一行
带这个串，于是只剩那行字节数，看着像没打内容——内容其实完整进了 journal。systemd 老于
247（Kylin V10、RHEL8 那一档）没有 `--grep`，就自己带上下文：

```sh
journalctl -u g3proxy --since "-10min" | grep -A40 'Bypass ICAP audit header'
```

查完把开关关掉再 reload（关掉后这条本身不再打印；期间其他库的 info 日志会持续到
进程重启）。这条日志里带着完整的请求头（Cookie、Authorization 之类都在），
只适合排障时短期开。

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

两个包要一起升级时注意安装时选的命名空间别改：与已装的兄弟单元不一致，安装
脚本会在写系统目录之前拒装（这是设计如此，比装完再静默丢审计好）。升级默认取已装单元
正在用的命名空间，回车就不会把服务搬走；真要换命名空间，就两个包都选新值，或
`systemctl edit` 现场改。`VERSION` 里的 `component:` 行记录了这份包是给哪个组件的，
进哪个命名空间记在装好的单元的 `NetworkNamespacePath=` 里。

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
- 默认安装让 g3proxy、g3fcgen 进 `ns-vpp`，ICAP 包默认也进同一个：`g3proxy.yaml` 里写
  `127.0.0.1` 的 g3fcgen(2999) 与 ICAP(1344) 指的是 ns-vpp 的回环，不是 host 的。接现场
  自己的 ICAP 设备时不必装 `g3icap`，但那个设备必须在 ns-vpp 里可达——要么地址本来就跨得过去，
  要么把 `icap_reqmod_service` 改成能到达的地址（同理 `tls_cert_generator` 的
  `query_peer_addr`）。三个服务分处两个命名空间是最坑的一种：全都 running，审计一条不到。
- `g3fcgen.yaml` 里的 `myCA.crt`/`myCA.key` 是相对配置目录的路径。CA 由构建保证随包：
  `deploy/conf/` 有成套就用它，没有则 `g3mkcert` 自动生成（正式环境发布前换成自己的再打包）。
  仓库里的测试私钥不外发；带 CA 的 `.run` 本身就是敏感物，分发必须走受控渠道。

## 8. 安全说明

- 单元没有做 `User=` 之类的沙箱收敛，服务以 root 运行——g3proxy 需要绑定监听
  端口并写 `/run/g3`，若要降权请自行加 `User=`/`AmbientCapabilities=` 并验证。默认的
  `NetworkNamespacePath=` 只是把进程搬进 vpp 那侧已经存在的网络命名空间（systemd 需要
  `CAP_SYS_ADMIN`，root 服务本就有），`PrivateNetwork=no` 表示没有做网络隔离，不是安全加固；
  要完全关掉就在安装选命名空间时输 `no`。
- **`g3icap` 会把送审内容打进日志**：每笔 ICAP 请求的请求行、头部和正文（默认截到 512 字节）
  都进 journald。它是排障/打通链路用的，不是审计留痕系统——要长期存审计数据请接真实 ICAP
  服务或把日志按敏感级别保管。`--max-body-print=0` 不打印正文字节（正文长度那行仍会打）。
- **`log_audit_header` 打开时，g3proxy 这侧也会把送审头部写进 journald**：里面是客户端原始
  请求头，Cookie、Authorization 这类凭据头都在，正文字节与 `X-TLS-*` 密钥行不会被打（密钥值
  统一屏蔽成 `***`）。默认关闭，排障用完就关；开启期间的日志要按敏感级别保管。
- 带 CA 的 `.run` 含私钥：临时目录 0700、退出即删，但**文件本身的保管与分发要按私钥的
  级别来**。`deploy/conf/myCA.*` 已进 `.gitignore`，不要把私钥提交进仓库。
- `uninstall.sh` 会 `rm -rf` 整个安装目录 `/opt/zf/g3`，配置与 CA 全在里面，执行前确认
  没有唯一副本。icap 包那份删 `/opt/zf/icap`，只摘 `g3icap.service`，不碰 g3 的任何东西。
- 安装/卸载脚本只在目标机本地读写，不联网、不外发任何数据。

## 9. 设计与跟踪

- 设计（含方案取舍与遗留待决策项）：`docs/superpowers/specs/2026-11-02-g3-run-package-deploy-design.md`
- 实施与验证清单：`docs/superpowers/plans/2026-11-02-g3-run-package-deploy.md`
- ICAP 包与三服务同命名空间的设计：`docs/superpowers/specs/2026-11-04-g3-icap-package-netns-design.md`
