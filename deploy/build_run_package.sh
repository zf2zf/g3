#!/bin/sh
#
# 编译并打一个 g3 "run 包"：可执行程序 + 配置 + systemd 单元 + 安装/卸载脚本，
# 产物是 dist/ 下的一个目录、同名 tar.gz，和一个可直接执行的自解压 .run，
# 部署目标是 /opt/zf/g3。
#
# 目标机部署就一条命令：
#   sudo ./g3-run-xxx.run      # 装 g3proxy 与 g3fcgen 两个服务，起不来则整装失败
#   sudo /opt/zf/g3/uninstall.sh   # 卸载（停服务、摘单元、删除 /opt/zf/g3）
#
# 重要：run 包里的二进制是按"打包这台机器"的动态库链接的（OpenSSL、c-ares、
# Lua、Python），请在与目标机同 OS/同架构的机器上执行本脚本。目标机是别的发行版，就加
# --portable / --static 裁剪（见下面"跨发行版"一段）。
#
# g3fcgen 是必须的服务（auditor 的 tls_cert_generator 运行时向它取 MITM 证书），
# 包里必须带 CA：deploy/conf 下有成套 myCA.crt/myCA.key 就直接打进包；没有则
# 构建时自动用 g3mkcert 生成一份自签根 CA 写回 deploy/conf（下次复用，已 gitignore）。
# 正式环境请换成自己的 CA 再打包（带 CA 的 .run 按私钥级别分发）。
#
# 用法（--参数 覆盖同名环境变量，环境变量只留作兼容与测试后门）：
#   deploy/build_run_package.sh
#   deploy/build_run_package.sh --profile=debug             # 排障用的调试包
#   deploy/build_run_package.sh --target=x86_64-unknown-linux-musl   # 交叉编译
#   deploy/build_run_package.sh --bins="g3proxy g3proxy-ctl"         # 精简程序集
#   deploy/build_run_package.sh --features=vendored-openssl          # 追加 cargo feature
#   deploy/build_run_package.sh --portable              # 跨发行版：去 Lua/Python，内置 OpenSSL/c-ares
#   deploy/build_run_package.sh --static                # 在 --portable 之上再把 glibc 静态进去
#   deploy/build_run_package.sh --netns=no                  # g3proxy 不进网络命名空间
#   deploy/build_run_package.sh --netns=/run/netns/ns-other # 换命名空间（默认 ns-vpp）
#
# g3proxy 默认装进网络命名空间（--netns 的路径值，默认 /run/netns/ns-vpp）：跑在 VPP 那边
# 的网络栈里，监听地址与回环都是该命名空间的。g3fcgen 与 ICAP 服务不进——
# 生效后进的 127.0.0.1 是 ns-vpp 的回环，g3proxy.yaml 里走回环的 g3fcgen(2999)
# 与 ICAP(1344) 必须在里面可达，否则 TLS 拦截与审计取不到东西。
#
# 目标机与构建机不是同一套系统，就加一个裁剪开关，别在目标机凑库：
#   deploy/build_run_package.sh --portable    # 去 Lua/Python，OpenSSL 与 c-ares 内置编译
#   deploy/build_run_package.sh --static      # 在 --portable 之上把 glibc 也静态进去
# --portable 只解决"缺 .so"。目标机 glibc 比构建机老（Kylin V10、RHEL8 那一档，装完报
# version 'GLIBC_2.34' not found）必须用 --static：开关自己补
# RUSTFLAGS=-C target-feature=+crt-static 与 --target=<构建机三元组>，包内自检照跑，
# 并额外验三个可执行程序确实不加载任何 .so。
# 两个开关都会关掉 cargo 的默认 feature（quic 与 TLS 后端由开关补回来），产物里就没有
# auth 的 type: lua / type: python 动态用户名来源——当前内联配置没有 auth，用不到。
# 详见 doc/deploy-run-package.md 的"feature 裁剪"一节。

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

# 打进 run 包的可执行程序，按需增删
RUN_BINS=${RUN_BINS:-"g3proxy g3proxy-ctl g3fcgen"}
# 需要一起编译的 workspace 包
BUILD_PACKAGES=${BUILD_PACKAGES:-"g3proxy g3proxy-ctl g3fcgen"}
# cargo 的构建 profile 与额外参数
PROFILE=${PROFILE:-release}
G3_BUILD_ARGS=${G3_BUILD_ARGS:-}
# 追加的 cargo feature（空格分隔）
EXTRA_FEATURES=${EXTRA_FEATURES:-}
# 目标三元组，留空表示用当前主机的默认 target
TARGET=${TARGET:-}
# 跨发行版裁剪：no=按构建机的库链接（默认）；portable=去 Lua/Python，OpenSSL 与 c-ares
# 内置编译；static=在 portable 之上把 glibc 也静态进去（目标机 glibc 比构建机老时用）
PORTABILITY=${PORTABILITY:-no}
# g3proxy 是否装进网络命名空间（yes/no），以及命名空间路径
NETNS=${NETNS:-yes}
NETNS_PATH=${NETNS_PATH:-/run/netns/ns-vpp}

DIST_DIR=${DIST_DIR:-"${PROJECT_DIR}/dist"}
# run 包内的配置来源：全部内联在 deploy/conf 的两份 yaml 里，
# server / auditor 不再有 server.d、auditor.d 子目录

usage() {
	# 打印 shebang 之后那段注释，不写死行号
	awk 'NR > 2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

# --参数=值 形式的配置，逐个覆盖上面从环境变量取来的默认值
while [ $# -gt 0 ]; do
	opt=$1
	case $opt in
	-h | --help)
		usage
		exit 0
		;;
	--profile=*)
		PROFILE=${opt#*=}
		;;
	--target=*)
		TARGET=${opt#*=}
		;;
	--bins=*)
		RUN_BINS=${opt#*=}
		BUILD_PACKAGES=${opt#*=}
		;;
	--packages=*)
		BUILD_PACKAGES=${opt#*=}
		;;
	--features=*)
		EXTRA_FEATURES=${opt#*=}
		;;
	--build-args=*)
		G3_BUILD_ARGS=${opt#*=}
		;;
	--dist-dir=*)
		DIST_DIR=${opt#*=}
		;;
	--netns=no)
		NETNS=no
		;;
	--netns=yes)
		NETNS=yes
		;;
	--netns=/*)
		NETNS=yes
		NETNS_PATH=${opt#--netns=}
		;;
	--portable)
		PORTABILITY=portable
		;;
	--static)
		PORTABILITY=static
		;;
	--portable=no | --static=no)
		PORTABILITY=no
		;;
	*)
		echo "未知参数：${opt}（用 -h 看用法）" >&2
		exit 1
		;;
	esac
	shift
done

cd "$PROJECT_DIR"

case "$PORTABILITY" in
no | portable | static) ;;
*)
	echo "PORTABILITY=${PORTABILITY} 不认，只能是 no / portable / static" >&2
	exit 1
	;;
esac

# c-ares：系统库太旧或缺失时退回内置编译，跟 scripts/package 的判定保持一致。
# 跨发行版的包不能碰构建机的 libcares.so.2，一律内置。
CARGO_FEATURES=""
if [ "$PORTABILITY" != no ]; then
	echo "c-ares: ${PORTABILITY} 包，强制内置编译（vendored-c-ares）"
	CARGO_FEATURES="vendored-c-ares"
elif pkg-config --atleast-version 1.18.0 libcares 2>/dev/null; then
	echo "c-ares: 使用系统库"
	CARGO_FEATURES="c-ares"
else
	echo "c-ares: 系统库不可用，改用内置编译（vendored-c-ares）"
	CARGO_FEATURES="vendored-c-ares"
fi
if [ -n "$EXTRA_FEATURES" ]; then
	CARGO_FEATURES="${CARGO_FEATURES} ${EXTRA_FEATURES}"
fi

# 跨发行版裁剪：默认 feature（lua54 + python + c-ares + quic + rustls-ring）整个关掉，
# 再补回 quic 与 TLS 后端，OpenSSL 交给内置编译。写全包名的那条是给 g3fcgen 的——
# 它一样链 OpenSSL，只裁 g3proxy 会给它留下 libssl.so.3。
if [ "$PORTABILITY" != no ]; then
	CARGO_FEATURES="${CARGO_FEATURES} quic rustls-ring vendored-openssl g3fcgen/vendored-openssl"
	case " ${G3_BUILD_ARGS} " in
	*" --no-default-features "*) ;;
	*) G3_BUILD_ARGS="${G3_BUILD_ARGS} --no-default-features" ;;
	esac
	echo "==> 跨发行版裁剪（${PORTABILITY}）：关默认 feature，OpenSSL/c-ares 内置编译"
	echo "    产物没有 Lua/Python 的用户认证模块（auth 里 type: lua / type: python 不可用）"
fi

# static：glibc 也静态进去，产物不加载任何 .so，也就不带 glibc 符号版本要求。
# 必须显式给 --target，cargo 才会把 RUSTFLAGS 只施加给目标工件——否则连 proc-macro 也吃
# +crt-static，cargo 直接报 "cannot produce proc-macro for ... does not support these
# crate types"（async-recursion、tokio-macros 都中招）。
if [ "$PORTABILITY" = static ]; then
	HOST_TARGET=$(rustc -Vv 2>/dev/null | sed -n 's/^host: //p')
	if [ -z "$HOST_TARGET" ]; then
		echo "拿不到 rustc 的 host 三元组，无法自动设 --target；请显式传 --target=<三元组>" >&2
		exit 1
	fi
	if [ -z "$TARGET" ]; then
		TARGET=$HOST_TARGET
	fi
	# --static 打的就是构建机自己这个三元组时产物仍然能跑，自检照做（见打包前自检一段）
	# shellcheck disable=SC2016
	RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static"
	export RUSTFLAGS
	echo "==> 静态链接 glibc：RUSTFLAGS=${RUSTFLAGS}，TARGET=${TARGET}"
fi

# feature 必须写成 包名/feature：一次 -p 多个包时，不存在的裸 feature 名会让
# cargo 直接报错（g3proxy-ctl 根本没有 feature）。默认都归到 g3proxy 上，
# 要改其他包的 feature 请自己写全名，例如 EXTRA_FEATURES="g3fcgen/vendored-openssl"
FEATURE_LIST=""
for feat in $CARGO_FEATURES; do
	case "$feat" in
	*/*) qualified=$feat ;;
	*) qualified="g3proxy/$feat" ;;
	esac
	if [ -z "$FEATURE_LIST" ]; then
		FEATURE_LIST=$qualified
	else
		FEATURE_LIST="$FEATURE_LIST,$qualified"
	fi
done

# Lua：g3proxy 默认 feature 带 lua54 与 python，缺这两套开发库时构建会失败，
# 具体怎么裁剪 feature 见 doc/deploy-run-package.md。裁剪模式下默认 feature 已经关了，不用提示。
LUA_OK=0
for mod in lua lua55 lua54 lua53; do
	if pkg-config --exists "$mod" 2>/dev/null; then
		LUA_OK=1
		break
	fi
done
if [ "$LUA_OK" = 0 ] && [ "$PORTABILITY" = no ]; then
	echo "提示：未找到 Lua 开发库，g3proxy 默认 feature 里的 lua54 可能编不过" >&2
fi

# cargo 参数（debug profile 的名字在 cargo 里叫 dev，产物目录仍是 target/debug）
set -- build
case "$PROFILE" in
release)
	set -- "$@" --release
	;;
debug) ;;
*)
	set -- "$@" --profile "$PROFILE"
	;;
esac
for pkg in $BUILD_PACKAGES; do
	set -- "$@" -p "$pkg"
done
set -- "$@" --features "$FEATURE_LIST"
if [ -n "$TARGET" ]; then
	set -- "$@" --target "$TARGET"
fi

BIN_DIR="$PROJECT_DIR/target"
if [ -n "$TARGET" ]; then
	BIN_DIR="$BIN_DIR/$TARGET"
fi
BIN_DIR="$BIN_DIR/$PROFILE"

echo "==> cargo $* ${G3_BUILD_ARGS:+$G3_BUILD_ARGS}"
# G3_BUILD_ARGS 是给操作者的逃生口（例如 "--offline"），不做引号处理
# shellcheck disable=SC2086
cargo "$@" $G3_BUILD_ARGS

VERSION=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$PROJECT_DIR/g3proxy/Cargo.toml" | head -1)
GIT_SHA=$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCH=$(uname -s | tr 'A-Z' 'a-z')-$(uname -m)
BUILT_AT=$(date -u +%Y%m%d)
PKG_NAME="g3-run-${VERSION}-${GIT_SHA}-${ARCH}-${BUILT_AT}"
PKG_DIR="$DIST_DIR/$PKG_NAME"

echo "==> 组装 run 包：$PKG_DIR"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/bin" "$PKG_DIR/conf" "$PKG_DIR/systemd"

for bin in $RUN_BINS; do
	if [ ! -f "$BIN_DIR/$bin" ]; then
		echo "找不到可执行程序 $BIN_DIR/$bin，请检查 RUN_BINS / BUILD_PACKAGES 设置" >&2
		exit 1
	fi
	cp "$BIN_DIR/$bin" "$PKG_DIR/bin/$bin"
	chmod 0755 "$PKG_DIR/bin/$bin"
done

cp "$PROJECT_DIR/deploy/conf/g3proxy.yaml" "$PKG_DIR/conf/g3proxy.yaml"
cp "$PROJECT_DIR/deploy/conf/g3fcgen.yaml" "$PKG_DIR/conf/g3fcgen.yaml"

# CA：g3fcgen 起来的前提，包里永远带一套。deploy/conf 下已有就直接用；
# 没有则用 g3mkcert 现生成一份自签根 CA 写回 deploy/conf（下次打包复用）。
# 只有一半视为操作者放错，直接报错——不拆散半套 CA。
CA_DIR="$PROJECT_DIR/deploy/conf"
if [ -e "$CA_DIR/myCA.crt" ] || [ -e "$CA_DIR/myCA.key" ]; then
	if [ ! -e "$CA_DIR/myCA.crt" ] || [ ! -e "$CA_DIR/myCA.key" ]; then
		echo "deploy/conf 下 myCA.crt 与 myCA.key 必须成对存在" >&2
		exit 1
	fi
	echo "==> 使用 deploy/conf 下已有的 CA"
else
	MKCERT="$BIN_DIR/g3mkcert"
	if [ ! -x "$MKCERT" ]; then
		echo "==> 编译 g3mkcert（用于生成 CA）"
		set -- build -p g3mkcert
		case "$PROFILE" in
		release) set -- "$@" --release ;;
		debug) ;;
		*) set -- "$@" --profile "$PROFILE" ;;
		esac
		if [ -n "$TARGET" ]; then
			set -- "$@" --target "$TARGET"
		fi
		# shellcheck disable=SC2086
		cargo "$@" $G3_BUILD_ARGS
	fi
	echo "==> deploy/conf 无 CA，自动生成自签根 CA（RSA 2048，写回 deploy/conf 供复用）"
	if ! "$MKCERT" --root --rsa 2048 \
		--organization "g3" --common-name "g3 MITM Root CA" \
		--output-cert "$CA_DIR/myCA.crt" --output-key "$CA_DIR/myCA.key"; then
		echo "CA 自动生成失败：交叉编译时 g3mkcert 可能不能在构建机运行，" >&2
		echo "请先在同架构机器生成 myCA.crt/myCA.key 放入 deploy/conf 再打包" >&2
		exit 1
	fi
fi
cp "$CA_DIR/myCA.crt" "$PKG_DIR/conf/myCA.crt"
cp "$CA_DIR/myCA.key" "$PKG_DIR/conf/myCA.key"
chmod 0600 "$PKG_DIR/conf/myCA.key"

# 单元模板里的 @NETNS@ 在这里就展开：进包的 g3proxy.service 是成品，install.sh 只
# 替换 @PREFIX@/@CONTROL_DIR@/@GROUP@ 这些目标机才知道的路径。
case "$NETNS" in
no | false | off | 0 | n)
	NETNS_LINES=""
	NETNS_NOTE="off（NETNS=${NETNS}，g3proxy 留在 host 网络）"
	;;
*)
	# systemd 只认绝对路径，且指令行开头不能留空白（会被当成上一行的续行）
	if [ "${NETNS_PATH#/}" = "$NETNS_PATH" ]; then
		echo "NETNS_PATH=${NETNS_PATH} 不是绝对路径（应为 /run/netns/<名字>），或者用 NETNS=no 关掉" >&2
		exit 1
	fi
	NETNS_LINES=$(printf '# 进程搬进 vpp 侧已建好的网络命名空间；PrivateNetwork=no 是 systemd 默认值，\n# 写出来只是表明这里不做网络隔离。生效后 127.0.0.1 是该命名空间的回环，\n# g3proxy.yaml 里的 g3fcgen(2999) 与 ICAP(1344) 必须在里面可达。\nNetworkNamespacePath=%s\nPrivateNetwork=no' "$NETNS_PATH")
	NETNS_NOTE="${NETNS_PATH}（只有 g3proxy 进入，g3fcgen 与 ICAP 留在 host）"
	;;
esac
echo "==> g3proxy 网络命名空间：${NETNS_NOTE}"

render_systemd_unit() {
	# @NETNS@ 单独占一行：开启时展开成指令，关闭时整行删掉，不留空行
	awk -v netns="$NETNS_LINES" '
		$0 == "@NETNS@" {
			if (netns != "") printf "%s\n", netns
			next
		}
		{ print }
	' "$1" > "$2"
}

render_systemd_unit "$PROJECT_DIR/deploy/systemd/g3proxy.service" "$PKG_DIR/systemd/g3proxy.service"
if [ -n "$NETNS_LINES" ]; then
	README_NETNS=$(printf 'g3proxy 跑在网络命名空间 %s 里（这两行指令在打包时展开进单元，g3fcgen 仍在 host）。\n所以 127.0.0.1 是这个命名空间自己的回环：g3proxy.yaml 里指向 127.0.0.1 的 g3fcgen(2999)\n与 ICAP(1344) 必须在 %s 里可达，否则 TLS 拦截取不到证书、审计也发不出去。\n想退回 host 网络：现场用 systemctl edit g3proxy 写一条空的 NetworkNamespacePath= 再\nrestart；或在构建机 NETNS=no 重新打包。' "$NETNS_PATH" "$NETNS_PATH")
else
	README_NETNS='本次打包未启用网络命名空间（NETNS=no），g3proxy 与 g3fcgen 都在 host 网络里。
要进 ns 的话在构建机用默认值 NETNS=yes（可配 NETNS_PATH=/run/netns/<名字>）重新打包。'
fi

# 包是什么来路，写进 README 与 VERSION：装到目标机的人只看得到这两份
case "$PORTABILITY" in
no)
	FEATURE_NOTE="默认 feature 之外额外启用了：${CARGO_FEATURES}。"
	DEFAULTS_STATE=enabled
	README_PORTABILITY='这个包按构建机的动态库链接（Lua/Python/OpenSSL/c-ares 用的都是构建机上的 .so），
换台不同发行版的机器就可能起不来：先是 error while loading shared libraries 报缺库，补齐库
还可能撞 glibc 符号版本（GLIBC_2.34 not found）。目标机不是同一套系统就在构建机重打：加
--portable 裁掉 Lua/Python 并内置 OpenSSL/c-ares；目标机 glibc 比构建机老再加 --static。'
	;;
portable)
	FEATURE_NOTE="已关闭 cargo 默认 feature，实际启用：${CARGO_FEATURES}。"
	DEFAULTS_STATE="disabled (${PORTABILITY})"
	README_PORTABILITY='这个包是 --portable 包：OpenSSL 与 c-ares 静态进二进制，运行时只剩 glibc 那套；
没有 Lua/Python 的用户认证模块（auth 里 type: lua / type: python 不可用）。目标机的 glibc
不能低于构建机，否则装完会报 GLIBC_x.y not found——那种机器要改用 --static 重打。'
	;;
static)
	FEATURE_NOTE="已关闭 cargo 默认 feature，实际启用：${CARGO_FEATURES}，glibc 同样静态链接。"
	DEFAULTS_STATE="disabled (static)"
	README_PORTABILITY='这个包是 --static 包：三个可执行程序都不加载任何 .so（ldd 显示 statically linked），
对目标机的 glibc 版本没有要求，可以装在与构建机不同发行版、glibc 更老的机器上（Kylin V10、
RHEL8 那一档）。没有 Lua/Python 的用户认证模块（auth 里 type: lua / type: python 不可用）。
静态 glibc 用不了 NSS 那套域名解析，本项目解析走 c-ares / hickory 自己发 UDP，不受影响。'
	;;
esac

cp "$PROJECT_DIR/deploy/systemd/g3fcgen.service" "$PKG_DIR/systemd/"
cp "$PROJECT_DIR/deploy/install.sh" "$PKG_DIR/install.sh"
cp "$PROJECT_DIR/deploy/uninstall.sh" "$PKG_DIR/uninstall.sh"
chmod 0755 "$PKG_DIR/install.sh" "$PKG_DIR/uninstall.sh"

# 目标机上唯一能看到的说明，装完会一起落到 ${PREFIX}/README.md
cat > "$PKG_DIR/README.md" << EOF
# g3 run 包 ${PKG_NAME}

g3proxy 版本 ${VERSION}，git ${GIT_SHA}，构建于 $(uname -s) $(uname -m)（profile: ${PROFILE}）。
${FEATURE_NOTE}详见 VERSION 文件。

${README_PORTABILITY}

## 部署

在构建机上把 ${PKG_NAME}.run 拷到目标机，一条命令装完：

    sudo ./${PKG_NAME}.run

程序与配置统一落在 /opt/zf/g3：bin 放可执行程序，conf 放配置（已存在的配置绝不覆盖，
新内容写成同名 .new 文件）。首次安装会问一行"g3proxy 监听端口"，直接回车用默认 10087，
也可以现场填别的端口；升级时已有 g3proxy.yaml 则不再询问，端口以现网文件为准。
g3proxy（默认 10087 代理）与 g3fcgen（MITM 证书签发，g3proxy 的 TLS 拦截依赖它）都注册为
systemd 服务并立即启动。控制套接字在 /run/g3，由 systemd 创建。

CA（myCA.crt/myCA.key）随包安装到 /opt/zf/g3/conf——构建时 deploy/conf 没有成套 CA
的话，这份是 g3mkcert 自动生成的自签根，正式环境请换成自己的 CA 重新打包。

## 网络命名空间

${README_NETNS}

## 日常操作

    systemctl status g3proxy g3fcgen
    journalctl -u g3proxy -u g3fcgen -f    # 配置里 log: stdout，日志进 journald
    systemctl reload g3proxy                # 改完配置做不停机重载
    sudo /opt/zf/g3/uninstall.sh            # 停服务、摘单元，并删除 /opt/zf/g3（含配置与 CA，先备份）

配置全部内联在 /opt/zf/g3/conf/g3proxy.yaml（server、auditor 都在这一个文件里），
改端口、ICAP 审计地址、拦截开关都只动它；改完 systemctl reload g3proxy 生效。

## 校验与排查

    /opt/zf/g3/bin/g3proxy -t -c /opt/zf/g3/conf/g3proxy.yaml   # 只校验配置
    /opt/zf/g3/bin/g3proxy --version

配置不合法时进程以 255 退出，systemd 不会反复重启它（RestartPreventExitStatus=255），
journal 里会留完整报错。
EOF

cat > "$PKG_DIR/VERSION" << EOF
package: ${PKG_NAME}
g3proxy version: ${VERSION}
git commit: ${GIT_SHA}
build host: $(uname -s) $(uname -m)
build profile: ${PROFILE}
cargo target: ${TARGET:-default}
built at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
cargo features: ${CARGO_FEATURES}
default features: ${DEFAULTS_STATE}
rustflags (build env): ${RUSTFLAGS:-none}
portability: ${PORTABILITY}
ca bundled: yes (from deploy/conf, auto-generated at build if absent)
network namespace (g3proxy only): ${NETNS_NOTE}
EOF

# 打包前自检：用包里这份二进制去加载包里这份配置。
# 真交叉编译（TARGET 与构建机三元组不同）时跳过——产物在构建机上跑不起来；
# --static 补出来的 TARGET 就是构建机自己的三元组，自检照跑。
if [ -z "$TARGET" ] || [ "$TARGET" = "${HOST_TARGET:-}" ]; then
	echo "==> 自检：g3proxy -t -c conf/g3proxy.yaml"
	if ! "$PKG_DIR/bin/g3proxy" -t -c "$PKG_DIR/conf/g3proxy.yaml"; then
		echo "包内配置自检失败，已保留 $PKG_DIR 供排查" >&2
		exit 1
	fi
else
	echo "==> 跳过配置自检（TARGET=${TARGET} 不是构建机三元组 ${HOST_TARGET:-未知}，产物跑不起来）"
fi

# --static 的核心承诺就是"不加载任何 .so"，检不掉就等于这个包白打，直接在构建机上拦掉
if [ "$PORTABILITY" = static ]; then
	echo "==> 自检：静态链接"
	for bin in $RUN_BINS; do
		path="$PKG_DIR/bin/$bin"
		if ! ldd "$path" 2>&1 | grep -q 'statically linked'; then
			echo "${bin} 不是静态链接：$(ldd "$path" 2>&1 | head -1)" >&2
			echo "多半是 RUSTFLAGS 被别处覆盖了（-h 里有 --static 实际用的值）" >&2
			exit 1
		fi
		if command -v objdump >/dev/null 2>&1; then
			syms=$(objdump -T "$path" 2>/dev/null | grep -c 'GLIBC_' || true)
			if [ "$syms" != 0 ]; then
				echo "${bin} 还带 ${syms} 个 GLIBC 符号版本要求，老 glibc 的目标机照样装不上" >&2
				exit 1
			fi
		fi
		echo "  ${bin}: statically linked，无 GLIBC 版本要求"
	done
fi

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/$PKG_NAME.tar.gz" "$DIST_DIR/$PKG_NAME.run"
# 包内路径统一以 ${PKG_NAME}/ 开头，解包后就是 install.sh 期望的目录结构
(cd "$DIST_DIR" && tar czf "$PKG_NAME.tar.gz" "$PKG_NAME")

# 自解压 .run：头部脚本按行号取尾部 payload（tar.gz）解到临时目录，
# 调用包内 install.sh；退出时删除临时目录（里面可能有 CA 私钥）。
RUN_HEADER=$(mktemp)
cat > "$RUN_HEADER" << 'EOF'
#!/bin/sh
#
# g3 run 包自解压安装器：把尾部的程序+配置+单元解到临时目录（用完即删），
# 执行包内固定安装流程。不带任何命令行参数——装 /opt/zf/g3、起 g3proxy 与
# g3fcgen；卸载用 sudo /opt/zf/g3/uninstall.sh。

set -eu

PKG_NAME="@PKG_NAME@"
PAYLOAD_LINE=@PAYLOAD_LINE@

if [ "$#" -gt 0 ]; then
	echo "这个 .run 不接受参数：sudo \"$0\" 即按默认方式安装（/opt/zf/g3，g3proxy+g3fcgen）" >&2
	exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
	echo "目标机没有 tar，无法解开安装负载" >&2
	exit 1
fi

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/g3-run.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

tail -n +"$PAYLOAD_LINE" "$0" | tar xzf - -C "$TMP_DIR"
"$TMP_DIR/$PKG_NAME/install.sh"
# 必须在读到尾部二进制负载之前退出：shell 是逐命令读取的，exit 之后才不会再往下取行
exit $?
EOF

# 替换占位符只动行内容不动行数，所以 payload 起始行号可以在写死进头部之前一次算定
PAYLOAD_START=$(awk 'END { print NR + 1 }' "$RUN_HEADER")
sed -e "s/@PKG_NAME@/${PKG_NAME}/" -e "s/@PAYLOAD_LINE@/${PAYLOAD_START}/" \
	"$RUN_HEADER" > "$DIST_DIR/$PKG_NAME.run"
rm -f "$RUN_HEADER"
# 校验必须在追加载荷之前做：sh -n 会把整个文件当脚本解析，尾部 tar 数据必然报错
sh -n "$DIST_DIR/$PKG_NAME.run" || { echo ".run 头部语法有问题" >&2; exit 1; }
cat "$DIST_DIR/$PKG_NAME.tar.gz" >> "$DIST_DIR/$PKG_NAME.run"
chmod 0755 "$DIST_DIR/$PKG_NAME.run"

echo
echo "run 包已生成："
echo "  安装器 $DIST_DIR/$PKG_NAME.run"
echo "  归档   $DIST_DIR/$PKG_NAME.tar.gz（与 .run 内容相同，供不方便跑安装器的场合手动解包）"
echo "  目录   $PKG_DIR"
echo
echo "下一步：把 .run 拷到目标机，执行"
echo "  sudo ./$PKG_NAME.run"
