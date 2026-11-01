#!/bin/sh
#
# 编译并打一个 g3 "run 包"：可执行程序 + 配置目录 + systemd 单元 + 安装脚本，
# 产物是 dist/ 下的一个目录和同名 tar.gz，部署目标是 /opt/zf/g3。
#
# 重要：run 包里的二进制是按"打包这台机器"的动态库链接的（OpenSSL、c-ares、
# Lua、Python），请在与目标机同 OS/同架构的机器上执行本脚本。
#
# 用法：
#   deploy/build_run_package.sh
#   PROFILE=debug deploy/build_run_package.sh            # 排障用的调试包
#   TARGET=x86_64-unknown-linux-musl deploy/build_run_package.sh   # 交叉编译
#   RUN_BINS="g3proxy g3proxy-ctl" deploy/build_run_package.sh     # 精简程序集
#   EXTRA_FEATURES=vendored-openssl deploy/build_run_package.sh    # 追加 cargo feature

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

DIST_DIR=${DIST_DIR:-"${PROJECT_DIR}/dist"}
# run 包内的配置来源：入口配置与 g3fcgen 模板在 deploy/conf，
# server.d / auditor.d 直接复用 etc/g3proxy/http，避免两处配置各写一份
CONF_DIR=${CONF_DIR:-"${PROJECT_DIR}/etc/g3proxy/http"}
CONF_SUBDIRS=${CONF_SUBDIRS:-"server.d auditor.d"}

usage() {
	# 打印 shebang 之后那段注释，不写死行号
	awk 'NR > 2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
"") ;;
*)
	echo "未知参数：${1}（用 -h 看用法）" >&2
	exit 1
	;;
esac

cd "$PROJECT_DIR"

# c-ares：系统库太旧或缺失时退回内置编译，跟 scripts/package 的判定保持一致
CARGO_FEATURES=""
if pkg-config --atleast-version 1.18.0 libcares 2>/dev/null; then
	echo "c-ares: 使用系统库"
	CARGO_FEATURES="c-ares"
else
	echo "c-ares: 系统库不可用，改用内置编译（vendored-c-ares）"
	CARGO_FEATURES="vendored-c-ares"
fi
if [ -n "$EXTRA_FEATURES" ]; then
	CARGO_FEATURES="${CARGO_FEATURES} ${EXTRA_FEATURES}"
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
# 具体怎么裁剪 feature 见 doc/deploy-run-package.md
LUA_OK=0
for mod in lua lua55 lua54 lua53; do
	if pkg-config --exists "$mod" 2>/dev/null; then
		LUA_OK=1
		break
	fi
done
if [ "$LUA_OK" = 0 ]; then
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
for sub in $CONF_SUBDIRS; do
	if [ ! -d "$CONF_DIR/$sub" ]; then
		echo "配置目录缺失：$CONF_DIR/$sub" >&2
		exit 1
	fi
	mkdir -p "$PKG_DIR/conf/$sub"
	cp "$CONF_DIR/$sub"/*.yaml "$PKG_DIR/conf/$sub/"
done

cp "$PROJECT_DIR/deploy/systemd/g3proxy.service" "$PKG_DIR/systemd/"
cp "$PROJECT_DIR/deploy/systemd/g3fcgen.service" "$PKG_DIR/systemd/"
cp "$PROJECT_DIR/deploy/install.sh" "$PKG_DIR/install.sh"
chmod 0755 "$PKG_DIR/install.sh"

# 目标机上唯一能看到的说明，装完会一起落到 ${PREFIX}/README.md
cat > "$PKG_DIR/README.md" << EOF
# g3 run 包 ${PKG_NAME}

g3proxy 版本 ${VERSION}，git ${GIT_SHA}，构建于 $(uname -s) $(uname -m)（profile: ${PROFILE}）。
默认 feature 之外额外启用了：${CARGO_FEATURES}。详见 VERSION 文件。

## 部署

    tar xzf ${PKG_NAME}.tar.gz
    cd ${PKG_NAME}
    sudo ./install.sh              # 装 g3proxy
    sudo ./install.sh --with-fcgen # 顺带装 MITM 证书签发服务 g3fcgen

程序与配置统一落在 /opt/zf/g3：bin 放可执行程序，conf 放配置（已存在的配置绝不覆盖，
新内容写成同名 .new 文件）。控制套接字在 /run/g3，由 systemd 创建。

## 日常操作

    systemctl status g3proxy
    journalctl -u g3proxy -f            # 配置里 log: stdout，日志进 journald
    systemctl reload g3proxy            # 改完配置做不停机重载
    systemctl restart g3proxy           # 整份配置重载
    sudo ./install.sh uninstall         # 停服务、摘单元，保留 /opt/zf/g3

改配置前先确认目录是否齐全：入口配置引用的 server.d、auditor.d 必须与 g3proxy.yaml
同级；要启用 resolver.d 或 escaper.d，先建目录再打开配置里对应的行。

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
extra features (on top of g3proxy defaults): ${CARGO_FEATURES}
EOF

# 打包前自检：用包里这份二进制去加载包里这份配置。
# 交叉编译（TARGET 非空）时跳过，因为产物不能在构建机上运行。
if [ -z "$TARGET" ]; then
	echo "==> 自检：g3proxy -t -c conf/g3proxy.yaml"
	if ! "$PKG_DIR/bin/g3proxy" -t -c "$PKG_DIR/conf/g3proxy.yaml"; then
		echo "包内配置自检失败，已保留 $PKG_DIR 供排查" >&2
		exit 1
	fi
else
	echo "==> 跳过自检（TARGET=${TARGET}，产物不能在构建机运行）"
fi

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/$PKG_NAME.tar.gz"
# 包内路径统一以 ${PKG_NAME}/ 开头，解包后就是 install.sh 期望的目录结构
(cd "$DIST_DIR" && tar czf "$PKG_NAME.tar.gz" "$PKG_NAME")

echo
echo "run 包已生成："
echo "  目录  $PKG_DIR"
echo "  归档  $DIST_DIR/$PKG_NAME.tar.gz"
echo
echo "下一步：把归档拷到目标机，解包后执行"
echo "  tar xzf $PKG_NAME.tar.gz && cd $PKG_NAME && sudo ./install.sh"
