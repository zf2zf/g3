#!/bin/sh
#
# 把 run 包装到目标机：可执行程序与配置统一落在 /opt/zf/g3，服务用 systemd 托管。
# 请在解包后的 run 包目录里执行本脚本（它按相对路径找 bin/ conf/ systemd/）。
#
# 用法：
#   sudo ./install.sh                    # 安装并启动 g3proxy
#   sudo ./install.sh --with-fcgen       # 同时安装 g3fcgen（MITM 证书签发）
#   sudo ./install.sh --prefix=/data/g3  # 换安装前缀
#   sudo ./install.sh uninstall          # 停服务、摘单元，保留配置和二进制
#   sudo ./install.sh uninstall --purge  # 连 /opt/zf/g3 一起删掉

set -eu

PREFIX=${PREFIX:-/opt/zf/g3}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
# 控制套接字目录由 systemd 的 RuntimeDirectory 创建，单位是 /run/g3、/run/g3fcgen
CONTROL_DIR=/run/g3
DAEMON_GROUP=g3
FCGEN_GROUP=g3fcgen

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

MODE=install
WITH_FCGEN=0
PURGE=0

usage() {
	# 打印 shebang 之后那段注释，不写死行号
	awk 'NR > 2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

while [ $# -gt 0 ]; do
	case "$1" in
	install)
		MODE=install
		;;
	uninstall)
		MODE=uninstall
		;;
	--prefix=*)
		PREFIX=${1#*=}
		;;
	--with-fcgen)
		WITH_FCGEN=1
		;;
	--purge)
		PURGE=1
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "未知参数：$1（用 -h 看用法）" >&2
		exit 1
		;;
	esac
	shift
done

check_package_layout() {
	for need in bin conf systemd install.sh; do
		if [ ! -e "$SCRIPT_DIR/$need" ]; then
			echo "看起来不在 run 包目录里：缺少 $SCRIPT_DIR/$need" >&2
			echo "请先执行 deploy/build_run_package.sh，再把生成的 tar.gz 拷到目标机解包" >&2
			exit 1
		fi
	done
}

# 装之前先确认待的是哪个包，再确认能不能写系统目录
if [ "$MODE" = install ]; then
	check_package_layout
fi

if [ "$(id -u)" != 0 ]; then
	echo "本脚本会写 ${PREFIX} 与 ${SYSTEMD_DIR}，请用 root 或 sudo 执行" >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "目标机没有 systemctl，本脚本只支持 systemd 托管的服务形态" >&2
	exit 1
fi

# 配置文件绝不覆盖：已存在就写成 *.new，由操作者自己比对合并
install_config_file() {
	src=$1
	dest=$2
	if [ -e "$dest" ]; then
		if cmp -s "$src" "$dest"; then
			echo "  配置未变化：$dest"
		else
			cp "$src" "$dest.new"
			echo "  配置有差异：新内容写到 $dest.new（原文件保持不变）"
		fi
	else
		cp "$src" "$dest"
		echo "  安装配置：$dest"
	fi
}

do_install() {
	if [ ! -x "$SCRIPT_DIR/bin/g3proxy" ]; then
		echo "包里没有可执行的 bin/g3proxy" >&2
		exit 1
	fi

	echo "==> 安装可执行程序到 ${PREFIX}/bin"
	mkdir -p "$PREFIX/bin"
	for bin in "$SCRIPT_DIR"/bin/*; do
		install -m 0755 "$bin" "$PREFIX/bin/$(basename "$bin")"
		echo "  $(basename "$bin")"
	done

	# 目标机上没有仓库可查，包里的说明直接放到安装前缀下，systemd 单元也指向它。
	# README 是文档不是配置，每次覆盖成当前版本的说明。
	if [ -f "$SCRIPT_DIR/README.md" ]; then
		install -m 0644 "$SCRIPT_DIR/README.md" "$PREFIX/README.md"
		echo "  $PREFIX/README.md"
	fi

	echo "==> 安装配置到 ${PREFIX}/conf"
	mkdir -p "$PREFIX/conf"
	install_config_file "$SCRIPT_DIR/conf/g3proxy.yaml" "$PREFIX/conf/g3proxy.yaml"
	for sub in "$SCRIPT_DIR"/conf/*/; do
		[ -d "$sub" ] || continue
		sub_name=$(basename "$sub")
		mkdir -p "$PREFIX/conf/$sub_name"
		for f in "$sub"*.yaml; do
			[ -f "$f" ] || continue
			install_config_file "$f" "$PREFIX/conf/$sub_name/$(basename "$f")"
		done
	done
	install_config_file "$SCRIPT_DIR/conf/g3fcgen.yaml" "$PREFIX/conf/g3fcgen.yaml"

	echo "==> 校验配置"
	if ! "$PREFIX/bin/g3proxy" -t -c "$PREFIX/conf/g3proxy.yaml"; then
		echo "配置校验失败，服务未启动；请检查上面 g3proxy 给出的报错" >&2
		exit 1
	fi

	echo "==> 安装 systemd 单元到 ${SYSTEMD_DIR}"
	sed "s#@PREFIX@#${PREFIX}#g; s#@CONTROL_DIR@#${CONTROL_DIR}#g; s#@GROUP@#${DAEMON_GROUP}#g" \
		"$SCRIPT_DIR/systemd/g3proxy.service" > "$SYSTEMD_DIR/g3proxy.service"
	chmod 0644 "$SYSTEMD_DIR/g3proxy.service"
	echo "  g3proxy.service"
	if [ "$WITH_FCGEN" = 1 ]; then
		sed "s#@PREFIX@#${PREFIX}#g; s#@GROUP@#${FCGEN_GROUP}#g" \
			"$SCRIPT_DIR/systemd/g3fcgen.service" > "$SYSTEMD_DIR/g3fcgen.service"
		chmod 0644 "$SYSTEMD_DIR/g3fcgen.service"
		echo "  g3fcgen.service"
	fi
	systemctl daemon-reload

	echo "==> 启动服务"
	systemctl enable --now g3proxy
	if [ "$WITH_FCGEN" = 1 ]; then
		# 证书签发服务要先有自己的 CA 私钥，否则这里会起不来
		if [ ! -e "$PREFIX/conf/myCA.key" ]; then
			echo "  警告：${PREFIX}/conf/myCA.key 不存在，g3fcgen 可能启动失败，" >&2
			echo "        请把自有 CA 的证书与私钥放到 ${PREFIX}/conf 后再 systemctl restart g3fcgen" >&2
		fi
		systemctl enable --now g3fcgen || echo "  g3fcgen 启动失败，见 systemctl status g3fcgen" >&2
	fi

	echo
	echo "完成。检查状态与日志："
	echo "  systemctl status g3proxy"
	echo "  journalctl -u g3proxy -f"
	echo "重载配置（不中断在途连接）："
	echo "  systemctl reload g3proxy"
}

do_uninstall() {
	for unit in g3proxy g3fcgen; do
		if [ -e "$SYSTEMD_DIR/$unit.service" ]; then
			systemctl disable --now "$unit" 2>/dev/null || true
			rm -f "$SYSTEMD_DIR/$unit.service"
			echo "  摘除单元：$unit.service"
		fi
	done
	systemctl daemon-reload

	if [ "$PURGE" = 1 ]; then
		rm -rf "$PREFIX"
		echo "  已删除 $PREFIX"
	else
		echo "  保留 $PREFIX（二进制与配置都在，重删用 uninstall --purge）"
	fi
}

case "$MODE" in
install)
	do_install
	;;
uninstall)
	do_uninstall
	;;
esac
