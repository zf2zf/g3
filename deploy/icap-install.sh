#!/bin/sh
#
# g3icap run 包的固定安装脚本：可执行程序与 systemd 单元落在 /opt/zf/icap，
# g3icap 装为 systemd 服务并启动。不提供任何命令行选项——正常流程由 .run
# 自解压安装器解压后调用本脚本。
#
# ICAP 服务端是审计链路的末端，必须和 g3proxy、g3fcgen 在同一个网络命名空间里：
# g3proxy 进了 ns 之后只会连该命名空间的 127.0.0.1:1344。所以装之前拿目标机上
# 已有的 g3 单元比对 NetworkNamespacePath，不一致就直接失败——装在别的命名空间里
# 表面上一切正常，审计请求却静默丢掉，比装不上难查得多。
#
# PREFIX / SYSTEMD_DIR 环境变量仅供测试，现场部署不要设置它们。

set -eu

PREFIX=${PREFIX:-/opt/zf/icap}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# 装之前先确认待的是哪个包，再确认能不能写系统目录
for need in bin systemd install.sh uninstall.sh; do
	if [ ! -e "$SCRIPT_DIR/$need" ]; then
		echo "看起来不在 run 包目录里：缺少 $SCRIPT_DIR/$need" >&2
		echo "请先在构建机执行 deploy/build_run_package.sh --component=icap，" >&2
		echo "再把生成的 .run 拷到目标机执行" >&2
		exit 1
	fi
done

if [ "$(id -u)" != 0 ]; then
	echo "本脚本会写 ${PREFIX} 与 ${SYSTEMD_DIR}，请用 root 或 sudo 执行" >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "目标机没有 systemctl，本脚本只支持 systemd 托管的服务形态" >&2
	exit 1
fi

if [ ! -x "$SCRIPT_DIR/bin/g3icap" ]; then
	echo "包里缺少可执行的 bin/g3icap" >&2
	exit 1
fi

# 本包的命名空间是打包时展开进单元的成品，这里只核对，不改。
unit_netns() {
	sed -n 's/^NetworkNamespacePath=//p' "$1" 2>/dev/null | head -1
}

ICAP_NS=$(unit_netns "$SCRIPT_DIR/systemd/g3icap.service")
G3_SEEN=0
for peer in g3proxy g3fcgen; do
	unit="$SYSTEMD_DIR/$peer.service"
	[ -e "$unit" ] || continue
	G3_SEEN=1
	peer_ns=$(unit_netns "$unit")
	if [ "$peer_ns" != "$ICAP_NS" ]; then
		echo "已安装的 ${peer} 在命名空间 ${peer_ns:-（host）}，本包要装的是 ${ICAP_NS:-（host）}" >&2
		echo "三者必须共用一个命名空间，否则 g3proxy 送的审计打到自己命名空间的空回环上。" >&2
		echo "三选一：" >&2
		echo "  1) 回构建机用与 g3 包相同的路径重打本包：" >&2
		echo "     deploy/build_run_package.sh --component=icap --netns=${peer_ns:-<g3 包用的路径>}；" >&2
		echo "  2) 现场改本服务：sudo systemctl edit g3icap 写 NetworkNamespacePath=${peer_ns:-（清空则留在 host）}，" >&2
		echo "     再 sudo systemctl daemon-reload restart g3icap；" >&2
		echo "  3) 两边都退回 host：两个包都用 --netns=no 重打。" >&2
		exit 1
	fi
	echo "==> 网络命名空间与已装的 ${peer} 一致：${ICAP_NS:-（都在 host）}"
done

if [ "$G3_SEEN" = 0 ]; then
	echo "提示：目标机上还没装 g3proxy/g3fcgen，无法比对命名空间。" >&2
	echo "      先装 g3 包，或保证两个包用同一个 --netns 路径打包（默认 /run/netns/ns-vpp）。" >&2
fi

if [ -n "$ICAP_NS" ] && [ ! -e "$ICAP_NS" ]; then
	echo "单元指定的网络命名空间不存在：${ICAP_NS}" >&2
	echo "命名空间由 vpp 侧建（或由 ip netns add 建），systemd 不会代你创建。三选一：" >&2
	echo "  1) 先把命名空间建出来（例如 ip netns add ${ICAP_NS##*/}，或由 vpp 侧创建）；" >&2
	echo "  2) 现场让它留在 host：sudo systemctl edit g3icap，写 [Service] 与一条空的" >&2
	echo "     NetworkNamespacePath=，再 daemon-reload；" >&2
	echo "  3) 回构建机 NETNS=no 重新打包。" >&2
	exit 1
fi

# 装完之后在 ns 里看一眼回环端口。只提示、不判失败：g3 包可能还没装。
check_ns_loopback() {
	ns=$1
	if ! command -v nsenter >/dev/null 2>&1 || ! command -v bash >/dev/null 2>&1; then
		echo "  目标机没有 nsenter/bash，跳过 ns 内连通性自检"
		return
	fi
	for port in 1344 2999; do
		if [ "$port" = 1344 ]; then
			what="g3icap 自己"
		else
			what="g3fcgen 证书签发（g3 包）"
		fi
		if nsenter --net="$ns" bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
			echo "  ns 内 127.0.0.1:$port 可达 — ${what}"
		else
			echo "  ns 内 127.0.0.1:$port 不可达 — ${what}：没装、没起，或不在 ${ns} 里"
		fi
	done
}

echo "==> 安装可执行程序到 ${PREFIX}/bin"
mkdir -p "$PREFIX/bin"
install -m 0755 "$SCRIPT_DIR/bin/g3icap" "$PREFIX/bin/g3icap"
echo "  g3icap"

# 包里的说明与版本记录放到安装前缀下，systemd 单元的 Documentation 指向 README
for doc in README.md VERSION; do
	if [ -f "$SCRIPT_DIR/$doc" ]; then
		install -m 0644 "$SCRIPT_DIR/$doc" "$PREFIX/$doc"
		echo "  $PREFIX/$doc"
	fi
done

echo "==> 安装 systemd 单元到 ${SYSTEMD_DIR}"
sed "s#@PREFIX@#${PREFIX}#g" \
	"$SCRIPT_DIR/systemd/g3icap.service" > "$SYSTEMD_DIR/g3icap.service"
chmod 0644 "$SYSTEMD_DIR/g3icap.service"
echo "  g3icap.service"
systemctl daemon-reload

echo "==> 卸载脚本落到 ${PREFIX}/uninstall.sh"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$PREFIX/uninstall.sh"

if [ -n "$ICAP_NS" ]; then
	echo "==> g3icap 装入网络命名空间：${ICAP_NS}"
fi

echo "==> 启动服务"
if ! systemctl enable --now g3icap; then
	echo "g3icap 启动失败：journalctl -u g3icap 看报错" >&2
	echo "        （监听口被占、命名空间不通都会在这里现形）" >&2
	exit 1
fi
echo "  g3icap"

if [ -n "$ICAP_NS" ]; then
	echo "==> ns 内回环连通性自检（只提示，不作为安装失败条件）"
	check_ns_loopback "$ICAP_NS"
fi

echo
echo "完成。检查状态与日志："
echo "  systemctl status g3icap"
echo "  journalctl -u g3icap -f        # 送审过来的 ICAP 报文逐段打印在这里"
echo "一条请求都没收到时先确认三个服务在同一命名空间："
echo "  systemctl show -p NetworkNamespacePath g3proxy g3fcgen g3icap   # 三行应当一致"
echo "卸载（停服务、摘单元，并删除 ${PREFIX}；不碰 g3 包的单元与目录）："
echo "  sudo ${PREFIX}/uninstall.sh"
