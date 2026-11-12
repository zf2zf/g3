#!/bin/sh
#
# run 包的固定安装脚本：程序与配置统一落在 /opt/zf/g3，g3proxy 与 g3fcgen
# 都装为 systemd 服务并启动。不提供任何命令行选项——正常流程由 .run
# 自解压安装器解压后调用本脚本。
#
# 全新安装（目标机上还没有 g3proxy.yaml）会交互式询问 g3proxy 的监听端口，
# 直接回车用配置模板里的默认值；已有配置时不再询问，端口以现网文件为准。
#
# 网络命名空间也在安装时选择：回车用默认 /run/netns/ns-vpp（升级时取已装单元正在用
# 的值，新装且已装对端 g3icap 时跟随它），输 no 留在 host 网络；非交互安装落默认值。
# 选的值必须与已装的 g3icap 一致，否则在写任何系统目录之前拦住。
#
# PREFIX / SYSTEMD_DIR 环境变量仅供测试，现场部署不要设置它们。

set -eu

PREFIX=${PREFIX:-/opt/zf/g3}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
# 控制套接字目录由 systemd 的 RuntimeDirectory 创建，单位是 /run/g3
CONTROL_DIR=/run/g3
DAEMON_GROUP=g3
FCGEN_GROUP=g3fcgen

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# 装之前先确认待的是哪个包，再确认能不能写系统目录
for need in bin conf systemd install.sh uninstall.sh; do
	if [ ! -e "$SCRIPT_DIR/$need" ]; then
		echo "看起来不在 run 包目录里：缺少 $SCRIPT_DIR/$need" >&2
		echo "请先在构建机执行 deploy/build_run_package.sh，再把生成的 .run 拷到目标机执行" >&2
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

# g3fcgen 是必须的服务：auditor 的 tls_cert_generator 会连 127.0.0.1:2999
# 按 SNI 取中间人证书，没有 CA 它起不来。正常构建的包必带 CA——deploy/conf
# 没有成套 CA 时构建脚本会自动生成一份。这里的检查是兜底：包被手工改动、
# 或目标机上压根没有 CA 时，在写任何系统目录之前中止，而不是装出一个
# 起不来的 g3fcgen。
if [ ! -e "$PREFIX/conf/myCA.key" ] || [ ! -e "$PREFIX/conf/myCA.crt" ]; then
	if [ ! -e "$SCRIPT_DIR/conf/myCA.key" ] || [ ! -e "$SCRIPT_DIR/conf/myCA.crt" ]; then
		echo "缺少 MITM 签发用的 CA：${PREFIX}/conf 与安装包里都没有 myCA.crt/myCA.key" >&2
		echo "请二选一后重新执行：" >&2
		echo "  1) 把 myCA.crt、myCA.key 放到构建机 deploy/conf/ 下重新打包；" >&2
		echo "  2) 把 myCA.crt、myCA.key 放到目标机 ${PREFIX}/conf/ 下。" >&2
		exit 1
	fi
fi

if [ ! -x "$SCRIPT_DIR/bin/g3proxy" ] || [ ! -x "$SCRIPT_DIR/bin/g3fcgen" ]; then
	echo "包里缺少可执行的 bin/g3proxy 或 bin/g3fcgen" >&2
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

# 监听端口交互：只在新装 g3proxy.yaml 时问一次，把端口写进刚装好的文件。
# 默认值取自模板里的 listen address；输入非法就重问； stdin 是 EOF（非交互
# 场景，如管道/自动化）直接落默认值，不卡住。
configure_listen_port() {
	dest=$1
	default_port=$(sed -n 's/.*\[::\]:\([0-9][0-9]*\).*/\1/p' "$dest" | head -1)
	if [ -z "$default_port" ]; then
		echo "  没在 $dest 里找到 \"[::]:<端口>\" 形式的 listen 地址，跳过端口询问" >&2
		return
	fi
	while :; do
		printf 'g3proxy 监听端口 [%s]：' "$default_port"
		if ! read answer; then
			answer=''
			echo
		fi
		[ -n "$answer" ] || answer=$default_port
		case $answer in
		*[!0-9]*)
			echo "  端口要是 1–65535 的数字"
			continue
			;;
		esac
		[ "$answer" -ge 1 ] && [ "$answer" -le 65535 ] && break
		echo "  端口要是 1–65535 的数字"
	done
	if [ "$answer" != "$default_port" ]; then
		sed "s#\[::\]:$default_port\\\"#[::]:$answer\\\"#g" "$dest" > "$dest.tmp" \
			&& mv "$dest.tmp" "$dest"
		echo "  监听端口写入 $dest：[::]:$answer"
	fi
}

# 命名空间契约：g3proxy 与 g3fcgen 必须进同一个命名空间——进 ns 之后 127.0.0.1 就是那个
# 命名空间的回环，g3proxy 取中间人证书走的正是它；而且要跟目标机上已经装好的 g3icap 一致，
# 否则审计请求会打到自己命名空间的空回环上，静默丢掉。命名空间在安装时选择、在这里
# 展开进单元（两个单元用同一个值），与已装 g3icap 的核对在写任何系统目录之前做。
unit_netns() {
	sed -n 's/^NetworkNamespacePath=//p' "$1" 2>/dev/null | head -1
}

# 默认值：升级取本服务单元正在用的命名空间（别把服务搬走）；新装时已装对端 g3icap
# 就跟随它；都没有才用默认 /run/netns/ns-vpp。
DEFAULT_NS=/run/netns/ns-vpp
if [ -e "$SYSTEMD_DIR/g3proxy.service" ]; then
	DEFAULT_NS=$(unit_netns "$SYSTEMD_DIR/g3proxy.service")
	[ -n "$DEFAULT_NS" ] || DEFAULT_NS=no
elif [ -e "$SYSTEMD_DIR/g3icap.service" ]; then
	DEFAULT_NS=$(unit_netns "$SYSTEMD_DIR/g3icap.service")
	[ -n "$DEFAULT_NS" ] || DEFAULT_NS=no
fi

# 命名空间交互：回车用默认值，输 no 留在 host 网络；输入非法就重问；stdin 是 EOF
# （非交互场景，如管道/自动化）直接落默认值，不卡住。
while :; do
	printf '网络命名空间 [%s]（输 no 留在 host 网络）：' "$DEFAULT_NS"
	if ! read answer; then
		answer=''
		echo
	fi
	[ -n "$answer" ] || answer=$DEFAULT_NS
	case $answer in
	no | host)
		PROXY_NS=''
		break
		;;
	/*)
		PROXY_NS=$answer
		break
		;;
	*)
		echo "  要是绝对路径（/run/netns/<名字>），或 no 留在 host 网络"
		;;
	esac
done

if [ -e "$SYSTEMD_DIR/g3icap.service" ]; then
	ICAP_NS=$(unit_netns "$SYSTEMD_DIR/g3icap.service")
	if [ "$ICAP_NS" != "$PROXY_NS" ]; then
		echo "目标机已装的 g3icap 在命名空间 ${ICAP_NS:-（host）}，本包要装的是 ${PROXY_NS:-（host）}" >&2
		echo "两者必须同一个命名空间：g3proxy 送审计只连自己命名空间里的 127.0.0.1:1344，" >&2
		echo "装在别的 ns 等于审计静默丢掉。三选一：" >&2
		echo "  1) 重装 ICAP：sudo /opt/zf/icap/uninstall.sh，再装 icap 包，安装时选同一个命名空间；" >&2
		echo "  2) 现场改它：sudo systemctl edit g3icap 写 NetworkNamespacePath=${PROXY_NS:-（清空则留在 host）}，" >&2
		echo "     再 sudo systemctl daemon-reload restart g3icap；" >&2
		echo "  3) 重装本包，安装时选与 g3icap 相同的命名空间。" >&2
		exit 1
	fi
	echo "==> 网络命名空间与已装的 g3icap 一致：${PROXY_NS:-（都在 host）}"
fi

if [ -n "$PROXY_NS" ] && [ ! -e "$PROXY_NS" ]; then
	echo "选择的网络命名空间不存在：${PROXY_NS}" >&2
	echo "命名空间由 vpp 侧建（或由 ip netns add 建），systemd 不会代你创建。三选一：" >&2
	echo "  1) 先把命名空间建出来（例如 ip netns add ${PROXY_NS##*/}，或由 vpp 侧创建）；" >&2
	echo "  2) 重装本包，输 no 让服务留在 host 网络；" >&2
	echo "  3) 装完后现场改：sudo systemctl edit g3proxy g3fcgen，各写 [Service] 与一条空的" >&2
	echo "     NetworkNamespacePath=，再 daemon-reload。" >&2
	exit 1
fi
if [ -n "$PROXY_NS" ]; then
	echo "==> g3proxy 与 g3fcgen 装入网络命名空间：${PROXY_NS}"
else
	echo "==> g3proxy 与 g3fcgen 留在 host 网络"
fi

# 装完之后在 ns 里看一眼两个回环端口通不通。只提示、不判失败：另一个包可能还没装，
# 装第一个包时对面必然还没起，这里要的是"至少能看一眼"。
check_ns_loopback() {
	ns=$1
	if ! command -v nsenter >/dev/null 2>&1 || ! command -v bash >/dev/null 2>&1; then
		echo "  目标机没有 nsenter/bash，跳过 ns 内连通性自检"
		return
	fi
	for port in 2999 1344; do
		if [ "$port" = 2999 ]; then
			what="g3fcgen 证书签发"
		else
			what="ICAP 审计（g3icap 包）"
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
for bin in "$SCRIPT_DIR"/bin/*; do
	install -m 0755 "$bin" "$PREFIX/bin/$(basename "$bin")"
	echo "  $(basename "$bin")"
done

# 目标机上没有仓库可查，包里的说明与版本记录放到安装前缀下，
# systemd 单元的 Documentation 指向 README。文档每次覆盖成当前版本。
for doc in README.md VERSION; do
	if [ -f "$SCRIPT_DIR/$doc" ]; then
		install -m 0644 "$SCRIPT_DIR/$doc" "$PREFIX/$doc"
		echo "  $PREFIX/$doc"
	fi
done

echo "==> 安装配置到 ${PREFIX}/conf"
mkdir -p "$PREFIX/conf"
fresh_proxy_config=0
[ -e "$PREFIX/conf/g3proxy.yaml" ] || fresh_proxy_config=1
install_config_file "$SCRIPT_DIR/conf/g3proxy.yaml" "$PREFIX/conf/g3proxy.yaml"
if [ "$fresh_proxy_config" = 1 ]; then
	configure_listen_port "$PREFIX/conf/g3proxy.yaml"
else
	echo "  已有 g3proxy.yaml，监听端口沿用现配置（要改端口：编辑该文件后 systemctl restart g3proxy）"
fi
install_config_file "$SCRIPT_DIR/conf/g3fcgen.yaml" "$PREFIX/conf/g3fcgen.yaml"
if [ -e "$SCRIPT_DIR/conf/myCA.crt" ]; then
	# 现网 CA 绝不被动：与已有 CA 不同的新 CA 只会落到 *.new
	install_config_file "$SCRIPT_DIR/conf/myCA.crt" "$PREFIX/conf/myCA.crt"
	install_config_file "$SCRIPT_DIR/conf/myCA.key" "$PREFIX/conf/myCA.key"
	chmod 0600 "$PREFIX/conf/myCA.key"
fi

echo "==> 校验配置"
if ! "$PREFIX/bin/g3proxy" -t -c "$PREFIX/conf/g3proxy.yaml"; then
	echo "配置校验失败，服务未启动；请检查上面 g3proxy 给出的报错" >&2
	exit 1
fi

echo "==> 安装 systemd 单元到 ${SYSTEMD_DIR}"
# @NETNS@ 单独占一行：选了命名空间就展开成指令，no 则整行删掉，不留空行
if [ -n "$PROXY_NS" ]; then
	NETNS_LINES=$(printf '# 进程搬进安装时选定的、已建好的网络命名空间；PrivateNetwork=no 是 systemd 默认值，\n# 写出来只是表明这里不做网络隔离。进 ns 之后 127.0.0.1 是该命名空间的回环，\n# 所以 g3proxy、g3fcgen 与 g3icap 必须共用同一个命名空间，2999 与 1344 才连得上。\nNetworkNamespacePath=%s\nPrivateNetwork=no' "$PROXY_NS")
else
	NETNS_LINES=''
fi
render_unit() {
	awk -v netns="$NETNS_LINES" '
		$0 == "@NETNS@" {
			if (netns != "") printf "%s\n", netns
			next
		}
		{ print }
	' "$1"
}
render_unit "$SCRIPT_DIR/systemd/g3proxy.service" \
	| sed "s#@PREFIX@#${PREFIX}#g; s#@CONTROL_DIR@#${CONTROL_DIR}#g; s#@GROUP@#${DAEMON_GROUP}#g" \
	> "$SYSTEMD_DIR/g3proxy.service"
chmod 0644 "$SYSTEMD_DIR/g3proxy.service"
echo "  g3proxy.service"
render_unit "$SCRIPT_DIR/systemd/g3fcgen.service" \
	| sed "s#@PREFIX@#${PREFIX}#g; s#@GROUP@#${FCGEN_GROUP}#g" \
	> "$SYSTEMD_DIR/g3fcgen.service"
chmod 0644 "$SYSTEMD_DIR/g3fcgen.service"
echo "  g3fcgen.service"
systemctl daemon-reload

echo "==> 卸载脚本落到 ${PREFIX}/uninstall.sh"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$PREFIX/uninstall.sh"

# 安装时选的命名空间已在装任何文件之前核对过（存在性、与已装的 g3icap 一致），
# 这里只负责起服务。
echo "==> 启动服务"
# 先起 g3fcgen：g3proxy 的 TLS 拦截在运行时向它取证书
if ! systemctl enable --now g3fcgen; then
	echo "g3fcgen 启动失败：检查 ${PREFIX}/conf 下的 CA 材料与 g3fcgen.yaml，" >&2
	echo "        修好后执行 systemctl restart g3fcgen" >&2
	exit 1
fi
echo "  g3fcgen"
systemctl enable --now g3proxy
echo "  g3proxy"

if [ -n "$PROXY_NS" ]; then
	echo "==> ns 内回环连通性自检（只提示，不作为安装失败条件）"
	check_ns_loopback "$PROXY_NS"
fi

echo
echo "完成。检查状态与日志："
echo "  systemctl status g3proxy g3fcgen"
echo "  journalctl -u g3proxy -u g3fcgen -f"
echo "重载配置（不中断在途连接）："
echo "  systemctl reload g3proxy"
if [ ! -e "$SYSTEMD_DIR/g3icap.service" ]; then
	echo "ICAP 审计服务端（127.0.0.1:1344）在另一个包里：装 g3icap 包即可，安装时选与本包"
	echo "相同的网络命名空间，安装脚本会核对是否一致。"
fi
echo "卸载（停服务、摘单元，并删除 ${PREFIX}，配置与 CA 一并清除）："
echo "  sudo ${PREFIX}/uninstall.sh"
