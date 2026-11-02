#!/bin/sh
#
# run 包的固定安装脚本：程序与配置统一落在 /opt/zf/g3，g3proxy 与 g3fcgen
# 都装为 systemd 服务并启动。不提供任何命令行选项——正常流程由 .run
# 自解压安装器解压后调用本脚本。
#
# 全新安装（目标机上还没有 g3proxy.yaml）会交互式询问 g3proxy 的监听端口，
# 直接回车用配置模板里的默认值；已有配置时不再询问，端口以现网文件为准。
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
sed "s#@PREFIX@#${PREFIX}#g; s#@CONTROL_DIR@#${CONTROL_DIR}#g; s#@GROUP@#${DAEMON_GROUP}#g" \
	"$SCRIPT_DIR/systemd/g3proxy.service" > "$SYSTEMD_DIR/g3proxy.service"
chmod 0644 "$SYSTEMD_DIR/g3proxy.service"
echo "  g3proxy.service"
sed "s#@PREFIX@#${PREFIX}#g; s#@GROUP@#${FCGEN_GROUP}#g" \
	"$SCRIPT_DIR/systemd/g3fcgen.service" > "$SYSTEMD_DIR/g3fcgen.service"
chmod 0644 "$SYSTEMD_DIR/g3fcgen.service"
echo "  g3fcgen.service"
systemctl daemon-reload

echo "==> 卸载脚本落到 ${PREFIX}/uninstall.sh"
install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$PREFIX/uninstall.sh"

# 打包时展开进单元的 NetworkNamespacePath 必须在目标机已经存在：命名空间由 vpp 那侧
# 建，缺了要等 systemd 起进程才失败，报错还埋在 journal 里。这里提前拦住。
netns_path=$(sed -n 's/^NetworkNamespacePath=//p' "$SYSTEMD_DIR/g3proxy.service" | head -1)
if [ -n "$netns_path" ]; then
	if [ ! -e "$netns_path" ]; then
		echo "g3proxy 单元指定的网络命名空间不存在：${netns_path}" >&2
		echo "三选一：" >&2
		echo "  1) 先把命名空间建出来（例如 ip netns add ${netns_path##*/}，或由 vpp 侧创建）；" >&2
		echo "  2) 现场让 g3proxy 留在 host：sudo systemctl edit g3proxy，写 [Service] 与一条空的" >&2
		echo "     NetworkNamespacePath=，再 daemon-reload；" >&2
		echo "  3) 回构建机 NETNS=no 重新打包。" >&2
		echo "另注意：g3proxy 进 ns 后 127.0.0.1 是该 ns 的回环，配置里的 g3fcgen(2999) 与" >&2
		echo "ICAP(1344) 必须在 ${netns_path} 里可达，否则 TLS 拦截与审计取不到东西。" >&2
		exit 1
	fi
	echo "==> g3proxy 装入网络命名空间：${netns_path}"
fi

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

echo
echo "完成。检查状态与日志："
echo "  systemctl status g3proxy g3fcgen"
echo "  journalctl -u g3proxy -u g3fcgen -f"
echo "重载配置（不中断在途连接）："
echo "  systemctl reload g3proxy"
echo "卸载（停服务、摘单元，并删除 ${PREFIX}，配置与 CA 一并清除）："
echo "  sudo ${PREFIX}/uninstall.sh"
