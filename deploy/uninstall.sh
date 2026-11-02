#!/bin/sh
#
# 卸载 run 包：停 g3proxy 与 g3fcgen、摘 systemd 单元，最后删除安装目录
# （本脚本所在处）。删除是脚本的最后一步：shell 经已打开的 fd 继续读脚本，
# inode 被删不影响收尾，但 rm 之后不能再依赖读脚本新行。

set -eu

# 前缀取本脚本所在位置——它被装在哪个目录就删哪个目录
PREFIX=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}

if [ "$(id -u)" != 0 ]; then
	echo "本脚本会操作 systemd 与 ${SYSTEMD_DIR}，请用 root 或 sudo 执行" >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "目标机没有 systemctl，本脚本只支持 systemd 托管的服务形态" >&2
	exit 1
fi

for unit in g3proxy g3fcgen; do
	if [ -e "$SYSTEMD_DIR/$unit.service" ]; then
		systemctl disable --now "$unit" 2>/dev/null || true
		rm -f "$SYSTEMD_DIR/$unit.service"
		echo "  摘除单元：$unit.service"
	fi
done
systemctl daemon-reload

# 只删安装目录：包里那份 uninstall.sh 与 install.sh 同级，从包目录执行时
# 整包原样保留，防止误删构建产物
if [ -e "$PREFIX/bin/g3proxy" ] && [ ! -e "$PREFIX/install.sh" ]; then
	rm -rf "$PREFIX"
	echo "  已删除 $PREFIX（配置与 CA 一并清除，如需留存请先备份）"
else
	echo "  $PREFIX 看起来是 run 包目录而非安装目录，原样保留"
fi
exit 0
