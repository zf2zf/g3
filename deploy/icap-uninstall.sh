#!/bin/sh
#
# 卸载 g3icap run 包：停 g3icap、摘 systemd 单元，最后删除安装目录（本脚本所在处）。
# 只动 g3icap 自己的单元与目录 —— g3proxy/g3fcgen 是另一个包装的，不在这个包的范围里。
# 删除是脚本的最后一步：shell 经已打开的 fd 继续读脚本，inode 被删不影响收尾，
# 但 rm 之后不能再依赖读脚本新行。

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

if [ -e "$SYSTEMD_DIR/g3icap.service" ]; then
	systemctl disable --now g3icap 2>/dev/null || true
	rm -f "$SYSTEMD_DIR/g3icap.service"
	echo "  摘除单元：g3icap.service"
fi
systemctl daemon-reload

# 只删安装目录：包里那份 uninstall.sh 与 install.sh 同级，从包目录执行时
# 整包原样保留，防止误删构建产物
if [ -e "$PREFIX/bin/g3icap" ] && [ ! -e "$PREFIX/install.sh" ]; then
	rm -rf "$PREFIX"
	echo "  已删除 $PREFIX（如需留存日志请先备份）"
else
	echo "  $PREFIX 看起来是 run 包目录而非安装目录，原样保留"
fi
exit 0
