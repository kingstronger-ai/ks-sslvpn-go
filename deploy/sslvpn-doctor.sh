#!/bin/sh
# KSVPN 首次成功工程：预检命令快捷入口
# 用法：
#   ./deploy/sslvpn-doctor.sh            人类可读报告
#   ./deploy/sslvpn-doctor.sh -json     结构化 JSON（供脚本/前端消费）
# 可通过 SSLVPN_CONTAINER 覆盖容器名。
set -eu
CONTAINER="${SSLVPN_CONTAINER:-ks-sslvpn-go}"
exec docker exec -it "$CONTAINER" sslvpn doctor "$@"
