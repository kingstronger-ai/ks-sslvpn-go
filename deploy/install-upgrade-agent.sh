#!/usr/bin/env bash
# 一键安装 SSLVPN-Go 宿主机升级代理（在服务器宿主机执行）
#   bash deploy/install-upgrade-agent.sh
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/upgrade-agent.sh"
DEST="${DEST:-/opt/sslvpn-upgrade}"
APP_DIR="${APP_DIR:-/opt/ks-sslvpn-go}"
CONTAINER="${CONTAINER:-ks-sslvpn-go}"

[ "$(id -u)" -eq 0 ] || { echo "请用 root 执行"; exit 1; }
[ -f "$SRC" ] || { echo "找不到 $SRC"; exit 1; }
[ -d "$APP_DIR" ] || { echo "找不到应用目录 $APP_DIR（可用 APP_DIR=/path 指定）"; exit 1; }
for c in docker curl tar sha256sum date sed grep; do
  command -v "$c" >/dev/null 2>&1 || { echo "缺少命令：$c"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "docker compose 不可用"; exit 1; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || { echo "容器 $CONTAINER 未运行（可用 CONTAINER=xxx 指定）"; exit 1; }

mkdir -p "$DEST/backups" "$DEST/packages"
cp "$SRC" "$DEST/upgrade-agent.sh"
chmod +x "$DEST/upgrade-agent.sh"

cat > /etc/systemd/system/sslvpn-upgrade-agent.service <<EOF
[Unit]
Description=SSLVPN-Go upgrade agent
After=docker.service
Requires=docker.service

[Service]
Type=simple
Environment=APP_DIR=$APP_DIR
Environment=CONTAINER=$CONTAINER
Environment=WORK=$DEST
ExecStart=/bin/bash $DEST/upgrade-agent.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sslvpn-upgrade-agent.service
sleep 2
systemctl is-active --quiet sslvpn-upgrade-agent.service || {
  echo "代理启动失败，请查看：journalctl -u sslvpn-upgrade-agent -n 50 --no-pager"; exit 1;
}

echo
echo "✓ 升级代理已安装并启动：$DEST/upgrade-agent.sh"
echo "  状态：systemctl status sslvpn-upgrade-agent"
echo "  日志：journalctl -u sslvpn-upgrade-agent -f"
echo
echo "接下来还需要两步（否则页面会提示「代理未在线 / 未配置更新源」）："
echo "  1) 把 version.json 放到 $DEST/version.json（模板见 deploy/version.json.example），"
echo "     代理会自动同步到容器内供检测读取。"
echo "  2) 在 $APP_DIR/docker-compose.yml 的 environment 加一行（注意是容器内的路径）："
echo "       - SSLVPN_UPDATE_URL=file:///var/lib/sslvpn/upgrade/version.json"
echo "     然后执行：cd $APP_DIR && docker compose up -d"
echo
echo "  版本包请放在 $DEST/packages/ 下，并把 version.json 的 package 指向它。"
