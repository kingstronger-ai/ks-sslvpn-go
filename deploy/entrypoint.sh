#!/bin/sh
set -e

echo ">>> SSLVPN-Go 启动中..."

# 1. tun 设备（容器内通常由 compose 挂载，兜底创建）
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 600 /dev/net/tun 2>/dev/null || true
fi

# 2. 内核路由转发（compose sysctls 已在容器网络命名空间生效，此处仅兜底）
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 3. 初始化（建库/管理员/PKI/钩子，幂等）
sslvpn init

# 4. 拉起此前运行中的实例
#    设计原则：单个实例启动失败只告警，不阻断 Web 管理界面（否则配置写坏就再也进不去了）
mkdir -p /var/log
if [ -x /usr/sbin/openvpn ]; then
    for conf in /etc/openvpn/instance/*/server.conf; do
        [ -e "$conf" ] || break
        name=$(basename "$(dirname "$conf")")
        logf="/var/log/openvpn-$name.log"
        : > "$logf" 2>/dev/null || true
        /usr/sbin/openvpn --config "$conf" --log-append "$logf" &
        pid=$!
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            echo "    已拉起实例: $name (pid $pid)"
        else
            echo "    !! 实例 $name 启动失败，错误输出："
            tail -n 25 "$logf" 2>/dev/null | sed 's/^/       /' || true
            echo "    --> 已跳过，Web 管理界面继续启动，请登录后修复该实例配置"
        fi
    done
else
    echo "    !! 未找到 /usr/sbin/openvpn，跳过实例启动"
fi

echo ">>> 启动完成，Web 管理界面: https://0.0.0.0:${SSLVPN_WEB_PORT:-8443} (admin / ChangeMe)"
exec sslvpn
