#!/usr/bin/env bash
# ============================================================================
# 一次性改名割接脚本：把现网 sslvpn-go 运行时统一为 ks-sslvpn-go
# ----------------------------------------------------------------------------
# 适用场景：
#   当前以 /opt/sslvpn-go + 容器 sslvpn-go + 镜像 sslvpn-go:latest + 卷
#   sslvpn-go_sslvpn-data / sslvpn-go_sslvpn-openvpn 运行，希望在不丢数据的
#   前提下改名为 ks-sslvpn-go，使运行时名称与 v1.2.4+ 源码 / 包名一致，
#   便于之后的「在线升级」无缝对接（两边都是 ks-sslvpn-go，不再端口冲突）。
#
# 本脚本会：
#   1) 预检（root / docker / 目录 / 容器 / compose 都在）
#   2) 停掉旧容器 sslvpn-go，拷贝数据卷到 ks-sslvpn-go_*
#   3) 目录 /opt/sslvpn-go -> /opt/ks-sslvpn-go
#   4) 改写新目录里的 compose（container_name / image -> ks-sslvpn-go）
#   5) 更新升级代理 systemd 单元的 APP_DIR / CONTAINER 环境变量
#   6) 重建镜像并启动新容器 ks-sslvpn-go，做健康检查
#
# 危险操作：会中断 VPN 数分钟、并拷贝数据卷。请在维护窗口执行，并确保有备份。
# Docker 没有 `volume rename` 命令，数据卷改名靠「建新卷 + 拷贝」，旧卷保留不删，
# 待你确认新服务正常后再手动删除（脚本末尾会给出命令）。
#
# 用法：
#   bash deploy/migrate-to-ks-sslvpn-go.sh            # 先打印计划，需手动确认
#   MIGRATE_YES=1 bash deploy/migrate-to-ks-sslvpn-go.sh   # 跳过确认直接执行
# ============================================================================
set -euo pipefail

# ---- 可覆盖的命名（一般不用动） -------------------------------------------
OLD_DIR="${OLD_DIR_OVERRIDE:-/opt/sslvpn-go}"
NEW_DIR="/opt/ks-sslvpn-go"
OLD_C="sslvpn-go"
NEW_C="ks-sslvpn-go"
OLD_IMG="sslvpn-go:latest"
NEW_IMG="ks-sslvpn-go:latest"
OLD_VP="sslvpn-go"            # 卷前缀：sslvpn-go_sslvpn-data / sslvpn-go_sslvpn-openvpn
NEW_VP="ks-sslvpn-go"
WORK="${WORK_OVERRIDE:-/opt/sslvpn-upgrade}"
UNIT="/etc/systemd/system/sslvpn-upgrade-agent.service"

# compose 里引用的命名卷（不带前缀，前缀由目录名派生）
VOL_BASES=(sslvpn-data sslvpn-openvpn)

log()  { echo -e "\033[1;32m[info]\033[0m $*"; }
warn() { echo -e "\033[1;33m[warn]\033[0m $*"; }
err()  { echo -e "\033[1;31m[error]\033[0m $*"; }
die()  { err "$*"; exit 1; }

# ---- 0. 预检 -----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "请用 root 执行（sudo -i 或直接 root）"
command -v docker >/dev/null 2>&1 || die "找不到 docker"
docker compose version >/dev/null 2>&1 || die "docker compose 不可用"
[ -d "$OLD_DIR" ] || die "找不到旧目录 $OLD_DIR（如路径不同请用 OLD_DIR_OVERRIDE= 指定）"
[ -f "$OLD_DIR/docker-compose.yml" ] || die "$OLD_DIR/docker-compose.yml 不存在"
[ ! -e "$NEW_DIR" ] || die "目标目录 $NEW_DIR 已存在，看起来已经迁移过，已中止"

if docker inspect "$OLD_C" >/dev/null 2>&1; then
  log "检测到旧容器 $OLD_C 正在运行"
else
  warn "旧容器 $OLD_C 未运行；目录仍在，仍会继续迁移（停服状态下改名）"
fi

# ---- 1. 打印计划 + 确认 -------------------------------------------------------
cat <<EOF

==================== 改名割接计划 ====================
  旧目录 : $OLD_DIR            ->  新目录 : $NEW_DIR
  旧容器 : $OLD_C              ->  新容器 : $NEW_C
  旧镜像 : $OLD_IMG            ->  新镜像 : $NEW_IMG
  旧卷前缀 : ${OLD_VP}_*       ->  新卷前缀 : ${NEW_VP}_*
  代理工作目录 : $WORK（不变）
  系统服务 : $UNIT（更新 APP_DIR / CONTAINER 环境变量）
  数据卷 : 建新卷 ${NEW_VP}_* 并拷贝，旧卷 ${OLD_VP}_* 保留不删（确认后再手动删）
=====================================================
EOF

if [ "${MIGRATE_YES:-0}" != "1" ]; then
  read -r -p "确认执行改名割接？(输入 YES 继续，其它退出) " ans
  [ "$ans" = "YES" ] || { warn "已取消"; exit 0; }
fi

# ---- 2. 目录备份（保险） ------------------------------------------------------
BAK="/opt/sslvpn-go-premigrate-$(date +%Y%m%d-%H%M%S).tar.gz"
log "备份旧目录到 $BAK（失败不致命，可跳过）"
tar -czf "$BAK" -C /opt sslvpn-go >/dev/null 2>&1 && log "目录备份完成：$BAK" \
  || warn "目录备份失败，继续（依赖后续数据卷拷贝兜底）"

# ---- 3. 停旧容器 --------------------------------------------------------------
if docker inspect "$OLD_C" >/dev/null 2>&1; then
  log "停止并删除旧容器 $OLD_C（VPN 将短暂中断）"
  docker rm -f "$OLD_C" >/dev/null 2>&1 || die "删除旧容器失败"
fi

# ---- 4. 数据卷改名（建新卷 + 拷贝） ------------------------------------------
copy_volume() {
  local oldv="$1" newv="$2"
  if docker volume inspect "$newv" >/dev/null 2>&1; then
    log "目标卷 $newv 已存在，跳过拷贝"
    return 0
  fi
  log "创建新卷 $newv 并从 $oldv 拷贝数据"
  docker volume create "$newv" >/dev/null 2>&1 || die "创建卷 $newv 失败"
  local img="alpine:3.19"
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    docker pull "$img" >/dev/null 2>&1 || img="busybox:latest"
  fi
  # 用 tar 管道整体拷贝，保留权限/隐藏文件
  docker run --rm -v "$oldv:/from" -v "$newv:/to" "$img" \
    sh -c 'cd /from && tar cf - . | (cd /to && tar xf -)' \
    || die "数据卷 $oldv -> $newv 拷贝失败"
  log "数据卷 $oldv -> $newv 拷贝完成"
}
for vb in "${VOL_BASES[@]}"; do
  copy_volume "${OLD_VP}_${vb}" "${NEW_VP}_${vb}"
done

# ---- 5. 目录改名 --------------------------------------------------------------
log "目录改名：$OLD_DIR -> $NEW_DIR"
mv "$OLD_DIR" "$NEW_DIR" || die "目录改名失败（旧目录仍在，可手动继续）"

# ---- 6. 改写新目录里的 compose（container_name / image） ----------------------
log "更新 $NEW_DIR 内的 compose（container_name / image -> $NEW_C）"
if grep -q "container_name: $OLD_C" "$NEW_DIR/docker-compose.yml"; then
  sed -i "s/^    container_name: $OLD_C$/    container_name: $NEW_C/" "$NEW_DIR/docker-compose.yml"
fi
sed -i "s|image: $OLD_IMG|image: $NEW_IMG|" "$NEW_DIR/docker-compose.yml"
[ -f "$NEW_DIR/docker-compose.nas.yml" ] \
  && sed -i "s|image: $OLD_IMG|image: $NEW_IMG|" "$NEW_DIR/docker-compose.nas.yml"
# 顺手把 compose 里残留的旧目录路径也改掉（如有）
sed -i "s|$OLD_DIR|$NEW_DIR|g" "$NEW_DIR/docker-compose.yml" "$NEW_DIR/docker-compose.nas.yml" 2>/dev/null || true

# ---- 7. 更新升级代理 systemd 单元的 APP_DIR / CONTAINER -----------------------
if [ -f "$UNIT" ]; then
  log "更新系统服务 $UNIT 的 APP_DIR / CONTAINER 环境变量"
  sed -i "s|^Environment=APP_DIR=.*|Environment=APP_DIR=$NEW_DIR|" "$UNIT"
  sed -i "s|^Environment=CONTAINER=.*|Environment=CONTAINER=$NEW_C|" "$UNIT"
  # 同步已经安装在 $WORK 的代理脚本默认值（防止日后重装/手动启动不一致）
  # 仅替换 /opt/sslvpn-go -> /opt/ks-sslvpn-go（代理脚本里该路径只出现在默认行）
  if [ -f "$WORK/upgrade-agent.sh" ]; then
    sed -i 's#/opt/sslvpn-go#/opt/ks-sslvpn-go#g' "$WORK/upgrade-agent.sh" || true
  fi
  systemctl daemon-reload
  systemctl restart sslvpn-upgrade-agent.service 2>/dev/null || warn "重启升级代理失败，请手动：systemctl restart sslvpn-upgrade-agent"
else
  warn "未找到 $UNIT，请手动更新升级代理的 APP_DIR/CONTAINER 后重启"
fi

# ---- 8. 重建并启动新容器 ------------------------------------------------------
log "重建镜像并启动新容器 $NEW_C（VPN 会短暂中断后恢复）"
( cd "$NEW_DIR" && docker compose up -d --build ) >/tmp/migrate-build.log 2>&1 \
  || { err "启动失败，详见 /tmp/migrate-build.log"; cat /tmp/migrate-build.log; exit 1; }

# ---- 9. 健康检查 --------------------------------------------------------------
HEALTH="https://127.0.0.1:58443/healthz"
log "等待健康检查 $HEALTH ..."
ok=0
for i in $(seq 1 30); do
  if curl -kfsS --max-time 3 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = "1" ] || { err "健康检查未通过，请查看：docker logs -f $NEW_C"; exit 1; }

# ---- 10. 完成 ----------------------------------------------------------------
cat <<EOF

==================== 改名完成 ====================
  新目录 : $NEW_DIR
  新容器 : $NEW_C（镜像 $NEW_IMG）
  新卷   : ${NEW_VP}_sslvpn-data / ${NEW_VP}_sslvpn-openvpn（数据已拷贝）
  升级代理 : 已更新 APP_DIR/CONTAINER 并重启
  应用版本 : 仍为迁移前的版本（改名不影响应用代码）

后续两步：
  1) 确认服务正常后，删除旧卷释放空间（可选）：
       docker volume rm ${OLD_VP}_sslvpn-data ${OLD_VP}_sslvpn-openvpn
     以及清理旧镜像（可选）：
       docker image rm $OLD_IMG 2>/dev/null || true
     目录备份可保留或删除：$BAK

  2) 现在运行时已是 ks-sslvpn-go，等 KSVPN 发布 v1.2.4（包名 ks-sslvpn-go-v1.2.4.tar.gz、
     顶层目录 ks-sslvpn-go）后，后台「系统设置 → 版本升级 → 检查更新」即可一键在线升级，
     不会再出现端口冲突。

回滚（若新容器异常）：
  停新容器 -> mv $NEW_DIR $OLD_DIR -> 恢复 $UNIT 的 APP_DIR/CONTAINER 为旧值 ->
  systemctl restart sslvpn-upgrade-agent -> cd $OLD_DIR && docker compose up -d
  旧数据卷 ${OLD_VP}_* 仍完整保留，无需恢复。
=================================================
EOF
