#!/usr/bin/env bash
# SSLVPN-Go 宿主机升级代理（在服务器宿主机运行，不在容器内）
#
# 与容器通过数据卷内的纯文本/JSON 文件通信，无需挂载 docker.sock、无需改 compose：
#   容器 -> 代理 : /var/lib/sslvpn/upgrade/request.json
#   代理 -> 容器 : status.ini / backups.txt / log.txt / version.json
#
# 流程：检测请求 -> 【先完整备份源码/配置/两个卷/旧镜像】-> 校验包 -> 原地覆盖
#       -> docker compose up -d --build -> 健康检查 -> 失败自动回滚。
# 任何情况下都不执行 docker compose down -v / docker volume rm。
set -u

APP_DIR="${APP_DIR:-/opt/sslvpn-go}"
CONTAINER="${CONTAINER:-sslvpn-go}"
WORK="${WORK:-/opt/sslvpn-upgrade}"
VOL_DIR="/var/lib/sslvpn/upgrade"
HEALTH_URL="${HEALTH_URL:-https://127.0.0.1:58443/healthz}"
BACKUP_IMG="${BACKUP_IMG:-}"   # 留空则用当前运行镜像（自带 tar，无需联网拉 alpine）
CUR_ID=""
CUR_BID=""

mkdir -p "$WORK/backups" "$WORK/packages"
[ -f "$WORK/status.ini" ] || cat > "$WORK/status.ini" <<EOF
phase=idle
progress=0
message=代理已就绪
request_id=
backup_id=
result_version=
heartbeat=$(date -Iseconds)
EOF
[ -f "$WORK/backups.txt" ] || : > "$WORK/backups.txt"
[ -f "$WORK/upgrade.log" ] || : > "$WORK/upgrade.log"

# 当前运行镜像（用于备份/恢复数据卷，避免额外拉取镜像）
runtime_image() {
  local img
  img="$(docker inspect "$CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  [ -n "$img" ] || img="alpine:3.19"
  echo "$img"
}

# 把宿主机文件同步进容器数据卷；容器重建期间失败可忽略，下一轮会重试
put() {
  local src="$1" name="$2"
  [ -f "$src" ] || return 0
  docker exec "$CONTAINER" mkdir -p "$VOL_DIR" >/dev/null 2>&1 || return 0
  docker cp "$src" "$CONTAINER:$VOL_DIR/$name" >/dev/null 2>&1 || return 0
}

set_status() {
  local phase="$1" progress="$2" msg="$3" rver="${4:-}"
  cat > "$WORK/status.ini" <<EOF
phase=$phase
progress=$progress
message=$msg
request_id=$CUR_ID
backup_id=$CUR_BID
result_version=$rver
heartbeat=$(date -Iseconds)
EOF
  put "$WORK/status.ini" status.ini
}

heartbeat() {
  sed -i '/^heartbeat=/d' "$WORK/status.ini" 2>/dev/null || true
  echo "heartbeat=$(date -Iseconds)" >> "$WORK/status.ini"
  put "$WORK/status.ini" status.ini
}

logline() {
  echo "[$(date '+%F %T')] $*" >> "$WORK/upgrade.log"
  tail -n 200 "$WORK/upgrade.log" > "$WORK/log.txt"
  put "$WORK/log.txt" log.txt
  echo "$*" >&2   # 日志走 stderr，保证 do_rollback 的 stdout 只返回版本号
}

# 从后端生成的紧凑 JSON 中取字符串字段（字段值不含引号）
jget() {
  printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
    | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//'
}

health_wait() {
  local i
  for i in $(seq 1 30); do
    if curl -kfsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

volume_names() {
  local v
  v="$(docker inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null || true)"
  [ -n "$v" ] || v="$(docker volume ls --format '{{.Name}}' | grep 'sslvpn' || true)"
  printf '%s' "$v"
}

# ---------- 备份：源码 + 配置 + 两个命名卷 + 旧镜像 tag ----------
do_backup() {
  local bid="$1" bk="$WORK/backups/$bid" v img ver
  CUR_BID="$bid"
  mkdir -p "$bk" || return 1
  set_status "backing_up" 10 "正在备份源码、配置与数据卷"
  logline "开始升级前备份 -> $bk"

  # 只排除历史升级包（*.tar.gz）。不能排除 *.zip：deploy/downloads/ 下的
  # 客户端安装包（Windows 卸载包、macOS 源码包等）是 zip，漏掉会导致回滚后缺文件。
  tar -czf "$bk/src.tar.gz" -C "$(dirname "$APP_DIR")" \
      --exclude='*.tar.gz' "$(basename "$APP_DIR")" || return 1
  cp -a "$APP_DIR/docker-compose.yml" "$bk/docker-compose.yml" || return 1
  [ -f "$APP_DIR/.env" ] && cp -a "$APP_DIR/.env" "$bk/.env"
  cp -a "$APP_DIR/backend/internal/version/VERSION" "$bk/VERSION" 2>/dev/null \
      || echo "unknown" > "$bk/VERSION"
  ver="$(tr -d '\r\n' < "$bk/VERSION")"

  v="$(volume_names)"
  [ -n "$v" ] || { logline "找不到 sslvpn 数据卷，已中止升级"; return 1; }
  BACKUP_IMG="$(runtime_image)"
  while IFS= read -r vol; do
    [ -n "$vol" ] || continue
    logline "备份数据卷 $vol"
    docker run --rm --entrypoint tar -v "$vol:/data:ro" -v "$bk:/backup" \
      "$BACKUP_IMG" czf "/backup/vol-$vol.tar.gz" -C /data . || return 1
  done <<< "$v"

  img="$(docker inspect "$CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  if [ -n "$img" ]; then
    docker tag "$img" "sslvpn-go:rollback-$bid" >/dev/null 2>&1 || true
    echo "$img" > "$bk/image.txt"
  fi

  printf '%s|%s|%s|%s|%s\n' "$bid" "$(date '+%F %T')" "$ver" \
      "$(du -sh "$bk" 2>/dev/null | cut -f1)" "$bk" >> "$WORK/backups.txt"
  put "$WORK/backups.txt" backups.txt
  logline "备份完成（版本 $ver），可随时回滚"
  return 0
}

restore_volumes() {
  local bk="$1" f vol
  BACKUP_IMG="$(runtime_image)"
  for f in "$bk"/vol-*.tar.gz; do
    [ -f "$f" ] || continue
    vol="$(basename "$f" .tar.gz)"; vol="${vol#vol-}"
    logline "恢复数据卷 $vol"
    docker run --rm --entrypoint tar -v "$vol:/data" -v "$bk:/backup:ro" \
      "$BACKUP_IMG" xzf "/backup/$(basename "$f")" -C /data || return 1
  done
  return 0
}

# ---------- 回滚：保留失败现场 + 恢复旧源码/卷/镜像 ----------
do_rollback() {
  local bid="$1" bk="$WORK/backups/$bid" oldver
  [ -d "$bk" ] || { logline "备份 $bid 不存在，无法回滚"; return 1; }
  oldver="$(tr -d '\r\n' < "$bk/VERSION" 2>/dev/null || echo unknown)"
  set_status "rolling_back" 70 "正在回滚到版本 $oldver（含数据卷恢复）"
  logline "开始回滚到备份 $bid（版本 $oldver）"

  (cd "$APP_DIR" && docker compose stop) >/dev/null 2>&1 || true
  # 目录改名保留失败现场；新解压出的目录仍叫 sslvpn-go，compose 项目名/卷归属不变
  mv "$APP_DIR" "$APP_DIR.failed-$bid" || { logline "保留失败现场失败"; return 1; }
  tar -xzf "$bk/src.tar.gz" -C "$(dirname "$APP_DIR")" || { logline "恢复源码失败"; return 1; }
  cp -a "$bk/docker-compose.yml" "$APP_DIR/docker-compose.yml"

  if ! restore_volumes "$bk"; then
    logline "警告：数据卷恢复有错误，请检查 $WORK/upgrade.log"
  fi
  if [ -f "$bk/image.txt" ] && docker image inspect "sslvpn-go:rollback-$bid" >/dev/null 2>&1; then
    docker tag "sslvpn-go:rollback-$bid" "$(cat "$bk/image.txt")" >/dev/null 2>&1 || true
    (cd "$APP_DIR" && docker compose up -d) > "$WORK/rollback.log" 2>&1
  else
    (cd "$APP_DIR" && docker compose up -d --build) > "$WORK/rollback.log" 2>&1
  fi
  if [ $? -ne 0 ]; then logline "回滚时启动容器失败，详见 $WORK/rollback.log"; return 1; fi
  if ! health_wait; then logline "回滚后健康检查未通过，详见 $WORK/rollback.log"; return 1; fi
  logline "回滚完成，当前版本 $oldver"
  echo "$oldver"
  return 0
}

rollback_and_fail() {
  local msg="$1"
  logline "$msg，执行自动回滚"
  if do_rollback "$CUR_BID" >/dev/null; then
    set_status "failed" 100 "$msg；已自动回滚到升级前状态" "$(tr -d '\r\n' < "$WORK/backups/$CUR_BID/VERSION" 2>/dev/null || echo unknown)"
  else
    set_status "failed" 100 "$msg；自动回滚失败，请查看日志手动处理"
  fi
}

# ---------- 升级 ----------
do_upgrade() {
  local rid="$1" ver="$2" pkg="$3" sha="$4"
  local bid="bk-$(date +%Y%m%d-%H%M%S)" localpkg top newver
  CUR_ID="$rid"
  logline "收到升级请求 id=$rid 目标版本 $ver"

  [ -d "$APP_DIR" ] || { set_status "failed" 0 "找不到 $APP_DIR"; return 1; }
  [ -f "$APP_DIR/docker-compose.yml" ] || { set_status "failed" 0 "目录下没有 docker-compose.yml"; return 1; }

  # ① 先备份，备份不成功绝不解压
  if ! do_backup "$bid"; then
    set_status "failed" 10 "升级前备份失败，已中止（源码未改动）"
    logline "备份失败，升级中止，源码保持原样"
    return 1
  fi

  # ② 取包：http(s) 下载；否则视为宿主机绝对路径
  set_status "downloading" 25 "正在获取升级包"
  if [[ "$pkg" == http* ]]; then
    localpkg="$WORK/packages/$rid.tar.gz"
    if ! curl -fL --retry 2 -o "$localpkg" "$pkg"; then
      set_status "failed" 25 "下载升级包失败，已中止（源码未改动）"
      return 1
    fi
  else
    localpkg="$pkg"
    if [ ! -f "$localpkg" ]; then
      set_status "failed" 25 "找不到升级包 $localpkg，已中止（源码未改动）"
      return 1
    fi
  fi

  # ③ 校验 sha256 + 包结构（防篡改、防解错目录）
  set_status "verifying" 40 "正在校验升级包"
  if ! echo "$sha  $localpkg" | sha256sum -c - >/dev/null 2>&1; then
    set_status "failed" 40 "sha256 校验失败，已中止（源码未改动）"
    return 1
  fi
  if ! tar -tzf "$localpkg" >/dev/null 2>&1; then
    set_status "failed" 40 "升级包不是有效的 tar.gz，已中止（源码未改动）"
    return 1
  fi
  top="$(tar -tzf "$localpkg" | head -1 | cut -d/ -f1)"
  if [ "$top" != "$(basename "$APP_DIR")" ]; then
    set_status "failed" 40 "升级包顶层目录为 $top，应为 $(basename "$APP_DIR")，已中止"
    return 1
  fi
  tar -xzOf "$localpkg" "$top/docker-compose.yml" > "$WORK/backups/$bid/compose.new.yml" 2>/dev/null || true

  # ④ 原地覆盖解压（tar 只覆盖不删除，保留现网 compose 的端口/环境自定义）
  set_status "extracting" 55 "正在原地覆盖源码"
  if ! tar -xzf "$localpkg" -C "$(dirname "$APP_DIR")"; then
    rollback_and_fail "解压失败"
    return 1
  fi
  cp -a "$WORK/backups/$bid/docker-compose.yml" "$APP_DIR/docker-compose.yml"

  # ⑤ 重建并启动（必须在本目录，目录名决定 compose 项目名 -> 决定挂哪个卷）
  set_status "building" 70 "正在重建镜像并启动容器（VPN 会短暂中断）"
  logline "执行 docker compose up -d --build"
  if ! (cd "$APP_DIR" && docker compose up -d --build) > "$WORK/build.log" 2>&1; then
    tail -n 30 "$WORK/build.log" >> "$WORK/upgrade.log"
    rollback_and_fail "镜像构建失败"
    return 1
  fi

  # ⑥ 健康检查，失败自动回滚
  set_status "healthcheck" 90 "正在做健康检查"
  if ! health_wait; then
    rollback_and_fail "升级后健康检查未通过"
    return 1
  fi

  newver="$(tr -d '\r\n' < "$APP_DIR/backend/internal/version/VERSION" 2>/dev/null || echo "$ver")"

  # ⑦ 代理自更新：新版包若带新的 upgrade-agent.sh，替换自身副本并重启服务加载
  #    （systemd 单元跑的是 $WORK/upgrade-agent.sh，不随应用升级自动更新；mv 原子替换，
  #     正在运行的旧进程不受影响，重启由 systemd 拉起新脚本）
  if [ -f "$APP_DIR/deploy/upgrade-agent.sh" ] && ! cmp -s "$APP_DIR/deploy/upgrade-agent.sh" "$WORK/upgrade-agent.sh"; then
    if cp -a "$APP_DIR/deploy/upgrade-agent.sh" "$WORK/upgrade-agent.sh.new" \
       && mv -f "$WORK/upgrade-agent.sh.new" "$WORK/upgrade-agent.sh"; then
      chmod +x "$WORK/upgrade-agent.sh"
      logline "升级代理脚本已自更新，即将重启代理加载新逻辑"
      set_status "done" 100 "升级完成，当前版本 $newver；升级前备份 $bid 可随时回滚；升级代理已自更新" "$newver"
      logline "升级完成：$newver（备份 $bid）"
      if [ -f /etc/systemd/system/sslvpn-upgrade-agent.service ]; then
        systemctl restart sslvpn-upgrade-agent 2>/dev/null || true
      fi
      return 0
    fi
    logline "升级代理自更新失败，继续使用旧代理（不影响本次升级结果）"
  fi

  set_status "done" 100 "升级完成，当前版本 $newver；升级前备份 $bid 可随时回滚" "$newver"
  logline "升级完成：$newver（备份 $bid）"
}

do_rollback_request() {
  local rid="$1" bid="$2" oldver
  CUR_ID="$rid"; CUR_BID="$bid"
  logline "收到回滚请求 id=$rid 备份 $bid"
  if oldver="$(do_rollback "$bid")"; then
    set_status "done" 100 "已回滚到版本 $oldver" "$oldver"
  else
    set_status "failed" 100 "回滚失败，请查看日志与 $WORK/backups/$bid 手动处理"
  fi
}

# ---------- 删除较早的备份（最近 2 份受保护，代理侧强制执行） ----------
do_delete_backup() {
  local rid="$1" bid="$2" total match_line bkdir left
  CUR_ID="$rid"; CUR_BID=""
  logline "收到删除备份请求 id=$rid 备份 $bid"
  case "$bid" in
    bk-*) [ "${bid#*/}" = "$bid" ] || { set_status "failed" 100 "备份 ID 不合法，已拒绝删除"; return 1; } ;;
    *) set_status "failed" 100 "备份 ID 不合法，已拒绝删除"; return 1 ;;
  esac
  if [ ! -s "$WORK/backups.txt" ]; then
    set_status "failed" 100 "备份清单为空，找不到 $bid"; return 1
  fi
  # backups.txt 为追加式（最后的行最新）：最新 2 行受保护
  total="$(grep -c . "$WORK/backups.txt" 2>/dev/null || echo 0)"
  match_line="$(grep -n "^${bid}|" "$WORK/backups.txt" 2>/dev/null | head -1 | cut -d: -f1)"
  if [ -z "$match_line" ]; then
    set_status "failed" 100 "找不到备份 $bid，可能已被清理"; return 1
  fi
  if [ "$match_line" -gt "$((total - 2))" ] 2>/dev/null; then
    set_status "failed" 100 "最近 2 份备份受保护，不能删除"; return 1
  fi
  # 防路径注入：只允许删除登记在 $WORK/backups/ 下的目录
  bkdir="$(grep "^${bid}|" "$WORK/backups.txt" | head -1 | cut -d'|' -f5)"
  case "$bkdir" in
    "$WORK"/backups/*) : ;;
    *) set_status "failed" 100 "备份路径异常，已拒绝删除"; return 1 ;;
  esac
  [ -d "$bkdir" ] || { set_status "failed" 100 "备份目录不存在：$bkdir"; return 1; }
  if ! rm -rf -- "$bkdir"; then
    set_status "failed" 100 "删除目录失败，请检查权限：$bkdir"
    return 1
  fi
  grep -v "^${bid}|" "$WORK/backups.txt" > "$WORK/backups.txt.tmp" \
    && mv -f "$WORK/backups.txt.tmp" "$WORK/backups.txt"
  put "$WORK/backups.txt" backups.txt
  left="$(grep -c . "$WORK/backups.txt" 2>/dev/null || echo 0)"
  set_status "done" 100 "已删除备份 $bid，剩余 $left 份备份"
  logline "已删除备份 $bid（目录 $bkdir），剩余 $left 份"
}

# ---------- 主循环 ----------
LAST_ID_FILE="$WORK/.last_request_id"
[ -f "$LAST_ID_FILE" ] || : > "$LAST_ID_FILE"
logline "升级代理启动：APP_DIR=$APP_DIR CONTAINER=$CONTAINER WORK=$WORK"
while true; do
  # 把宿主机 $WORK/version.json 同步进容器供 file:// 更新源读取。
  # 用内容比对而非 mtime：容器重建、手动 docker cp、文件被覆盖、.version.synced
  # 时间戳领先等情况都能自愈。容器短暂不可用时 put 静默失败，下一轮自动重试。
  if [ -f "$WORK/version.json" ]; then
    if ! docker exec -i "$CONTAINER" cmp -s "$VOL_DIR/version.json" - < "$WORK/version.json" >/dev/null 2>&1; then
      put "$WORK/version.json" version.json
    fi
  fi

  req="$(docker exec "$CONTAINER" cat "$VOL_DIR/request.json" 2>/dev/null || true)"
  if [ -n "$req" ]; then
    rid="$(jget "$req" id)"
    last="$(cat "$LAST_ID_FILE" 2>/dev/null || true)"
    if [ -n "$rid" ] && [ "$rid" != "$last" ]; then
      echo "$rid" > "$LAST_ID_FILE"
      case "$(jget "$req" action)" in
        upgrade)       do_upgrade "$rid" "$(jget "$req" version)" "$(jget "$req" package)" "$(jget "$req" sha256)" ;;
        rollback)      do_rollback_request "$rid" "$(jget "$req" backup_id)" ;;
        delete_backup) do_delete_backup "$rid" "$(jget "$req" backup_id)" ;;
        *) logline "忽略未知升级请求 action" ;;
      esac
    fi
  fi
  heartbeat
  sleep 5
done
