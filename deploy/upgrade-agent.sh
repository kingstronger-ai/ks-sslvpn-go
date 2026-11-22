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
# 备份包内含 CA 私钥、VPN 明文口令与初始管理员口令，工作目录按密钥级资产处理：
# 全局 umask 077 保证新建的备份包/状态/日志文件均为 0600、目录为 0700。
umask 077

APP_DIR="${APP_DIR:-/opt/ks-sslvpn-go}"
CONTAINER="${CONTAINER:-ks-sslvpn-go}"
WORK="${WORK:-/opt/sslvpn-upgrade}"
VOL_DIR="/var/lib/sslvpn/upgrade"
HEALTH_URL="${HEALTH_URL:-https://127.0.0.1:58443/healthz}"
BACKUP_IMG="${BACKUP_IMG:-}"   # 留空则用当前运行镜像（自带 tar，无需联网拉 alpine）
CUR_ID=""
CUR_BID=""

mkdir -p "$WORK/backups" "$WORK/packages"
# 修正旧部署遗留的宽松权限（umask 只影响新建文件，旧产物需显式收紧）
chmod 700 "$WORK" "$WORK/backups" "$WORK/packages" 2>/dev/null || true
for _f in status.ini backups.txt upgrade.log log.txt; do
  [ -e "$WORK/$_f" ] && chmod 600 "$WORK/$_f" 2>/dev/null || true
done
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
    img_repo="${img%%@*}"; img_repo="${img_repo%%:*}"
    docker tag "$img" "${img_repo}:rollback-$bid" >/dev/null 2>&1 || true
    echo "$img" > "$bk/image.txt"
  fi

  # 备份含 CA 私钥/明文口令，收紧权限；数据卷快照由容器内进程创建，不继承宿主机 umask，需显式覆盖
  chmod 700 "$bk" 2>/dev/null || true
  chmod -R go-rwx "$bk" 2>/dev/null || true
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

# 备份/失败现场保留上限：备份最近 5 份、失败现场最近 5 个，超出清理最旧（F-10）
MAX_KEEP=5

# valid_backup_id：与 do_delete_backup 同一白名单（F-10）。
# 仅允许 bk- 前缀 + [A-Za-z0-9._-]，禁止 ".." 与 "/"，杜绝经 rollback 路径穿越/DoS。
valid_backup_id() {
  case "$1" in
    bk-[A-Za-z0-9._-]*) : ;;
    *) return 1 ;;
  esac
  case "$1" in
    *..*|*/*) return 1 ;;
  esac
  return 0
}

# prune_old_backups：backups.txt 追加式（末行最新），超出 MAX_KEEP 清理最旧
prune_old_backups() {
  local total extra old d
  total="$(grep -c . "$WORK/backups.txt" 2>/dev/null || echo 0)"
  [ "$total" -gt "$MAX_KEEP" ] || return 0
  extra=$((total - MAX_KEEP))
  head -n "$extra" "$WORK/backups.txt" | cut -d'|' -f1 | while IFS= read -r old; do
    [ -n "$old" ] || continue
    d="$WORK/backups/$old"
    if [ -d "$d" ]; then rm -rf -- "$d"; fi
    logline "清理最旧备份 $old（最多保留 $MAX_KEEP 份）"
  done
  tail -n "$MAX_KEEP" "$WORK/backups.txt" > "$WORK/backups.txt.tmp" \
    && mv -f "$WORK/backups.txt.tmp" "$WORK/backups.txt"
  put "$WORK/backups.txt" backups.txt
}

# prune_failed_dirs：failed-* 现场目录按 mtime 保留最近 MAX_KEEP 个
prune_failed_dirs() {
  local n=0 d
  for d in $(ls -1dt "$APP_DIR".failed-* 2>/dev/null); do
    n=$((n + 1))
    if [ "$n" -gt "$MAX_KEEP" ]; then
      rm -rf -- "$d"
      logline "清理最旧失败现场 $d（最多保留 $MAX_KEEP 个）"
    fi
  done
}

do_rollback() {
  local bid="$1" bk="$WORK/backups/$bid" oldver
  # F-10：backup_id 白名单校验（此前 rollback 直接透传，可被 request.json 注入 ../../ 触发
  # 「先停服后失败」的稳定 DoS）
  if ! valid_backup_id "$bid"; then
    logline "备份 ID 不合法，已拒绝回滚: $bid"
    return 1
  fi
  [ -d "$bk" ] || { logline "备份 $bid 不存在，无法回滚"; return 1; }
  oldver="$(tr -d '\r\n' < "$bk/VERSION" 2>/dev/null || echo unknown)"
  set_status "rolling_back" 70 "正在回滚到版本 $oldver（含数据卷恢复）"
  logline "开始回滚到备份 $bid（版本 $oldver）"

  (cd "$APP_DIR" && docker compose stop) >/dev/null 2>&1 || true
  # 目录改名保留失败现场；新解压出的目录仍叫 ks-sslvpn-go，compose 项目名/卷归属不变
  mv "$APP_DIR" "$APP_DIR.failed-$bid" || { logline "保留失败现场失败"; return 1; }
  tar -xzf "$bk/src.tar.gz" -C "$(dirname "$APP_DIR")" || { logline "恢复源码失败"; return 1; }
  cp -a "$bk/docker-compose.yml" "$APP_DIR/docker-compose.yml"

  if ! restore_volumes "$bk"; then
    logline "警告：数据卷恢复有错误，请检查 $WORK/upgrade.log"
  fi
  img_repo="$(cat "$bk/image.txt" 2>/dev/null || true)"
  img_repo="${img_repo%%@*}"; img_repo="${img_repo%%:*}"
  if [ -f "$bk/image.txt" ] && docker image inspect "${img_repo}:rollback-$bid" >/dev/null 2>&1; then
    docker tag "${img_repo}:rollback-$bid" "$(cat "$bk/image.txt")" >/dev/null 2>&1 || true
    (cd "$APP_DIR" && docker compose up -d) > "$WORK/rollback.log" 2>&1
  else
    (cd "$APP_DIR" && docker compose up -d --build) > "$WORK/rollback.log" 2>&1
  fi
  if [ $? -ne 0 ]; then logline "回滚时启动容器失败，详见 $WORK/rollback.log"; return 1; fi
  if ! health_wait; then logline "回滚后健康检查未通过，详见 $WORK/rollback.log"; return 1; fi
  logline "回滚完成，当前版本 $oldver"
  prune_old_backups
  prune_failed_dirs
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
# F-11：升级包主机允许列表（与后端 manifest 白名单保持一致）。
# 仅接受官方发布域名；重定向链由 curl --proto-redir '=https' 强制全程 https。
pkg_host_allowed() {
  case "$1" in
    gitee.com|github.com|objects.githubusercontent.com|raw.githubusercontent.com) return 0 ;;
    *) return 1 ;;
  esac
}

# url_host 提取 https URL 的主机名
url_host() {
  printf '%s' "$1" | sed -E 's#^https://([^/?#]+).*#\1#'
}

do_upgrade() {
  local rid="$1" ver="$2" pkg="$3" sha="$4" fallback_pkg="${5:-}"
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

  # ② 取包：主源失败自动切备用源；每个源下载后立即校验 sha256，
  #    校验不通过的包直接丢弃并切下一个源（被劫持的源无法污染升级）。
  #    仅 https 下载（明文 http 可被中间人替换为恶意包 -> 宿主机 root），
  #    否则视为宿主机本地绝对路径。rid 由容器以 UnixNano 生成，此处再白名单校验防路径注入。
  set_status "downloading" 25 "正在获取升级包"
  case "$rid" in
    ''|*[!0-9]*) set_status "failed" 25 "升级请求 ID 不合法，已中止"; return 1 ;;
  esac
  if [[ "$pkg" == http://* ]]; then
    set_status "failed" 25 "已拒绝明文 http 升级包（不安全），请使用 https://"
    return 1
  elif [[ "$pkg" == https://* ]]; then
    localpkg="$WORK/packages/$rid.tar.gz"
    local src downloaded=0
    for src in "$pkg" "$fallback_pkg"; do
      [ -z "$src" ] && continue
      [[ "$src" == http://* ]] && { logline "已拒绝明文 http 源: $src"; continue; }
      [[ "$src" != https://* ]] && { logline "备用源非 https，跳过: $src"; continue; }
      # F-11：包主机白名单（manifest 无签名前提下收窄“任意 https 源”的攻击面）
      src_host="$(url_host "$src")"
      if ! pkg_host_allowed "$src_host"; then
        logline "已拒绝非白名单包主机: $src_host（仅允许 gitee.com/github.com 及其发布域）"
        continue
      fi
      # F-11：--proto/--proto-redir 全程 https（禁降级、禁内网 http 重定向），
      # --max-filesize 2GB 防恶意源撑爆磁盘，--max-redirs 限制重定向链。
      if curl -fL --proto '=https' --proto-redir '=https' --max-redirs 5 \
           --max-filesize 2147483648 --connect-timeout 10 --retry 2 --max-time 1800 \
           -o "$localpkg" "$src"; then
        if echo "$sha  $localpkg" | sha256sum -c - >/dev/null 2>&1; then
          logline "升级包下载且校验通过: $src"
          downloaded=1
          break
        fi
        logline "升级包 sha256 不匹配，丢弃并切换源: $src"
        rm -f "$localpkg"   # 防止残留包被后续步骤误用
      else
        logline "升级包下载失败，切换源: $src"
        rm -f "$localpkg"
      fi
    done
    if [ "$downloaded" -ne 1 ]; then
      set_status "failed" 25 "主源与备用源均下载失败或校验未通过，已中止（源码未改动）"
      return 1
    fi
  else
    localpkg="$pkg"
    # 本地路径必须是绝对路径，且不得含 .. 分段
    case "$localpkg" in
      /*) ;;
      *) set_status "failed" 25 "升级包路径必须是绝对路径，已中止"; return 1 ;;
    esac
    case "/$localpkg/" in
      *"/../"*) set_status "failed" 25 "升级包路径含 .. 已中止"; return 1 ;;
    esac
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
  # 成员路径穿越检查：禁止绝对路径 / .. 分段 / 顶层目录不一致的成员。
  # 恶意包可借 ../ 写出 APP_DIR 之外（如 systemd unit、cron、agent 自身）获取 root。
  if ! tar -tzf "$localpkg" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    :
  else
    set_status "failed" 40 "升级包含非法路径成员（绝对路径或 ..），已中止（源码未改动）"
    return 1
  fi
  bad_member="$(tar -tzf "$localpkg" | awk -F/ -v t="$top" '$1 != t {print; exit}')"
  if [ -n "$bad_member" ]; then
    set_status "failed" 40 "升级包含越界成员 $bad_member（应全部位于 $top/），已中止"
    return 1
  fi
  # 符号链接/硬链接成员检查（CWE-59）：恶意包可先放一个指向 /etc/cron.d 的符号链接，
  # 再放一个经该链接路径的普通文件，tar 顺序解压时会写穿到 APP_DIR 之外并以 root 落盘。
  # 正版发布包全部是普通文件/目录，不含任何链接成员，直接拒绝即可。
  if tar -tvzf "$localpkg" 2>/dev/null | awk '{p=substr($1,1,1); if (p=="l" || index($0,"link to")>0) {print; exit}}' | grep -q .; then
    link_member="$(tar -tvzf "$localpkg" 2>/dev/null | awk '{p=substr($1,1,1); if (p=="l" || index($0,"link to")>0) {print; exit}}')"
    set_status "failed" 40 "升级包含符号链接/硬链接成员 $link_member，已中止（源码未改动）"
    return 1
  fi
  tar -xzOf "$localpkg" "$top/docker-compose.yml" > "$WORK/backups/$bid/compose.new.yml" 2>/dev/null || true

  # ④ 原地覆盖解压（tar 只覆盖不删除，保留现网 compose 的端口/环境自定义）
  set_status "extracting" 55 "正在原地覆盖源码"
  if ! tar -xzf --no-same-owner --no-same-permissions "$localpkg" -C "$(dirname "$APP_DIR")"; then
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

  # ⑦ 安全：不再从升级包内替换/重启升级代理自身。
  #    以 root 运行的守护进程若可被一次普通升级替换，等于把宿主机 root 交给了更新源。
  #    升级代理脚本变更改为随安装文档人工部署，不经应用升级包自动生效。
  if [ -f "$APP_DIR/deploy/upgrade-agent.sh" ] && ! cmp -s "$APP_DIR/deploy/upgrade-agent.sh" "$WORK/upgrade-agent.sh"; then
    logline "提示：升级包内 upgrade-agent.sh 与运行版本不同；出于安全不再自动替换代理，请按新版本安装文档人工更新 $WORK/upgrade-agent.sh"
  fi

  set_status "done" 100 "升级完成，当前版本 $newver；升级前备份 $bid 可随时回滚" "$newver"
  logline "升级完成：$newver（备份 $bid）"
  prune_old_backups
  prune_failed_dirs
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
        upgrade)       do_upgrade "$rid" "$(jget "$req" version)" "$(jget "$req" package)" "$(jget "$req" sha256)" "$(jget "$req" package_fallback)" ;;
        rollback)      do_rollback_request "$rid" "$(jget "$req" backup_id)" ;;
        delete_backup) do_delete_backup "$rid" "$(jget "$req" backup_id)" ;;
        *) logline "忽略未知升级请求 action" ;;
      esac
    fi
  fi
  heartbeat
  sleep 5
done
