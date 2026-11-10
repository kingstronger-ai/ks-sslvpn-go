// 在线升级：容器内只负责「版本检测 + 用户确认 + 状态展示」，
// 真正的备份/替换/重建/回滚由宿主机上的 deploy/upgrade-agent.sh 执行。
// 二者通过数据卷内的 request.json / status.ini / backups.txt / log.txt 通信，
// 因此不需要把 docker.sock 挂进容器，也不需要改动 docker-compose.yml。
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
	"sslvpn/internal/version"
)

const (
	defaultUpgradeDir = "/var/lib/sslvpn/upgrade"
	agentTTL          = 90 * time.Second
	maxUpgradeBody    = 1 << 16
)

var upgradeMu sync.Mutex

// upgradeDir 允许测试时用环境变量指向临时目录
func upgradeDir() string {
	if d := strings.TrimSpace(os.Getenv("SSLVPN_UPGRADE_DIR")); d != "" {
		return d
	}
	return defaultUpgradeDir
}

// updateSource version.json 地址：http(s):// 或容器内 file:// 路径
func updateSource() string { return strings.TrimSpace(os.Getenv("SSLVPN_UPDATE_URL")) }

type updateManifest struct {
	Version    string `json:"version"`
	ReleasedAt string `json:"released_at"`
	Notes      string `json:"notes"`
	Package    string `json:"package"` // http(s) URL 或宿主机上的包绝对路径
	Sha256     string `json:"sha256"`
	MinVersion string `json:"min_version"`
}

// fetchManifest 由服务端自行读取更新源；apply 时绝不采信前端传来的下载地址，
// 避免管理端被注入任意 URL 后让宿主机代理下载执行。
func fetchManifest() (*updateManifest, error) {
	u := updateSource()
	if u == "" {
		return nil, errors.New("未配置更新源：请在 docker-compose.yml 的 environment 加 SSLVPN_UPDATE_URL（指向 version.json）")
	}
	var data []byte
	var err error
	switch {
	case strings.HasPrefix(u, "file://"):
		data, err = os.ReadFile(strings.TrimPrefix(u, "file://"))
	case strings.HasPrefix(u, "http://"), strings.HasPrefix(u, "https://"):
		client := &http.Client{Timeout: 12 * time.Second}
		resp, e := client.Get(u)
		if e != nil {
			return nil, fmt.Errorf("获取更新源失败：%v", e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("更新源返回 HTTP %d", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	default:
		return nil, errors.New("更新源仅支持 http(s):// 或 file:// 地址")
	}
	if err != nil {
		return nil, fmt.Errorf("读取更新源失败：%v", err)
	}
	var m updateManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errors.New("更新源不是有效的 version.json")
	}
	m.Version = strings.TrimSpace(m.Version)
	if _, ok := version.Parse(m.Version); !ok {
		return nil, errors.New("更新源缺少合法的 version 字段")
	}
	m.Package = strings.TrimSpace(m.Package)
	m.Sha256 = strings.ToLower(strings.TrimSpace(m.Sha256))
	m.MinVersion = strings.TrimSpace(m.MinVersion)
	m.Notes = strings.TrimSpace(m.Notes)
	return &m, nil
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// readKV 解析宿主机代理写入的 status.ini（key=value，无转义）
func readKV(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}

func statusKV() map[string]string {
	return readKV(filepath.Join(upgradeDir(), "status.ini"))
}

func agentOnline() bool {
	t, err := time.Parse(time.RFC3339, statusKV()["heartbeat"])
	return err == nil && time.Since(t) < agentTTL
}

var busyPhases = map[string]bool{
	"backing_up": true, "downloading": true, "verifying": true, "extracting": true,
	"building": true, "healthcheck": true, "rolling_back": true, "pending": true,
}

func upgradeBusy() bool { return busyPhases[statusKV()["phase"]] }

// readBackups 每行：id|时间|版本|大小|备份目录
func readBackups() []map[string]string {
	out := []map[string]string{}
	b, err := os.ReadFile(filepath.Join(upgradeDir(), "backups.txt"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "|", 5)
		for len(p) < 5 {
			p = append(p, "")
		}
		out = append([]map[string]string{{
			"id": p[0], "time": p[1], "version": p[2], "size": p[3], "path": p[4],
		}}, out...)
	}
	return out
}

func writeRequest(fields map[string]string) error {
	dir := upgradeDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(fields)
	tmp := filepath.Join(dir, "request.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "request.json"))
}

func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxUpgradeBody)).Decode(v)
}

// UpgradeVersion 当前版本、更新源与代理在线状态
func UpgradeVersion(w http.ResponseWriter, r *http.Request) {
	st := statusKV()
	util.OK(w, map[string]any{
		"version":         version.Version,
		"update_url":      updateSource(),
		"agent_online":    agentOnline(),
		"agent_heartbeat": st["heartbeat"],
		"upgrade_dir":     upgradeDir(),
	})
}

// UpgradeCheck 检测新版本（只读，不触发任何升级动作）
func UpgradeCheck(w http.ResponseWriter, r *http.Request) {
	m, err := fetchManifest()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	newer := version.IsNewer(m.Version, version.Version)
	compatible := m.MinVersion == "" || version.Compare(version.Version, m.MinVersion) >= 0
	util.OK(w, map[string]any{
		"current":     version.Version,
		"latest":      m.Version,
		"has_update":  newer,
		"released_at": m.ReleasedAt,
		"notes":       m.Notes,
		"package":     m.Package,
		"sha256":      m.Sha256,
		"min_version": m.MinVersion,
		"compatible":  compatible,
		"ready":       newer && compatible && m.Package != "" && validSHA256(m.Sha256) && agentOnline(),
		"agent_online": agentOnline(),
	})
}

// UpgradeApply 用户点击「确认升级」后提交请求；代理会先完整备份再执行
func UpgradeApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(r, &req); err != nil || !req.Confirm {
		util.Fail(w, "请先确认升级操作")
		return
	}
	m, err := fetchManifest()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	if !version.IsNewer(m.Version, version.Version) {
		util.Fail(w, "当前已是最新版本 "+version.Version)
		return
	}
	if m.MinVersion != "" && version.Compare(version.Version, m.MinVersion) < 0 {
		util.Fail(w, fmt.Sprintf("当前版本 %s 低于本次升级所需最低版本 %s，请先逐版本升级", version.Version, m.MinVersion))
		return
	}
	if m.Package == "" || !validSHA256(m.Sha256) {
		util.Fail(w, "更新源缺少 package 或合法的 sha256，出于安全考虑已拒绝升级")
		return
	}
	if !agentOnline() {
		util.Fail(w, "宿主机升级代理未在线，请先在服务器部署 deploy/upgrade-agent.sh")
		return
	}
	upgradeMu.Lock()
	defer upgradeMu.Unlock()
	if upgradeBusy() {
		util.Fail(w, "已有升级/回滚任务进行中，请等待完成")
		return
	}
	id := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := writeRequest(map[string]string{
		"id":           id,
		"action":       "upgrade",
		"version":      m.Version,
		"package":      m.Package,
		"sha256":       m.Sha256,
		"requested_at": time.Now().Format(time.RFC3339),
	}); err != nil {
		util.Fail(w, "写入升级请求失败："+err.Error())
		return
	}
	db.Syslog("admin", "发起在线升级", version.Version+" -> "+m.Version, clientIP(r))
	util.OKMsg(w, "升级请求已提交，代理将先自动备份再执行", map[string]any{
		"request_id": id, "version": m.Version,
	})
}

// UpgradeStatus 供前端轮询：阶段/进度/结果 + 备份清单
func UpgradeStatus(w http.ResponseWriter, r *http.Request) {
	st := statusKV()
	progress, _ := strconv.Atoi(st["progress"])
	util.OK(w, map[string]any{
		"current":        version.Version,
		"phase":          st["phase"],
		"progress":       progress,
		"message":        st["message"],
		"request_id":     st["request_id"],
		"backup_id":      st["backup_id"],
		"result_version": st["result_version"],
		"heartbeat":      st["heartbeat"],
		"agent_online":   agentOnline(),
		"backups":        readBackups(),
	})
}

// UpgradeBackups 升级前自动生成的备份清单（可回滚）
func UpgradeBackups(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]any{"list": readBackups()})
}

// UpgradeLog 代理执行日志（纯文本），前端只做展示
func UpgradeLog(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(filepath.Join(upgradeDir(), "log.txt"))
	if err != nil {
		util.OK(w, map[string]any{"log": ""})
		return
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	util.OK(w, map[string]any{"log": strings.Join(lines, "\n")})
}

// UpgradeRollback 一键回滚到某次升级前的完整备份
func UpgradeRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BackupID string `json:"backup_id"`
		Confirm  bool   `json:"confirm"`
	}
	if err := decodeBody(r, &req); err != nil || !req.Confirm || strings.TrimSpace(req.BackupID) == "" {
		util.Fail(w, "请确认要回滚的备份")
		return
	}
	id := strings.TrimSpace(req.BackupID)
	exists := false
	for _, b := range readBackups() {
		if b["id"] == id {
			exists = true
			break
		}
	}
	if !exists {
		util.Fail(w, "找不到该备份，可能已被清理")
		return
	}
	if !agentOnline() {
		util.Fail(w, "宿主机升级代理未在线，无法回滚")
		return
	}
	upgradeMu.Lock()
	defer upgradeMu.Unlock()
	if upgradeBusy() {
		util.Fail(w, "已有升级/回滚任务进行中")
		return
	}
	rid := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := writeRequest(map[string]string{
		"id":           rid,
		"action":       "rollback",
		"backup_id":    id,
		"requested_at": time.Now().Format(time.RFC3339),
	}); err != nil {
		util.Fail(w, "写入回滚请求失败："+err.Error())
		return
	}
	db.Syslog("admin", "发起版本回滚", id, clientIP(r))
	util.OKMsg(w, "回滚请求已提交", map[string]any{"request_id": rid, "backup_id": id})
}
