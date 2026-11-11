package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func setupUpgradeEnv(t *testing.T, version, sha string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SSLVPN_UPGRADE_DIR", dir)
	mf := filepath.Join(dir, "version.json")
	body := `{"version":"` + version + `","released_at":"2026-11-10","notes":"test",` +
		`"package":"/opt/sslvpn-upgrade/packages/test.tar.gz","sha256":"` + sha + `","min_version":"1.1.0"}`
	if err := os.WriteFile(mf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSLVPN_UPDATE_URL", "file://"+mf)
	st := "phase=idle\nprogress=0\nmessage=就绪\nheartbeat=" + time.Now().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "status.ini"), []byte(st), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type upgradeResp struct {
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Data map[string]any `json:"data"`
}

func callUpgrade(t *testing.T, fn func(w http.ResponseWriter, r *http.Request), method, body string) upgradeResp {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/upgrade", strings.NewReader(body))
	w := httptest.NewRecorder()
	fn(w, req)
	var out upgradeResp
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("响应不是 JSON：%v / %s", err, w.Body.String())
	}
	return out
}

func TestUpgradeVersionAndCheck(t *testing.T) {
	setupUpgradeEnv(t, "9.9.9", testSHA)
	v := callUpgrade(t, UpgradeVersion, "GET", "")
	if v.Code != 1 || v.Data["version"] == "" || v.Data["agent_online"] != true {
		t.Fatalf("版本信息异常：%+v", v)
	}
	c := callUpgrade(t, UpgradeCheck, "GET", "")
	if c.Code != 1 || c.Data["has_update"] != true || c.Data["ready"] != true {
		t.Fatalf("应检测到新版本且可升级：%+v", c)
	}
}

func TestUpgradeCheckNoDowngrade(t *testing.T) {
	setupUpgradeEnv(t, "0.0.1", testSHA)
	c := callUpgrade(t, UpgradeCheck, "GET", "")
	if c.Data["has_update"] != false {
		t.Fatalf("不应把旧版本当作更新：%+v", c)
	}
}

func TestUpgradeApplyRejectsBadSHA(t *testing.T) {
	dir := setupUpgradeEnv(t, "9.9.9", "not-a-sha")
	r := callUpgrade(t, UpgradeApply, "POST", `{"confirm":true}`)
	if r.Code == 1 {
		t.Fatal("sha256 非法时不应放行")
	}
	if _, err := os.Stat(filepath.Join(dir, "request.json")); !os.IsNotExist(err) {
		t.Fatal("校验失败时不应写入升级请求")
	}
}

// 安全：apply 只接受 confirm，下载地址与 sha256 一律由服务端从更新源读取，
// 前端请求体里夹带的 package 不得进入宿主机代理。
func TestUpgradeApplyIgnoresClientPackage(t *testing.T) {
	dir := setupUpgradeEnv(t, "9.9.9", testSHA)
	r := callUpgrade(t, UpgradeApply, "POST",
		`{"confirm":true,"package":"http://evil.example/x.tar.gz","sha256":"`+testSHA+`"}`)
	if r.Code != 1 {
		t.Fatalf("提交升级失败：%+v", r)
	}
	b, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]string
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	if req["action"] != "upgrade" || req["version"] != "9.9.9" {
		t.Fatalf("请求内容异常：%s", b)
	}
	if strings.Contains(req["package"], "evil.example") || req["package"] != "/opt/sslvpn-upgrade/packages/test.tar.gz" {
		t.Fatalf("前端注入的下载地址被采信：%s", b)
	}
}

func TestUpgradeRollbackRejectsUnknownBackup(t *testing.T) {
	setupUpgradeEnv(t, "9.9.9", testSHA)
	r := callUpgrade(t, UpgradeRollback, "POST", `{"confirm":true,"backup_id":"not-exist"}`)
	if r.Code == 1 {
		t.Fatal("不存在的备份不应允许回滚")
	}
}

func TestReadBackupsNewestFirst(t *testing.T) {
	dir := setupUpgradeEnv(t, "9.9.9", testSHA)
	content := "bk-a|2026-11-10 10:00:00|1.1.0|10M|/x/a\nbk-b|2026-11-10 11:00:00|1.1.0|10M|/x/b\n"
	if err := os.WriteFile(filepath.Join(dir, "backups.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	list := readBackups()
	if len(list) != 2 || list[0]["id"] != "bk-b" || list[1]["id"] != "bk-a" {
		t.Fatalf("备份列表应按时间倒序：%+v", list)
	}
	if list[0]["protected"] != "1" || list[1]["protected"] != "1" {
		t.Fatalf("全部不足 2 份时应都受保护：%+v", list)
	}
}

func TestReadBackupsProtectsNewestTwo(t *testing.T) {
	dir := setupUpgradeEnv(t, "9.9.9", testSHA)
	content := "bk-a|t1|1.1.0|10M|/x/a\nbk-b|t2|1.1.0|10M|/x/b\nbk-c|t3|1.1.0|10M|/x/c\n"
	if err := os.WriteFile(filepath.Join(dir, "backups.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	list := readBackups()
	if list[0]["id"] != "bk-c" || list[0]["protected"] != "1" ||
		list[1]["id"] != "bk-b" || list[1]["protected"] != "1" ||
		list[2]["id"] != "bk-a" || list[2]["protected"] != "" {
		t.Fatalf("应仅最近 2 份受保护：%+v", list)
	}
}

func TestUpgradeBackupDeleteProtectedAndUnknown(t *testing.T) {
	dir := setupUpgradeEnv(t, "9.9.9", testSHA)
	content := "bk-a|t1|1.1.0|10M|/x/a\nbk-b|t2|1.1.0|10M|/x/b\nbk-c|t3|1.1.0|10M|/x/c\n"
	if err := os.WriteFile(filepath.Join(dir, "backups.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"bk-c", "bk-b"} {
		if r := callUpgrade(t, UpgradeBackupDelete, "POST", `{"confirm":true,"backup_id":"`+id+`"}`); r.Code == 1 {
			t.Fatalf("最近的备份 %s 不应允许删除", id)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "request.json")); !os.IsNotExist(err) {
		t.Fatal("被拒绝时不应写入删除请求")
	}
	if r := callUpgrade(t, UpgradeBackupDelete, "POST", `{"confirm":true,"backup_id":"bk-zzz"}`); r.Code == 1 {
		t.Fatal("不存在的备份不应允许删除")
	}
	r := callUpgrade(t, UpgradeBackupDelete, "POST", `{"confirm":true,"backup_id":"bk-a"}`)
	if r.Code != 1 {
		t.Fatalf("较早的备份应允许删除：%+v", r)
	}
	b, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]string
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	if req["action"] != "delete_backup" || req["backup_id"] != "bk-a" {
		t.Fatalf("删除请求内容异常：%s", b)
	}
}

func TestUpgradeBackupDeleteRequiresConfirm(t *testing.T) {
	setupUpgradeEnv(t, "9.9.9", testSHA)
	if r := callUpgrade(t, UpgradeBackupDelete, "POST", `{"backup_id":"bk-a"}`); r.Code == 1 {
		t.Fatal("缺少 confirm 不应放行")
	}
}
