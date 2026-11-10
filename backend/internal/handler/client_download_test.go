package handler

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

func TestSafeDownloadName(t *testing.T) {
	ok := []string{"KSVPN-Setup-v0.4.3.exe", "KSVPN-macOS-Source-v1.0.0.zip", "KSVPN-macOS13-arm64-Full-v0.4.4.pkg", "配置服务器地址.ps1", "readme.md"}
	for _, n := range ok {
		if !safeDownloadName(n) {
			t.Errorf("应允许下载: %s", n)
		}
	}
	bad := []string{"", "../etc/passwd", "..", "a/b.exe", `..\secret.exe`, "x.exe/../../y", "evil.php", "noext", `q".exe`, "x\n.exe"}
	for _, n := range bad {
		if safeDownloadName(n) {
			t.Errorf("不应允许下载: %s", n)
		}
	}
}

func TestDownloadMetaMacOS(t *testing.T) {
	p, d := downloadMeta("KSVPN-macOS13-arm64-Full-v0.4.4.pkg")
	if p != "macOS" || !strings.Contains(d, "全量安装包") || !strings.Contains(d, "2.7.8") {
		t.Errorf("全量 pkg 描述不正确: %s / %s", p, d)
	}
	p, d = downloadMeta("KSVPN-macOS-Source-v1.0.0.zip")
	if p != "macOS" || !strings.Contains(d, "源码包") {
		t.Errorf("源码包描述不正确: %s / %s", p, d)
	}
}

func TestClientDownloads(t *testing.T) {
	oldEnabled, oldScope := db.GetSetting(setClientDownloadEnabled), db.GetSetting(setClientDownloadScope)
	db.SetSetting(setClientDownloadEnabled, "1")
	db.SetSetting(setClientDownloadScope, "public")
	t.Cleanup(func() {
		db.SetSetting(setClientDownloadEnabled, oldEnabled)
		db.SetSetting(setClientDownloadScope, oldScope)
	})

	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	dir := t.TempDir()
	customDownloadDir = filepath.Join(dir, "missing") // 不存在 → 回退内置目录
	builtinDownloadDir = dir
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })

	if err := os.WriteFile(filepath.Join(dir, "KSVPN-Setup-v0.4.3.exe"), []byte("MZ-fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hidden.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	ClientDownloads(w, httptest.NewRequest("GET", "/downloads", nil))
	body := w.Body.String()
	if !strings.Contains(body, "KSVPN-Setup-v0.4.3.exe") || !strings.Contains(body, "/downloads/KSVPN-Setup-v0.4.3.exe") {
		t.Errorf("下载页缺少安装包条目:\n%s", body)
	}
	if strings.Contains(body, "hidden.php") {
		t.Error("下载页不应列出非白名单文件")
	}
	if !strings.Contains(body, "首次使用必读") {
		t.Error("下载页缺少配置说明")
	}

	// 正常下载
	fd := httptest.NewRecorder()
	ClientDownloadFile(fd, httptest.NewRequest("GET", "/downloads/KSVPN-Setup-v0.4.3.exe", nil))
	if fd.Code != 200 || fd.Body.String() != "MZ-fake" {
		t.Errorf("文件下载失败: %d %q", fd.Code, fd.Body.String())
	}
	if !strings.Contains(fd.Header().Get("Content-Disposition"), "attachment") {
		t.Error("应作为附件下载")
	}

	// 路径穿越必须拒绝
	for _, p := range []string{"/downloads/../etc/passwd", "/downloads/hidden.php", "/downloads/..%2fetc%2fpasswd"} {
		bad := httptest.NewRecorder()
		ClientDownloadFile(bad, httptest.NewRequest("GET", p, nil))
		if bad.Code == 200 {
			t.Errorf("路径穿越未被拒绝: %s", p)
		}
	}
}
