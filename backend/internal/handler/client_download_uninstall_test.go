package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/middleware"
)

// 卸载工具的分类、权限与排序规则。
func TestUninstallToolClassification(t *testing.T) {
	for _, c := range []struct {
		name, platform string
	}{
		{winUninstallName, "windows"},
		{macUninstallName, "macos"},
	} {
		if !isUninstallTool(c.name) {
			t.Errorf("%q 应识别为卸载工具", c.name)
		}
		if !adminOnlyDownload(c.name) {
			t.Errorf("%q 应仅管理员可见", c.name)
		}
		if got := uninstallPlatform(c.name); got != c.platform {
			t.Errorf("%q 平台 = %q，期望 %q", c.name, got, c.platform)
		}
		// 关键：卸载包不能与 macOS 源码包共用 macos-source 键，
		// 否则同平台版本去重会把其中一个挤掉。
		if got := downloadPlatformKey(c.name); got != "" {
			t.Errorf("%q 不应参与平台归类，得到 %q", c.name, got)
		}
		if got := downloadItemGroup(c.name); got != c.platform {
			t.Errorf("%q 分组 = %q，期望 %q", c.name, got, c.platform)
		}
		if got := downloadItemRank(c.name); got != 3 {
			t.Errorf("%q 排序权重 = %d，期望 3（排最后）", c.name, got)
		}
		platform, desc := downloadMeta(c.name)
		if !strings.Contains(desc, "卸载") || !strings.Contains(desc, "仅管理员") {
			t.Errorf("%q 说明应标注卸载与权限：%q", c.name, desc)
		}
		if platform != "Windows" && platform != "macOS" {
			t.Errorf("%q 平台标签异常：%q", c.name, platform)
		}
	}

	for _, name := range []string{
		"KSVPN-Setup-v0.4.3.exe",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
		"configure-gateway.ps1",
	} {
		if isUninstallTool(name) || adminOnlyDownload(name) {
			t.Errorf("%q 不应被当作仅管理员可见的卸载工具", name)
		}
	}
	if !adminOnlyDownload("KSVPN-macOS-Source-v1.0.0.zip") {
		t.Error("macOS 源码包仍应仅管理员可见")
	}
}

// 三个 .zip（源码包 + 两个卸载包）必须同时出现在列表里，且权限标记正确。
func TestClientDownloadItemsUninstallTools(t *testing.T) {
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	base := t.TempDir()
	custom, builtin := filepath.Join(base, "custom"), filepath.Join(base, "builtin")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(builtin, 0o755); err != nil {
		t.Fatal(err)
	}
	customDownloadDir, builtinDownloadDir = custom, builtin
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })

	for _, n := range []string{
		"KSVPN-Setup-v0.4.3.exe",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
		"KSVPN-macOS-Source-v1.0.0.zip",
		winUninstallName,
		macUninstallName,
		"configure-gateway.ps1",
	} {
		if err := os.WriteFile(filepath.Join(builtin, n), []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	items := clientDownloadItems()
	got := map[string]bool{}
	adminOnly := map[string]bool{}
	for _, it := range items {
		got[it.Name] = true
		adminOnly[it.Name] = it.AdminOnly
	}
	for _, n := range []string{
		"KSVPN-Setup-v0.4.3.exe", "KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
		"KSVPN-macOS-Source-v1.0.0.zip", winUninstallName, macUninstallName,
	} {
		if !got[n] {
			t.Errorf("%q 应出现在下载列表：%v", n, got)
		}
	}
	for _, n := range []string{"KSVPN-macOS-Source-v1.0.0.zip", winUninstallName, macUninstallName} {
		if !adminOnly[n] {
			t.Errorf("%q 应标记为仅管理员可见", n)
		}
	}
	for _, n := range []string{"KSVPN-Setup-v0.4.3.exe", "KSVPN-macOS13-arm64-Full-v0.5.0.pkg"} {
		if adminOnly[n] {
			t.Errorf("%q 不应标记为仅管理员可见", n)
		}
	}
	// 卸载工具不应被当作安装包随账号邮件群发
	atts := clientInstallerAtts("windows", "macos")
	for _, a := range atts {
		if isUninstallTool(a.Name) || strings.Contains(a.Name, "Source") {
			t.Errorf("账号邮件不应附带卸载工具或源码包：%q", a.Name)
		}
	}
}

// 下载页：普通用户看不到卸载工具，管理员可见；直链对普通用户 403。
func TestUninstallToolAdminOnlyGate(t *testing.T) {
	oldEnabled, oldScope := db.GetSetting(setClientDownloadEnabled), db.GetSetting(setClientDownloadScope)
	db.SetSetting(setClientDownloadEnabled, "1")
	db.SetSetting(setClientDownloadScope, "public")
	t.Cleanup(func() {
		db.SetSetting(setClientDownloadEnabled, oldEnabled)
		db.SetSetting(setClientDownloadScope, oldScope)
	})

	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	dir := t.TempDir()
	customDownloadDir = filepath.Join(dir, "missing")
	builtinDownloadDir = dir
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })

	for _, n := range []string{"KSVPN-Setup-v0.4.3.exe", winUninstallName, macUninstallName} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	middleware.InitSession("test-uninstall-secret")
	adminCookie := &http.Cookie{Name: "sslvpn_session", Value: middleware.MakeSession()}
	const winUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"

	render := func(admin bool) string {
		r := httptest.NewRequest("GET", "/downloads", nil)
		r.Header.Set("User-Agent", winUA)
		if admin {
			r.AddCookie(adminCookie)
		}
		w := httptest.NewRecorder()
		ClientDownloads(w, r)
		if w.Code != 200 {
			t.Fatalf("下载页返回 %d", w.Code)
		}
		return w.Body.String()
	}

	anon := render(false)
	if strings.Contains(anon, "/downloads/"+winUninstallName) || strings.Contains(anon, "/downloads/"+macUninstallName) {
		t.Error("普通用户不应在下载页看到卸载工具")
	}
	if !strings.Contains(anon, "/downloads/KSVPN-Setup-v0.4.3.exe") {
		t.Error("普通用户仍应看到 Windows 安装包")
	}
	admin := render(true)
	if !strings.Contains(admin, "/downloads/"+winUninstallName) {
		t.Error("管理员应能在下载页看到 Windows 卸载工具")
	}

	// 直链门禁：普通用户 403，管理员 200
	link := func(admin bool) int {
		r := httptest.NewRequest("GET", "/downloads/"+winUninstallName, nil)
		if admin {
			r.AddCookie(adminCookie)
		}
		w := httptest.NewRecorder()
		ClientDownloadFile(w, r)
		return w.Code
	}
	if code := link(false); code != http.StatusForbidden {
		t.Errorf("普通用户直链应 403，得到 %d", code)
	}
	if code := link(true); code != http.StatusOK {
		t.Errorf("管理员直链应可下载，得到 %d", code)
	}
}

// 邮件正文：卸载工具附带完整教程，且不放普通用户看不到的下载页链接。
func TestUninstallMailContent(t *testing.T) {
	winSubject, winBody := clientDownloadMailCompose(winUninstallName, 8559, "https://vpn.example.com:58443")
	if !strings.Contains(winSubject, "卸载工具") {
		t.Errorf("Windows 卸载邮件标题应含「卸载工具」：%q", winSubject)
	}
	for _, kw := range []string{
		"Uninstall-KSVPN.cmd", "KSVPN-uninstall.ps1", "%LOCALAPPDATA%",
		"应用和功能", "OpenVPN", "手动卸载", "卸载说明.txt",
	} {
		if !strings.Contains(winBody, kw) {
			t.Errorf("Windows 卸载教程缺少 %q", kw)
		}
	}
	if strings.Contains(winBody, "/downloads") {
		t.Error("卸载邮件不应放下载页链接（普通用户看不到管理员专属文件）")
	}

	macSubject, macBody := clientDownloadMailCompose(macUninstallName, 6966, "https://vpn.example.com:58443")
	if !strings.Contains(macSubject, "卸载工具") {
		t.Errorf("macOS 卸载邮件标题应含「卸载工具」：%q", macSubject)
	}
	for _, kw := range []string{
		"KSVPN-Uninstall.command", "pkgutil --forget", "LaunchDaemon",
		"PrivilegedHelperTools", "管理员密码", "Homebrew", "手动卸载",
	} {
		if !strings.Contains(macBody, kw) {
			t.Errorf("macOS 卸载教程缺少 %q", kw)
		}
	}
	if strings.Contains(macBody, "%LOCALAPPDATA%") {
		t.Error("macOS 教程不应混入 Windows 路径")
	}

	// 普通安装包的邮件仍保持原模板与下载页链接
	subject, body := clientDownloadMailCompose("KSVPN-Setup-v0.4.3.exe", 1024, "https://vpn.example.com:58443")
	if strings.Contains(subject, "卸载工具") || !strings.Contains(body, "/downloads") {
		t.Errorf("安装包邮件不应被卸载模板污染：subject=%q body=%q", subject, body)
	}
	if strings.Contains(body, "Uninstall-KSVPN.cmd") {
		t.Error("安装包邮件不应混入卸载步骤")
	}
}
