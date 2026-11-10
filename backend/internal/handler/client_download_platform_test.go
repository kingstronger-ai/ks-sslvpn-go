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

func TestClientPlatform(t *testing.T) {
	cases := []struct {
		name, ua, query, want string
	}{
		{"Windows Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "", "windows"},
		{"Windows Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0.0.0", "", "windows"},
		{"macOS Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15", "", "macos"},
		{"macOS Chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "", "macos"},
		{"iPadOS 伪装 Macintosh", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Version/17.0 Mobile/15E148 Safari/604.1", "", "other"},
		{"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile/15E148 Safari/604.1", "", "other"},
		{"Android", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36", "", "other"},
		{"Linux 桌面", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/121.0", "", "other"},
		{"无 UA", "", "", "other"},
		{"手动切 macOS", "Mozilla/5.0 (Windows NT 10.0)", "?platform=macos", "macos"},
		{"手动切 Windows", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "?platform=windows", "windows"},
		{"手动查看全部", "Mozilla/5.0 (Windows NT 10.0)", "?platform=all", "other"},
		{"别名 win", "", "?platform=win", "windows"},
		{"未知参数按 UA", "Mozilla/5.0 (Windows NT 10.0)", "?platform=evil", "windows"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/downloads"+c.query, nil)
		if c.ua != "" {
			r.Header.Set("User-Agent", c.ua)
		}
		if got := clientPlatform(r); got != c.want {
			t.Errorf("%s: 得到 %q，期望 %q", c.name, got, c.want)
		}
	}
}

func TestDownloadItemGroup(t *testing.T) {
	cases := map[string]string{
		"KSVPN-Setup-v0.4.3.exe":              "windows",
		"MyClient.msi":                        "windows",
		"KSVPN-macOS13-arm64-Full-v0.4.4.pkg": "macos",
		"MyClient.dmg":                        "macos",
		"KSVPN-macOS-Source-v1.0.0.zip":       "macos",
		"configure-gateway.ps1":               "windows",
		"readme.md":                           "common",
		"notes.txt":                           "common",
	}
	for name, want := range cases {
		if got := downloadItemGroup(name); got != want {
			t.Errorf("%s: 分组 %q，期望 %q", name, got, want)
		}
	}
}

// 下载页按访问系统筛选：主区只放本平台，其它平台收进折叠区，说明文字同步裁剪。
func TestClientDownloadsPlatformFilter(t *testing.T) {
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

	const exe = "KSVPN-Setup-v0.4.3.exe"
	const pkg = "KSVPN-macOS13-arm64-Full-v0.4.4.pkg"
	const src = "KSVPN-macOS-Source-v1.0.0.zip"
	const ps1 = "configure-gateway.ps1"
	for _, n := range []string{exe, pkg, src, ps1} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	middleware.InitSession("test-download-secret")
	adminCookie := &http.Cookie{Name: "sslvpn_session", Value: middleware.MakeSession()}
	render := func(ua, query string) string {
		r := httptest.NewRequest("GET", "/downloads"+query, nil)
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		w := httptest.NewRecorder()
		ClientDownloads(w, r)
		if w.Code != 200 {
			t.Fatalf("下载页返回 %d", w.Code)
		}
		return w.Body.String()
	}
	renderAdmin := func(ua, query string) string {
		r := httptest.NewRequest("GET", "/downloads"+query, nil)
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		r.AddCookie(adminCookie)
		w := httptest.NewRecorder()
		ClientDownloads(w, r)
		if w.Code != 200 {
			t.Fatalf("下载页返回 %d", w.Code)
		}
		return w.Body.String()
	}
	mainArea := func(body string) string {
		if i := strings.Index(body, `<details class="other">`); i >= 0 {
			return body[:i]
		}
		return body
	}
	const winUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
	const macUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15"

	win := render(winUA, "")
	if !strings.Contains(mainArea(win), "/downloads/"+exe) || !strings.Contains(mainArea(win), "/downloads/"+ps1) {
		t.Error("Windows 主区应包含 exe 与网关脚本")
	}
	if strings.Contains(mainArea(win), "/downloads/"+pkg) || strings.Contains(mainArea(win), "/downloads/"+src) {
		t.Error("Windows 主区不应出现 macOS 安装包")
	}
	if !strings.Contains(win, `<details class="other">`) || !strings.Contains(win, "我是 macOS 用户") {
		t.Error("Windows 页应提供其它平台折叠区与切换入口")
	}
	if strings.Contains(win, "<b>macOS</b>（Apple Silicon") || strings.Contains(win, "⚠ 换服务器请注意") {
		t.Error("Windows 页不应显示 macOS 使用说明")
	}

	mac := render(macUA, "")
	if !strings.Contains(mainArea(mac), "/downloads/"+pkg) {
		t.Error("macOS 主区应包含全量 pkg")
	}
	if strings.Contains(mac, "/downloads/"+src) {
		t.Error("匿名用户不应看到源码包（含折叠区）")
	}
	if strings.Contains(mainArea(mac), "/downloads/"+exe) || strings.Contains(mainArea(mac), "/downloads/"+ps1) {
		t.Error("macOS 主区不应出现 Windows 安装包或脚本")
	}
	if strings.Contains(mac, "<b>Windows</b>：运行") {
		t.Error("macOS 页不应显示 Windows 使用说明")
	}
	if !strings.Contains(mac, "我是 Windows 用户") {
		t.Error("macOS 页应提供切换入口")
	}
	// 管理员登录后源码包恢复可见
	macAdmin := renderAdmin(macUA, "")
	if !strings.Contains(mainArea(macAdmin), "/downloads/"+src) {
		t.Error("管理员应看到源码包")
	}
	// macOS 提示区应有终端一键改网关命令与复制按钮
	if !strings.Contains(mac, "gwCmd") || !strings.Contains(mac, "copyGwCmd") || !strings.Contains(mac, "gateway.txt") {
		t.Error("macOS 页应包含终端一键改网关命令与复制按钮")
	}

	// 主安装包必须排在源码包 / 配置脚本之前，避免用户误下第一个卡片
	if i, j := strings.Index(win, "/downloads/"+exe), strings.Index(win, "/downloads/"+ps1); i < 0 || j < 0 || i > j {
		t.Error("Windows 安装包应排在网关脚本之前")
	}
	if i, j := strings.Index(macAdmin, "/downloads/"+pkg), strings.Index(macAdmin, "/downloads/"+src); i < 0 || j < 0 || i > j {
		t.Error("macOS 全量 pkg 应排在源码包之前")
	}

	// 手动覆盖优先于 UA
	forced := render(winUA, "?platform=macos")
	if !strings.Contains(mainArea(forced), "/downloads/"+pkg) || strings.Contains(mainArea(forced), "/downloads/"+exe) {
		t.Error("?platform=macos 未覆盖 Windows UA")
	}

	// 未识别系统 / 查看全部：全部文件都在主区，不出现折叠区（匿名下不含源码包）
	all := render("", "?platform=all")
	for _, n := range []string{exe, pkg} {
		if !strings.Contains(all, "/downloads/"+n) {
			t.Errorf("查看全部时缺少 %s", n)
		}
	}
	if strings.Contains(all, "/downloads/"+src) {
		t.Error("匿名查看全部时不应出现源码包")
	}
	if strings.Contains(all, `<details class="other">`) {
		t.Error("查看全部时不应再有折叠区")
	}

	// platform 参数不能绕过下载开关
	db.SetSetting(setClientDownloadEnabled, "0")
	closed := render(winUA, "?platform=all")
	if !strings.Contains(closed, "客户端下载暂未开放") || strings.Contains(closed, "/downloads/"+exe) {
		t.Error("关闭下载时 platform 参数不应绕过门禁")
	}
}

// 源码包仅管理员可下载：匿名直链 403，管理员会话 200。
func TestClientDownloadSourceAdminOnly(t *testing.T) {
	middleware.InitSession("test-download-secret")
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

	const src = "KSVPN-macOS-Source-v1.0.0.zip"
	const pkg = "KSVPN-macOS13-arm64-Full-v0.5.0.pkg"
	for _, n := range []string{src, pkg} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fetch := func(admin bool, name string) int {
		r := httptest.NewRequest("GET", "/downloads/"+name, nil)
		if admin {
			r.AddCookie(&http.Cookie{Name: "sslvpn_session", Value: middleware.MakeSession()})
		}
		w := httptest.NewRecorder()
		ClientDownloadFile(w, r)
		return w.Code
	}
	if c := fetch(false, src); c != http.StatusForbidden {
		t.Errorf("匿名下载源码包应 403，得到 %d", c)
	}
	if c := fetch(true, src); c != http.StatusOK {
		t.Errorf("管理员下载源码包应 200，得到 %d", c)
	}
	// 全量 pkg 不受源码包门禁影响
	if c := fetch(false, pkg); c != http.StatusOK {
		t.Errorf("匿名下载全量 pkg 应 200（scope=public），得到 %d", c)
	}
}
