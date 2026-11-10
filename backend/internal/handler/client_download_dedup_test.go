package handler

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClientDownloadItemsBuiltinVersionDedup 验证内置下载目录里同平台多个版本时，
// 下载页只展示版本号最高的那个，被取代的旧包不再列出。
func TestClientDownloadItemsBuiltinVersionDedup(t *testing.T) {
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	defer func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin }()

	base := t.TempDir()
	custom := filepath.Join(base, "custom")
	builtin := filepath.Join(base, "builtin")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(builtin, 0o755); err != nil {
		t.Fatal(err)
	}
	customDownloadDir, builtinDownloadDir = custom, builtin

	for _, n := range []string{
		"KSVPN-macOS13-arm64-Full-v0.4.4.pkg",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
		"KSVPN-macOS-Source-v1.0.0.zip",
		"KSVPN-Setup-v0.4.3.exe",
	} {
		if err := os.WriteFile(filepath.Join(builtin, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 无版本号的辅助文件必须保留，不参与去重
	if err := os.WriteFile(filepath.Join(builtin, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	items := clientDownloadItems()
	got := map[string]bool{}
	for _, it := range items {
		got[it.Name] = true
	}
	if got["KSVPN-macOS13-arm64-Full-v0.4.4.pkg"] {
		t.Errorf("旧版 v0.4.4.pkg 不应出现在下载列表")
	}
	if !got["KSVPN-macOS13-arm64-Full-v0.5.0.pkg"] {
		t.Errorf("最新版 v0.5.0.pkg 应出现在下载列表")
	}
	if !got["KSVPN-macOS-Source-v1.0.0.zip"] {
		t.Errorf("源码包应保留")
	}
	if !got["KSVPN-Setup-v0.4.3.exe"] {
		t.Errorf("Windows 安装包应保留")
	}
	if !got["notes.txt"] {
		t.Errorf("无版本号辅助文件应保留")
	}
}

// TestExtractVersion 验证版本号解析与比较。
func TestExtractVersion(t *testing.T) {
	cases := []struct {
		name string
		want [3]int
		ok   bool
	}{
		{"KSVPN-macOS13-arm64-Full-v0.4.4.pkg", [3]int{0, 4, 4}, true},
		{"KSVPN-Setup-v0.4.3.exe", [3]int{0, 4, 3}, true},
		{"KSVPN-macOS-Source-v1.0.0.zip", [3]int{1, 0, 0}, true},
		{"notes.txt", [3]int{}, false},
		{"configure-gateway.ps1", [3]int{}, false},
	}
	for _, c := range cases {
		v, ok := extractVersion(c.name)
		if ok != c.ok {
			t.Errorf("extractVersion(%q) ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		if ok && v != c.want {
			t.Errorf("extractVersion(%q)=%v want %v", c.name, v, c.want)
		}
	}
	if !versionGreater([3]int{0, 4, 6}, [3]int{0, 4, 4}) {
		t.Errorf("0.4.6 应大于 0.4.4")
	}
	if versionGreater([3]int{0, 4, 4}, [3]int{0, 4, 4}) {
		t.Errorf("相同版本不应大于自身")
	}
}

// TestBuiltinSameVersionPrefersNewName 验证重新打包并更换命名后，增量解包残留的
// 同版本旧命名内置包不会重新出现在下载页，也不会被当作账号邮件附件发出。
func TestBuiltinSameVersionPrefersNewName(t *testing.T) {
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	defer func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin }()

	base := t.TempDir()
	custom := filepath.Join(base, "custom")
	builtin := filepath.Join(base, "builtin")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(builtin, 0o755); err != nil {
		t.Fatal(err)
	}
	customDownloadDir, builtinDownloadDir = custom, builtin

	for _, n := range []string{
		"AAA-Client-v0.4.3.exe", // 旧命名残留，版本号与新包相同
		"KSVPN-Setup-v0.4.3.exe",
		"AAA-Client-v0.4.6.pkg",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
	} {
		if err := os.WriteFile(filepath.Join(builtin, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	items := clientDownloadItems()
	got := map[string]bool{}
	for _, it := range items {
		got[it.Name] = true
	}
	if got["AAA-Client-v0.4.3.exe"] || got["AAA-Client-v0.4.6.pkg"] {
		t.Errorf("同版本旧命名残留包不应出现在下载列表：%v", got)
	}
	if !got["KSVPN-Setup-v0.4.3.exe"] || !got["KSVPN-macOS13-arm64-Full-v0.5.0.pkg"] {
		t.Errorf("新命名安装包应保留：%v", got)
	}

	atts := clientInstallerAtts("windows", "macos")
	names := map[string]bool{}
	for _, a := range atts {
		names[a.Name] = true
	}
	if len(atts) != 2 || !names["KSVPN-Setup-v0.4.3.exe"] || !names["KSVPN-macOS13-arm64-Full-v0.5.0.pkg"] {
		t.Errorf("账号邮件应只附带新命名安装包：%v", names)
	}

	// 管理员上传的同版本包优先级仍高于镜像内置包
	if err := os.WriteFile(filepath.Join(custom, "ZZZ-Upload-v0.4.3.exe"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	atts = clientInstallerAtts("windows")
	if len(atts) != 1 || atts[0].Name != "ZZZ-Upload-v0.4.3.exe" {
		t.Errorf("管理员上传包应优先于内置包：%+v", atts)
	}
}
