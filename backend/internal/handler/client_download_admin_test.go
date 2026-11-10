package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/middleware"
)

func withDownloadDirs(t *testing.T) (string, string) {
	t.Helper()
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	base := t.TempDir()
	custom, builtin := filepath.Join(base, "custom"), filepath.Join(base, "builtin")
	for _, d := range []string{custom, builtin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	customDownloadDir, builtinDownloadDir = custom, builtin
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })
	return custom, builtin
}

func restoreDownloadPolicy(t *testing.T) func() {
	t.Helper()
	oldE, oldS := db.GetSetting(setClientDownloadEnabled), db.GetSetting(setClientDownloadScope)
	return func() {
		db.SetSetting(setClientDownloadEnabled, oldE)
		db.SetSetting(setClientDownloadScope, oldS)
	}
}

func downloadReq(target string, authed bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if authed {
		r.AddCookie(&http.Cookie{Name: "sslvpn_session", Value: middleware.MakeSession()})
	}
	return r
}

func jsonCode(t *testing.T, w *httptest.ResponseRecorder) (int, string) {
	t.Helper()
	var d struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("响应不是 JSON: %v / %s", err, w.Body.String())
	}
	return d.Code, d.Msg
}

func TestDownloadPolicyGuard(t *testing.T) {
	_, builtin := withDownloadDirs(t)
	defer restoreDownloadPolicy(t)()
	if err := os.WriteFile(filepath.Join(builtin, "KSVPN-Setup-v0.4.3.exe"), []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	const exeURL = "/downloads/KSVPN-Setup-v0.4.3.exe"

	// 关闭：页面无下载按钮，直接访问链接也被拒绝
	db.SetSetting(setClientDownloadEnabled, "0")
	db.SetSetting(setClientDownloadScope, "public")
	w := httptest.NewRecorder()
	ClientDownloads(w, downloadReq("/downloads", false))
	body := w.Body.String()
	if !strings.Contains(body, "客户端下载暂未开放") || strings.Contains(body, exeURL) {
		t.Errorf("关闭时应隐藏下载按钮:\n%s", body)
	}
	fd := httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq(exeURL, false))
	if fd.Code != http.StatusForbidden {
		t.Errorf("关闭时直接下载应 403，实际 %d", fd.Code)
	}

	// 仅管理员：未登录显示登录引导，链接同样 403
	db.SetSetting(setClientDownloadEnabled, "1")
	db.SetSetting(setClientDownloadScope, "admin")
	w = httptest.NewRecorder()
	ClientDownloads(w, downloadReq("/downloads", false))
	body = w.Body.String()
	if !strings.Contains(body, "请先登录管理后台") || strings.Contains(body, exeURL) {
		t.Errorf("未登录应提示先登录:\n%s", body)
	}
	fd = httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq(exeURL, false))
	if fd.Code != http.StatusForbidden {
		t.Errorf("未登录直接下载应 403，实际 %d", fd.Code)
	}

	// 管理员登录后可见可下载
	w = httptest.NewRecorder()
	ClientDownloads(w, downloadReq("/downloads", true))
	if !strings.Contains(w.Body.String(), exeURL) {
		t.Error("管理员登录后应显示下载按钮")
	}
	fd = httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq(exeURL, true))
	if fd.Code != 200 || fd.Body.String() != "MZ" {
		t.Errorf("管理员下载失败: %d %q", fd.Code, fd.Body.String())
	}

	// 切公开：免登录可见可下载
	db.SetSetting(setClientDownloadScope, "public")
	w = httptest.NewRecorder()
	ClientDownloads(w, downloadReq("/downloads", false))
	if !strings.Contains(w.Body.String(), exeURL) {
		t.Error("公开模式应免登录显示下载按钮")
	}
	fd = httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq(exeURL, false))
	if fd.Code != 200 || fd.Body.String() != "MZ" {
		t.Errorf("公开模式下载失败: %d %q", fd.Code, fd.Body.String())
	}
}

func uploadPart(t *testing.T, platform, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("platform", platform); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func doUpload(t *testing.T, platform, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := uploadPart(t, platform, filename, content)
	r := httptest.NewRequest(http.MethodPost, "/system/clientDownload/upload", body)
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	ClientDownloadUpload(w, r)
	return w
}

func doDelete(t *testing.T, filename string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"filename": filename})
	r := httptest.NewRequest(http.MethodPost, "/system/clientDownload/delete", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClientDownloadDelete(w, r)
	return w
}

func TestClientDownloadUploadReplace(t *testing.T) {
	custom, builtin := withDownloadDirs(t)
	defer restoreDownloadPolicy(t)()
	db.SetSetting(setClientDownloadEnabled, "1")
	db.SetSetting(setClientDownloadScope, "public")

	for n, c := range map[string]string{
		"KSVPN-Setup-v0.4.3.exe":              "BUILTIN-WIN",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg": "BUILTIN-MAC",
		"configure-gateway.ps1":               "STATIC-SCRIPT",
	} {
		if err := os.WriteFile(filepath.Join(builtin, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	w := doUpload(t, "windows", "MyVPN-v2.0.exe", []byte("NEW-WIN"))
	if code, msg := jsonCode(t, w); code != 1 {
		t.Fatalf("上传 Windows 包失败: %d %s", code, msg)
	}
	if got, _ := os.ReadFile(filepath.Join(custom, "MyVPN-v2.0.exe")); string(got) != "NEW-WIN" {
		t.Fatal("上传文件未写入 custom 目录")
	}

	names := map[string]bool{}
	for _, it := range clientDownloadItems() {
		names[it.Name] = true
	}
	if !names["MyVPN-v2.0.exe"] {
		t.Error("上传包未出现在下载列表")
	}
	if names["KSVPN-Setup-v0.4.3.exe"] {
		t.Error("同平台内置包应被上传包替换")
	}
	if !names["KSVPN-macOS13-arm64-Full-v0.5.0.pkg"] {
		t.Error("上传 Windows 包不应影响 macOS 内置包")
	}

	fd := httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq("/downloads/MyVPN-v2.0.exe", false))
	if fd.Body.String() != "NEW-WIN" {
		t.Errorf("应下载到上传包内容，实际 %q", fd.Body.String())
	}

	// 再传一个 Windows 包，同平台旧上传包应被清理
	if code, msg := jsonCode(t, doUpload(t, "windows", "MyVPN-v3.0.exe", []byte("NEWER-WIN"))); code != 1 {
		t.Fatalf("二次上传失败: %d %s", code, msg)
	}
	if fileExists(filepath.Join(custom, "MyVPN-v2.0.exe")) {
		t.Error("同平台旧上传包应被自动删除")
	}

	// 同名上传直接覆盖，且列表不出现重复条目
	if code, msg := jsonCode(t, doUpload(t, "windows", "MyVPN-v3.0.exe", []byte("OVERWRITTEN"))); code != 1 {
		t.Fatalf("同名覆盖失败: %d %s", code, msg)
	}
	if got, _ := os.ReadFile(filepath.Join(custom, "MyVPN-v3.0.exe")); string(got) != "OVERWRITTEN" {
		t.Error("同名上传应覆盖原文件内容")
	}
	count := 0
	for _, it := range clientDownloadItems() {
		if it.Name == "MyVPN-v3.0.exe" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("同名覆盖后列表应只有 1 条，实际 %d", count)
	}

	// 与内置包同名时以上传版为准，删除后恢复内置版
	if code, msg := jsonCode(t, doUpload(t, "windows", "KSVPN-Setup-v0.4.3.exe", []byte("CUSTOM-SAME-NAME"))); code != 1 {
		t.Fatalf("同名内置包覆盖失败: %d %s", code, msg)
	}
	fd = httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq("/downloads/KSVPN-Setup-v0.4.3.exe", false))
	if fd.Body.String() != "CUSTOM-SAME-NAME" {
		t.Errorf("同名时应下载上传版，实际 %q", fd.Body.String())
	}
	if code, _ := jsonCode(t, doDelete(t, "KSVPN-Setup-v0.4.3.exe")); code != 1 {
		t.Error("应允许删除与内置同名的上传包")
	}
	fd = httptest.NewRecorder()
	ClientDownloadFile(fd, downloadReq("/downloads/KSVPN-Setup-v0.4.3.exe", false))
	if fd.Body.String() != "BUILTIN-WIN" {
		t.Errorf("删除上传包后应恢复内置版，实际 %q", fd.Body.String())
	}

	// 平台与扩展名必须匹配
	if code, _ := jsonCode(t, doUpload(t, "macos", "bad.exe", []byte("x"))); code == 1 {
		t.Error("macOS 平台不应接受 .exe")
	}
	if code, _ := jsonCode(t, doUpload(t, "unknown", "bad.pkg", []byte("x"))); code == 1 {
		t.Error("未知平台应被拒绝")
	}

	// 上面「与内置同名」用例已删除最后一个上传包，此时应自动恢复内置同平台包
	names = map[string]bool{}
	for _, it := range clientDownloadItems() {
		names[it.Name] = true
	}
	if !names["KSVPN-Setup-v0.4.3.exe"] || names["MyVPN-v3.0.exe"] {
		t.Error("删除上传包后应恢复内置包")
	}
	if code, _ := jsonCode(t, doDelete(t, "KSVPN-Setup-v0.4.3.exe")); code == 1 {
		t.Error("不应允许删除镜像内置包")
	}
}

func TestGatewayScriptGenerated(t *testing.T) {
	withDownloadDirs(t)
	defer restoreDownloadPolicy(t)()
	db.SetSetting(setClientDownloadEnabled, "1")
	db.SetSetting(setClientDownloadScope, "public")
	oldHost := db.GetSetting("public_host")
	defer db.SetSetting("public_host", oldHost)

	db.SetSetting("public_host", "https://vpn.example.cn:6443")
	w := httptest.NewRecorder()
	ClientDownloadFile(w, downloadReq("/downloads/configure-gateway.ps1", false))
	body := w.Body.String()
	if !strings.Contains(body, "$Gateway = 'https://vpn.example.cn:6443'") {
		t.Errorf("网关脚本未跟随公网地址:\n%s", body)
	}
	if strings.Contains(body, "__GATEWAY__") {
		t.Error("网关脚本不应残留写死地址或占位符")
	}

	// 公网地址不带端口、且访问带同一主机名的端口时自动补端口
	db.SetSetting("public_host", "https://example.com")
	r := httptest.NewRequest(http.MethodGet, "https://example.com:58443/downloads/configure-gateway.ps1", nil)
	w = httptest.NewRecorder()
	ClientDownloadFile(w, r)
	if !strings.Contains(w.Body.String(), "$Gateway = 'https://example.com:58443'") {
		t.Errorf("未自动补端口:\n%s", w.Body.String())
	}
}

func TestClientDownloadConfigSave(t *testing.T) {
	defer restoreDownloadPolicy(t)()
	body, _ := json.Marshal(map[string]any{"enabled": false, "scope": "public"})
	r := httptest.NewRequest(http.MethodPost, "/system/clientDownload/save", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClientDownloadConfigSave(w, r)
	if code, msg := jsonCode(t, w); code != 1 {
		t.Fatalf("保存失败: %d %s", code, msg)
	}
	enabled, scope := clientDownloadPolicy()
	if enabled || scope != "public" {
		t.Errorf("保存未生效: enabled=%v scope=%s", enabled, scope)
	}
}
