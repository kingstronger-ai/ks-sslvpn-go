package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/mail"
)

// mailReq 构造带 JSON body 的请求
func mailReq(filename, email string) *http.Request {
	b, _ := json.Marshal(map[string]string{"filename": filename, "email": email})
	r := httptest.NewRequest("POST", "/api/v1/system/clientDownload/mail", strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// ClientDownloadMail 参数与前置条件校验：邮箱格式、文件存在性、SMTP 未配置。
func TestClientDownloadMailValidation(t *testing.T) {
	oldEnabled := db.GetSetting(setClientDownloadEnabled)
	db.SetSetting(setClientDownloadEnabled, "1")
	t.Cleanup(func() { db.SetSetting(setClientDownloadEnabled, oldEnabled) })

	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	dir := t.TempDir()
	customDownloadDir = filepath.Join(dir, "missing")
	builtinDownloadDir = dir
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })
	if err := os.WriteFile(filepath.Join(dir, "KSVPN-Setup-v0.4.3.exe"), []byte("fake-exe"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := func(filename, email string) string {
		w := httptest.NewRecorder()
		ClientDownloadMail(w, mailReq(filename, email))
		return w.Body.String()
	}

	if body := req("KSVPN-Setup-v0.4.3.exe", "not-an-email"); !strings.Contains(body, "邮箱") {
		t.Errorf("非法邮箱应被拒绝，得到: %s", body)
	}
	if body := req("../etc/passwd", "u@x.com"); !strings.Contains(body, "不合法") {
		t.Errorf("路径穿越应被拒绝，得到: %s", body)
	}
	if body := req("no-such-file.exe", "u@x.com"); !strings.Contains(body, "不存在") {
		t.Errorf("不存在的文件应被拒绝，得到: %s", body)
	}
	// SMTP 未配置时的提示（测试环境无 SMTP 设置）
	if body := req("KSVPN-Setup-v0.4.3.exe", "u@x.com"); !strings.Contains(body, "SMTP") {
		t.Errorf("SMTP 未配置应给出提示，得到: %s", body)
	}
}

// clientInstallerAtts：随账号邮件发送的客户端附件——Windows/macOS 各取最新版，
// 管理员上传包优先于内置包；源码包与无版本文件不参与。
func TestClientInstallerAtts(t *testing.T) {
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	dir := t.TempDir()
	customDownloadDir = filepath.Join(dir, "custom")
	builtinDownloadDir = filepath.Join(dir, "builtin")
	if err := os.MkdirAll(customDownloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(builtinDownloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })

	for _, n := range []string{
		"KSVPN-Setup-v0.4.3.exe",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
		"KSVPN-macOS-Source-v1.0.0.zip", // 源码包不随账号邮件发送
	} {
		if err := os.WriteFile(filepath.Join(builtinDownloadDir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 管理员上传的新版 Windows 包应取代内置 v0.4.3
	if err := os.WriteFile(filepath.Join(customDownloadDir, "KSVPN-Setup-v0.4.5.exe"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	atts := clientInstallerAtts()
	got := map[string]bool{}
	for _, a := range atts {
		got[a.Name] = true
	}
	if len(atts) != 2 {
		t.Fatalf("应恰好返回 Windows/macOS 各一个附件，得到 %d 个: %v", len(atts), got)
	}
	if !got["KSVPN-Setup-v0.4.5.exe"] {
		t.Errorf("Windows 应取上传的 v0.4.5: %v", got)
	}
	if !got["KSVPN-macOS13-arm64-Full-v0.5.0.pkg"] {
		t.Errorf("macOS 应取内置 v0.5.0: %v", got)
	}
	if got["KSVPN-Setup-v0.4.3.exe"] || got["KSVPN-macOS-Source-v1.0.0.zip"] {
		t.Errorf("旧版 exe 与源码包不应随账号邮件发送: %v", got)
	}
}

// accountMailAtts 的开关行为：默认关闭只可能含配置文件；开启后按勾选平台附带客户端，
// 且可以不勾配置文件（客户端发送不带配置文件）。
func TestAccountMailAttachSwitch(t *testing.T) {
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	dir := t.TempDir()
	customDownloadDir = filepath.Join(dir, "custom")
	builtinDownloadDir = filepath.Join(dir, "builtin")
	if err := os.MkdirAll(customDownloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(builtinDownloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })
	for _, n := range []string{
		"KSVPN-Setup-v0.4.3.exe",
		"KSVPN-macOS13-arm64-Full-v0.5.0.pkg",
	} {
		if err := os.WriteFile(filepath.Join(builtinDownloadDir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	old := [4]string{db.GetSetting(setMailAttach), db.GetSetting(setMailAttachCfg), db.GetSetting(setMailAttachWin), db.GetSetting(setMailAttachMac)}
	t.Cleanup(func() {
		db.SetSetting(setMailAttach, old[0])
		db.SetSetting(setMailAttachCfg, old[1])
		db.SetSetting(setMailAttachWin, old[2])
		db.SetSetting(setMailAttachMac, old[3])
	})

	set := func(attach, cfg, win, mac string) {
		db.SetSetting(setMailAttach, attach)
		db.SetSetting(setMailAttachCfg, cfg)
		db.SetSetting(setMailAttachWin, win)
		db.SetSetting(setMailAttachMac, mac)
	}
	a := &Account{Username: "tester", Email: "t@x.com"}
	hasInstaller := func(atts []mail.Attachment) bool {
		for _, at := range atts {
			if strings.HasSuffix(at.Name, ".exe") || strings.HasSuffix(at.Name, ".pkg") {
				return true
			}
		}
		return false
	}

	// 默认关闭：不应附带任何客户端安装包
	set("", "", "", "")
	if hasInstaller(accountMailAtts(a)) {
		t.Error("开关关闭时不应附带客户端安装包")
	}
	// 开启 + 只选 Windows：只出 exe（不带配置文件也不报错）
	set("1", "0", "1", "0")
	atts := accountMailAtts(a)
	if !hasInstaller(atts) || strings.Contains(strings.Join(names(atts), ","), ".pkg") {
		t.Errorf("开启后只选 Windows 应只出 exe: %v", names(atts))
	}
	// 开启 + 只选 macOS
	set("1", "0", "0", "1")
	atts = accountMailAtts(a)
	if !strings.Contains(strings.Join(names(atts), ","), ".pkg") || strings.Contains(strings.Join(names(atts), ","), ".exe") {
		t.Errorf("开启后只选 macOS 应只出 pkg: %v", names(atts))
	}
}

func names(atts []mail.Attachment) []string {
	out := make([]string, 0, len(atts))
	for _, a := range atts {
		out = append(out, a.Name)
	}
	return out
}

// 邮件正文：默认（只发配置文件）保持原有提示且加粗纯黑；开启附带客户端后
// 不再提示“解压导入配置文件”，改为直接安装客户端登录。
func TestMailBodyInstallHint(t *testing.T) {
	oldBody, oldLDAP := db.GetSetting("mail_body"), db.GetSetting("mail_body_ldap")
	db.SetSetting("mail_body", "")
	db.SetSetting("mail_body_ldap", "")
	old := [4]string{db.GetSetting(setMailAttach), db.GetSetting(setMailAttachCfg), db.GetSetting(setMailAttachWin), db.GetSetting(setMailAttachMac)}
	t.Cleanup(func() {
		db.SetSetting("mail_body", oldBody)
		db.SetSetting("mail_body_ldap", oldLDAP)
		db.SetSetting(setMailAttach, old[0])
		db.SetSetting(setMailAttachCfg, old[1])
		db.SetSetting(setMailAttachWin, old[2])
		db.SetSetting(setMailAttachMac, old[3])
	})
	set := func(attach, cfg, win, mac string) {
		db.SetSetting(setMailAttach, attach)
		db.SetSetting(setMailAttachCfg, cfg)
		db.SetSetting(setMailAttachWin, win)
		db.SetSetting(setMailAttachMac, mac)
	}

	// 默认关闭：保留原有配置文件提示，且提示段落为加粗纯黑
	set("", "", "", "")
	_, body := renderMailTemplate(&Account{Username: "tester"})
	if !strings.Contains(body, "解压后导入 VPN 客户端即可使用") {
		t.Errorf("默认应保留配置文件提示: %s", body)
	}
	if strings.Contains(body, "无需解压或导入配置文件") {
		t.Error("默认关闭时不应出现安装客户端提示")
	}
	if strings.Contains(body, "#909399") || !strings.Contains(body, "#000000;font-weight:bold") {
		t.Error("提示文字应为加粗纯黑，不再是灰色")
	}

	// 开启附带 Windows/macOS：改成安装客户端即登录，不再提示导入配置文件
	set("1", "0", "1", "1")
	_, body = renderMailTemplate(&Account{Username: "tester"})
	if !strings.Contains(body, "直接使用上方账号密码登录") || !strings.Contains(body, "无需解压或导入配置文件") {
		t.Errorf("开启后应提示直接安装客户端登录: %s", body)
	}
	if strings.Contains(body, "解压后导入 VPN 客户端即可使用") {
		t.Error("开启后不应再提示解压导入配置文件")
	}
	if !strings.Contains(body, "Windows 双击") || !strings.Contains(body, "macOS 双击") {
		t.Errorf("应按勾选平台给出安装方式: %s", body)
	}

	// 只勾 macOS：不应出现 Windows 说法
	set("1", "0", "0", "1")
	_, body = renderMailTemplate(&Account{Username: "tester"})
	if strings.Contains(body, "Windows 双击") || !strings.Contains(body, "macOS 双击") {
		t.Errorf("只勾 macOS 时不应提 Windows: %s", body)
	}

	// TOTP 账号：动态码填写格式必须保留（否则无法登录），仅替换附件说明
	set("1", "0", "1", "0")
	_, body = renderMailTemplate(&Account{Username: "tester", AuthType: "totp"})
	if !strings.Contains(body, "密码,动态码") {
		t.Errorf("TOTP 账号应保留动态码填写格式: %s", body)
	}
	if strings.Contains(body, "解压后导入 VPN 客户端即可使用") {
		t.Error("TOTP 账号开启附带客户端后也不应提示导入配置文件")
	}

	// LDAP 默认模板：同开关切换，且原有“解压导入”说法被替换
	set("", "", "", "")
	_, body = renderMailTemplate(&Account{Username: "ldapuser", AuthType: "ldap"})
	if !strings.Contains(body, "请下载附件中的tgz") {
		t.Errorf("LDAP 默认应保留原有提示: %s", body)
	}
	set("1", "0", "1", "1")
	_, body = renderMailTemplate(&Account{Username: "ldapuser", AuthType: "ldap"})
	if strings.Contains(body, "请下载附件中的tgz") || !strings.Contains(body, "直接使用上方账号密码登录") {
		t.Errorf("LDAP 开启后应改为安装客户端登录: %s", body)
	}

	// 管理员保存过的旧模板（灰色小字 + 写死的导入提示）也要被兼容升级
	set("1", "0", "1", "0")
	db.SetSetting("mail_body", `<p style="color:#909399">附件为该账号的 VPN 客户端配置文件，解压后导入 VPN 客户端即可使用。</p>`)
	_, body = renderMailTemplate(&Account{Username: "tester"})
	if strings.Contains(body, "#909399") {
		t.Error("旧自定义模板的灰色小字应升为加粗纯黑")
	}
	if strings.Contains(body, "解压后导入 VPN 客户端即可使用") {
		t.Error("旧自定义模板里写死的导入提示也应被替换")
	}
	if !strings.Contains(body, "直接使用上方账号密码登录") {
		t.Errorf("旧自定义模板应改为安装客户端登录提示: %s", body)
	}
}

// 网关脚本（generated）也应允许作为附件发送的候选文件。
func TestClientDownloadMailGeneratedScript(t *testing.T) {
	oldEnabled := db.GetSetting(setClientDownloadEnabled)
	db.SetSetting(setClientDownloadEnabled, "1")
	t.Cleanup(func() { db.SetSetting(setClientDownloadEnabled, oldEnabled) })
	oldCustom, oldBuiltin := customDownloadDir, builtinDownloadDir
	customDownloadDir = t.TempDir()
	builtinDownloadDir = filepath.Join(customDownloadDir, "missing")
	t.Cleanup(func() { customDownloadDir, builtinDownloadDir = oldCustom, oldBuiltin })

	w := httptest.NewRecorder()
	ClientDownloadMail(w, mailReq("configure-gateway.ps1", "u@x.com"))
	// 未配置 SMTP 时的提示而非「文件不存在」
	if strings.Contains(w.Body.String(), "文件不存在") {
		t.Errorf("生成的网关脚本不应被判定为不存在: %s", w.Body.String())
	}
}
