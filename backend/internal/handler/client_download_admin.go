package handler

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sslvpn/internal/db"
	"sslvpn/internal/mail"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
)

// 客户端下载的开关与可见范围。
// enabled 为空（未配置过）视为开启，保证部署后 Windows 安装包可直接使用；
// scope 为空视为 admin，即仅管理员登录后能下载，避免安装包被任意公网访问。
const (
	setClientDownloadEnabled = "client_download_enabled"
	setClientDownloadScope   = "client_download_scope"
	clientDownloadMaxBytes   = 300 << 20

	// 账号邮件附件策略：默认关闭只发配置文件；开启后可自由组合
	// 配置文件 / Windows 客户端 / macOS 客户端（客户端发送可以不带配置文件）。
	setMailAttach    = "account_mail_attach"
	setMailAttachCfg = "account_mail_attach_cfg"
	setMailAttachWin = "account_mail_attach_win"
	setMailAttachMac = "account_mail_attach_mac"
)

// accountMailAttachMode 返回 (总开关, 附带配置文件, 附带 Windows, 附带 macOS)。
// 总开关默认关闭：只发配置文件（历史行为）。
func accountMailAttachMode() (attach, cfg, win, mac bool) {
	attach = db.GetSetting(setMailAttach) == "1"
	cfg = db.GetSetting(setMailAttachCfg) != "0"
	win = db.GetSetting(setMailAttachWin) != "0"
	mac = db.GetSetting(setMailAttachMac) != "0"
	return
}

var clientDownloadExts = map[string][]string{
	"windows": {".exe", ".msi"},
	"macos":   {".pkg", ".dmg", ".zip"},
}

func clientDownloadPolicy() (bool, string) {
	enabled := db.GetSetting(setClientDownloadEnabled) != "0"
	scope := strings.TrimSpace(db.GetSetting(setClientDownloadScope))
	if scope != "public" {
		scope = "admin"
	}
	return enabled, scope
}

// downloadPageState 返回 (是否开放, 是否需要登录)。下载页用它区分两种提示。
func downloadPageState(r *http.Request) (bool, bool) {
	enabled, scope := clientDownloadPolicy()
	if !enabled {
		return false, false
	}
	if scope == "public" {
		return true, false
	}
	return true, !middleware.CheckRequest(r)
}

// downloadAllowed 文件下载接口的统一门禁，防止绕过页面直接访问链接
func downloadAllowed(r *http.Request) bool {
	enabled, needLogin := downloadPageState(r)
	return enabled && !needLogin
}

// ClientDownloadConfigGet GET /system/clientDownload/get
func ClientDownloadConfigGet(w http.ResponseWriter, r *http.Request) {
	enabled, scope := clientDownloadPolicy()
	util.OK(w, map[string]any{
		"enabled":     enabled,
		"scope":       scope,
		"public_url":  "/downloads",
		"custom_dir":  customDownloadDir,
		"files":       clientDownloadItems(),
		"attach_mail": db.GetSetting(setMailAttach) == "1",
		"attach_cfg":  db.GetSetting(setMailAttachCfg) != "0",
		"attach_win":  db.GetSetting(setMailAttachWin) != "0",
		"attach_mac":  db.GetSetting(setMailAttachMac) != "0",
	})
}

// ClientDownloadConfigSave POST /system/clientDownload/save
func ClientDownloadConfigSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled    *bool  `json:"enabled"`
		Scope      string `json:"scope"`
		AttachMail *bool  `json:"attach_mail"`
		AttachCfg  *bool  `json:"attach_cfg"`
		AttachWin  *bool  `json:"attach_win"`
		AttachMac  *bool  `json:"attach_mac"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	scope := strings.TrimSpace(req.Scope)
	if scope != "public" {
		scope = "admin"
	}
	enabled := "1"
	if req.Enabled != nil && !*req.Enabled {
		enabled = "0"
	}
	db.SetSetting(setClientDownloadEnabled, enabled)
	db.SetSetting(setClientDownloadScope, scope)
	flag := func(v *bool, def string) string {
		if v == nil {
			return def
		}
		if *v {
			return "1"
		}
		return "0"
	}
	// attach_cfg 等未配置时默认开启，保持「1」
	db.SetSetting(setMailAttach, flag(req.AttachMail, db.GetSetting(setMailAttach)))
	db.SetSetting(setMailAttachCfg, flag(req.AttachCfg, "1"))
	db.SetSetting(setMailAttachWin, flag(req.AttachWin, "1"))
	db.SetSetting(setMailAttachMac, flag(req.AttachMac, "1"))
	db.Syslog("admin", "客户端下载设置", "开放="+enabled+"，范围="+scope+"，邮件附件开关="+db.GetSetting(setMailAttach), clientIP(r))
	util.OKMsg(w, "客户端下载设置已保存", nil)
}

func cleanUploadName(raw string) string {
	name := strings.TrimSpace(raw)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// ClientDownloadUpload POST /system/clientDownload/upload
// multipart: platform=windows|macos, file=<安装包>。上传后自动替换同平台的旧包。
func ClientDownloadUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, clientDownloadMaxBytes)
	if err := r.ParseMultipartForm(clientDownloadMaxBytes); err != nil {
		util.Fail(w, "上传失败：文件过大或格式不正确（上限 300MB）")
		return
	}
	platform := strings.ToLower(strings.TrimSpace(r.FormValue("platform")))
	exts, ok := clientDownloadExts[platform]
	if !ok {
		util.Fail(w, "请指定平台：windows 或 macos")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		util.Fail(w, "未找到上传文件字段 file")
		return
	}
	defer file.Close()

	name := cleanUploadName(hdr.Filename)
	if !safeDownloadName(name) {
		util.Fail(w, "文件名不合法，仅允许英文/数字/中文文件名与安装包扩展名")
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	allowed := false
	for _, e := range exts {
		if ext == e {
			allowed = true
			break
		}
	}
	if !allowed {
		util.Fail(w, "该平台只支持 "+strings.Join(exts, " / ")+" 文件")
		return
	}
	if err := os.MkdirAll(customDownloadDir, 0o755); err != nil {
		util.Fail(w, "创建上传目录失败: "+err.Error())
		return
	}

	// 同一平台只保留一个上传包，避免下载页出现多个同平台安装包
	key := downloadPlatformKey(name)
	if entries, err := os.ReadDir(customDownloadDir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if n == name || e.IsDir() || !safeDownloadName(n) {
				continue
			}
			if k := downloadPlatformKey(n); k != "" && k == key {
				_ = os.Remove(filepath.Join(customDownloadDir, n))
			}
		}
	}

	tmp, err := os.CreateTemp(customDownloadDir, ".upload-*")
	if err != nil {
		util.Fail(w, "保存失败: "+err.Error())
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	n, err := io.Copy(tmp, io.LimitReader(file, clientDownloadMaxBytes+1))
	closeErr := tmp.Close()
	if err != nil || closeErr != nil || n > clientDownloadMaxBytes {
		util.Fail(w, "保存失败：文件过大或写入出错（上限 300MB）")
		return
	}
	if err := os.Rename(tmpPath, filepath.Join(customDownloadDir, name)); err != nil {
		util.Fail(w, "保存失败: "+err.Error())
		return
	}
	if err := os.Chmod(filepath.Join(customDownloadDir, name), 0o644); err != nil {
		util.Fail(w, "保存失败: "+err.Error())
		return
	}
	db.Syslog("admin", "上传客户端安装包", platform+" / "+name+" / "+humanSize(n), clientIP(r))
	util.OKMsg(w, "已上传 "+name+"，同平台旧包已自动替换", map[string]any{"filename": name, "size": n})
}

// ClientDownloadDelete POST /system/clientDownload/delete
// 只允许删除管理员上传的文件；镜像内置包不可删（上传同名/同平台包即可覆盖）。
func ClientDownloadDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	name := cleanUploadName(req.Filename)
	if !safeDownloadName(name) {
		util.Fail(w, "文件名不合法")
		return
	}
	path := filepath.Join(customDownloadDir, name)
	if !fileExists(path) {
		util.Fail(w, "该文件不是上传包，或已不存在（镜像内置包不可删除）")
		return
	}
	if err := os.Remove(path); err != nil {
		util.Fail(w, "删除失败: "+err.Error())
		return
	}
	db.Syslog("admin", "删除客户端安装包", name, clientIP(r))
	util.OKMsg(w, "已删除 "+name, nil)
}

var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// clientInstallerAtts 收集随账号邮件发送的客户端安装包附件，platforms 指定平台
// （windows / macos，默认两者）：同平台取版本号最高者，管理员上传包优先于镜像内置包；
// 源码包与脚本不随账号邮件发送。
func clientInstallerAtts(platforms ...string) []mail.Attachment {
	if len(platforms) == 0 {
		platforms = []string{"windows", "macos"}
	}
	type cand struct {
		path string
		name string
		ver  [3]int
		prio int // 1=管理员上传，0=镜像内置；上传包优先
	}
	best := map[string]cand{}
	for idx, dir := range []string{customDownloadDir, builtinDownloadDir} {
		prio := 1 - idx
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !safeDownloadName(e.Name()) {
				continue
			}
			k := downloadPlatformKey(e.Name())
			if k != "windows" && k != "macos" {
				continue
			}
			v, ok := extractVersion(e.Name())
			if !ok {
				continue
			}
			// 版本高者优先；同版本时管理员上传包优先，仍同分则取文件名靠后者，
			// 保证重新打包改名后不会把增量解包残留的旧命名包发给用户。
			cur, exists := best[k]
			if !exists || versionGreater(v, cur.ver) ||
				(v == cur.ver && (prio > cur.prio || (prio == cur.prio && e.Name() > cur.name))) {
				best[k] = cand{filepath.Join(dir, e.Name()), e.Name(), v, prio}
			}
		}
	}
	var atts []mail.Attachment
	for _, k := range platforms {
		c, ok := best[k]
		if !ok {
			continue
		}
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		atts = append(atts, mail.Attachment{Name: filepath.Base(c.path), Data: b})
	}
	return atts
}

// ClientDownloadMail POST /system/clientDownload/mail
// 把安装包（内置或上传）以附件发到用户邮箱；自动生成的网关脚本同样支持。
// clientDownloadMailCompose 生成单包邮件的标题与正文。
// 卸载工具附带完整卸载教程；注意不带下载页链接——卸载工具仅管理员可见，
// 普通用户打开 /downloads 看不到它，放链接只会造成困惑。
func clientDownloadMailCompose(name string, size int64, origin string) (string, string) {
	if p := uninstallPlatform(name); p != "" {
		return uninstallMailContent(p, name, size)
	}
	subject := brandName() + " 客户端：" + name
	body := fmt.Sprintf(`<div style="font-family:sans-serif;max-width:560px">
<h2>VPN 客户端安装包</h2>
<p>附件为 <b>%s</b>（%s），请下载后按以下说明安装使用：</p>
<ul>
<li><b>Windows（.exe）</b>：直接运行安装；装后运行 <code>configure-gateway.ps1</code>（可在下载页获取）把网关指向本服务器。</li>
<li><b>macOS（.pkg）</b>：双击安装（Apple Silicon / macOS 13+），支持本地账号 / LDAP / TOTP / 飞书扫码登录。</li>
<li><b>macOS（.zip）</b>：SwiftUI 源码包，在 Mac 上按包内 README 编译，适合深度定制。</li>
</ul>
<p>更多说明与其它文件：<a href="%s">%s</a></p>
<p style="color:#888">本邮件由系统发送，请勿回复。</p>
</div>`, html.EscapeString(name), humanSize(size), origin+"/downloads", origin+"/downloads")
	return subject, body
}

// uninstallMailContent 卸载工具邮件的分步教程（Windows / macOS）。
func uninstallMailContent(platform, name string, size int64) (string, string) {
	subject := brandName() + " 客户端卸载工具：" + name
	head := `<div style="font-family:sans-serif;max-width:620px;line-height:1.7">
<h2>KSVPN 客户端卸载</h2>
<p>附件为 <b>` + html.EscapeString(name) + `</b>（` + humanSize(size) + `），内含卸载脚本与「卸载说明.txt」。
请先<b>退出客户端并断开 VPN 连接</b>，再按下面步骤操作。</p>`

	winSteps := `<h3>一、自动卸载（推荐）</h3>
<ol>
<li>先点客户端右上角 <b>X</b>：会自动断开 VPN 并退出；确认右下角托盘里没有 KSVPN。</li>
<li>把附件 zip 解压到任意文件夹，<b>保持 <code>Uninstall-KSVPN.cmd</code> 与 <code>KSVPN-uninstall.ps1</code> 在同一目录</b>。</li>
<li>双击 <code>Uninstall-KSVPN.cmd</code>，看到「KSVPN 客户端已卸载」即完成。</li>
</ol>
<p>脚本会自动结束客户端 / OpenVPN 进程、删除桌面与开始菜单快捷方式、移除「应用和功能」卸载项，
并删除 <code>%LOCALAPPDATA%\KSVPN</code>（含配置文件、证书、profile、记住的密码与日志）。</p>

<h3>二、正规卸载入口（新版安装包）</h3>
<p>用最新版 <code>KSVPN-Setup-v0.4.3.exe</code> 安装的客户端，也可直接在
「设置 → 应用 → 已安装的应用 → KSVPN → 卸载」，或点开始菜单的「卸载 KSVPN」。</p>

<h3>三、手动卸载</h3>
<ol>
<li>退出客户端并断开连接，删除桌面「KSVPN」快捷方式。</li>
<li>资源管理器地址栏输入 <code>%LOCALAPPDATA%</code> 回车，删除 <code>KSVPN</code> 文件夹。</li>
<li>若「应用」列表仍有残留，删除注册表项
<code>HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\KSVPN</code>。</li>
</ol>

<h3>四、是否连 OpenVPN 一起卸载</h3>
<p>安装包会自动安装 OpenVPN Community 2.7.8（含 TAP 虚拟网卡）。卸载脚本<b>默认不动它</b>，
避免影响其它依赖 OpenVPN 的软件。如需彻底移除：设置 → 应用 → 已安装的应用 → OpenVPN → 卸载（会弹 UAC），
完成后建议重启一次电脑。</p>`

	macSteps := `<h3>一、自动卸载（推荐）</h3>
<ol>
<li>先退出 KSVPN 客户端并断开 VPN 连接（点窗口右上角 X 会自动断开）。</li>
<li>解压附件，双击 <code>KSVPN-Uninstall.command</code>，在终端窗口按提示输入 Mac 登录密码。</li>
<li>看到「卸载完成」即结束。若提示「来自身份不明的开发者」：右键文件 → 打开 → 再点「打开」，
或先执行 <code>chmod +x KSVPN-Uninstall.command</code>。</li>
</ol>
<p>脚本会自动结束客户端 / OpenVPN 进程，按 <code>pkgutil</code> 安装收据删除
<code>.app</code>、OpenVPN 引擎、特权 helper 与 LaunchDaemon 后台服务，
并清理用户配置、证书、profile、日志与网关覆盖文件，最后 <code>pkgutil --forget</code> 清掉收据。</p>

<h3>二、手动卸载</h3>
<ol>
<li>退出客户端并断开连接，把「应用程序」里的 KSVPN.app 拖到废纸篓。</li>
<li>删除 <code>~/Library/Application Support/KSVPN/</code> 以及本客户端的旧数据目录。</li>
<li>删除 <code>/Library/LaunchDaemons/</code> 下本客户端的 service plist、
<code>/Library/PrivilegedHelperTools/</code> 下的 helper、
<code>/Library/Application Support/</code> 下的引擎目录（需要管理员权限）。</li>
<li>终端执行 <code>pkgutil --pkgs | grep -i vpn</code>，若还有本产品收据，执行
<code>sudo pkgutil --forget &lt;包标识符&gt;</code>。</li>
<li>清空废纸篓并重启一次 Mac。</li>
</ol>

<h3>三、注意</h3>
<p>卸载需要管理员密码；曾单独用 Homebrew 安装的 openvpn 不受本脚本影响，请自行
<code>brew uninstall openvpn</code>。卸载后如需重装，直接运行
<code>KSVPN-macOS13-arm64-Full-v0.5.0.pkg</code> 即可。</p>`

	steps := macSteps
	if platform == "windows" {
		steps = winSteps
	}
	tail := `<p style="color:#888;margin-top:18px">本邮件由系统发送，请勿回复。
卸载工具仅管理员可见，如需协助或重新安装请联系管理员。</p></div>`
	return subject, head + steps + tail
}

func ClientDownloadMail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
		Email    string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	name := cleanUploadName(req.Filename)
	email := strings.TrimSpace(req.Email)
	if !safeDownloadName(name) {
		util.Fail(w, "文件名不合法")
		return
	}
	if !reEmail.MatchString(email) {
		util.Fail(w, "请输入正确的邮箱地址")
		return
	}
	cfg := loadSMTP()
	path, generated := resolveClientDownload(name)
	if path == "" && !generated {
		util.Fail(w, "文件不存在")
		return
	}
	if cfg == nil || cfg.Host == "" || cfg.Port == 0 {
		util.Fail(w, "请先在「系统设置 → 邮件服务」配置 SMTP")
		return
	}
	var data []byte
	if generated { // 网关脚本按当前公网地址实时生成
		data = []byte(gatewayScript(r))
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			util.Fail(w, "读取文件失败: "+err.Error())
			return
		}
		data = b
	}
	if len(data) > 20<<20 {
		util.Fail(w, "文件超过 20MB，大多数邮箱拒收，请让用户从下载页直接下载")
		return
	}

	origin := ssoDerivedOrigin(r)
	subject, body := clientDownloadMailCompose(name, int64(len(data)), origin)
	if err := mail.SendWithAttachment(cfg, email, subject, body, name, data); err != nil {
		db.Syslog("admin", "邮件发送安装包失败", name+" → "+email+"："+err.Error(), clientIP(r))
		util.Fail(w, "发送失败: "+err.Error())
		return
	}
	db.Syslog("admin", "邮件发送安装包", name+" → "+email, clientIP(r))
	util.OKMsg(w, "已发送 "+name+" 到 "+email+"（附件 "+humanSize(int64(len(data)))+"，大附件请留意对方邮箱限制）", nil)
}
