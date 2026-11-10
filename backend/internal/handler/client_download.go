package handler

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sslvpn/internal/middleware"
)

// 桌面客户端安装包下载页。
// 文件来源：管理员上传的卷内 /var/lib/sslvpn/downloads（重建容器不丢）优先，
// 镜像内置 /opt/sslvpn-client 作为兜底；两个目录按「安装包类型」合并，
// 上传了某平台的新包就自动替换掉该平台的内置包，其它平台不受影响。
var (
	customDownloadDir  = "/var/lib/sslvpn/downloads"
	builtinDownloadDir = "/opt/sslvpn-client"
)

// gatewayScriptName 按当前公网地址动态生成的网关配置脚本
const gatewayScriptName = "configure-gateway.ps1"

// 卸载工具包：内置可下载，但仅管理员可见；需要时用后台「✉ 发送」发给指定个人。
const (
	winUninstallName = "KSVPN-Windows-Uninstall.zip"
	macUninstallName = "KSVPN-macOS-Uninstall.zip"
)

func isUninstallTool(name string) bool {
	return name == winUninstallName || name == macUninstallName
}

// uninstallPlatform 返回卸载包对应平台，供分组、排序与邮件教程使用。
func uninstallPlatform(name string) string {
	switch name {
	case winUninstallName:
		return "windows"
	case macUninstallName:
		return "macos"
	}
	return ""
}

// adminOnlyDownload 单文件级门禁：源码包与卸载工具仅管理员可见。
// 普通用户在下载页看不到、直链也会被 403 拦截；管理员可下载或用邮件发给个人。
func adminOnlyDownload(name string) bool {
	return isUninstallTool(name) || downloadPlatformKey(name) == "macos-source"
}

// safeDownloadName 只允许纯文件名 + 安装包/文档扩展名，杜绝路径穿越与任意文件读取
func safeDownloadName(name string) bool {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	if strings.ContainsAny(name, "\x00\r\n\"'") {
		return false
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{".exe", ".msi", ".zip", ".dmg", ".pkg", ".txt", ".md", ".ps1"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// downloadPlatformKey 安装包按平台归类，用于「上传包替换内置同平台包」。
// 源码包单独一类，避免上传 .pkg 时把 .zip 源码包一起隐藏；脚本/文档不参与。
func downloadPlatformKey(name string) string {
	// 卸载工具不参与平台归类与版本去重：它们与 macOS 源码包同为 .zip，
	// 若共用 macos-source 键，会被同平台最高版本去重逻辑互相挤掉。
	if isUninstallTool(name) {
		return ""
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".msi":
		return "windows"
	case ".pkg", ".dmg":
		return "macos"
	case ".zip":
		return "macos-source"
	default:
		return ""
	}
}

var reVersion = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

// extractVersion 从文件名提取语义版本号（vX.Y.Z），用于内置安装包去重时比较新旧。
func extractVersion(name string) ([3]int, bool) {
	m := reVersion.FindStringSubmatch(strings.ToLower(name))
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

// versionGreater 比较两个语义版本号，a>b 返回 true。
func versionGreater(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

type clientDownloadItem struct {
	Name      string
	URL       string
	Size      string
	Platform  string
	Desc      string
	Source    string // custom=管理员上传 / builtin=镜像内置
	AdminOnly bool   `json:"admin_only"` // 仅管理员可见（源码包 / 卸载工具）
}

func downloadMeta(name string) (platform, desc string) {
	if p := uninstallPlatform(name); p != "" {
		if p == "windows" {
			return "Windows", "Windows 客户端卸载工具（仅管理员可见）：解压后双击 Uninstall-KSVPN.cmd，自动清理进程、快捷方式、卸载项与本地配置"
		}
		return "macOS", "macOS 客户端卸载工具（仅管理员可见）：解压后双击 KSVPN-Uninstall.command，清理应用、后台服务、引擎与用户配置"
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".pkg") || strings.HasSuffix(lower, ".dmg"):
		return "macOS", "macOS 全量安装包（自带 OpenVPN 2.7.8 引擎），Apple Silicon / macOS 13+，双击直接安装"
	case strings.Contains(lower, "macos") && strings.Contains(lower, "source"):
		return "macOS", "SwiftUI 客户端源码包（可自定义网关），在 Mac 上按包内 README 编译 .app"
	case strings.Contains(lower, "macos") || strings.HasSuffix(lower, ".zip"):
		return "macOS", "macOS 客户端资源包，按包内 README 使用"
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".msi"):
		return "Windows", "Windows 客户端安装包（已内置 OpenVPN 2.7.8），下载后直接运行安装"
	case strings.HasSuffix(lower, ".ps1"):
		return "Windows", "装完运行一次，把客户端认证网关指向当前服务器（仅 Windows 客户端需要）"
	default:
		return "通用", "客户端相关文件"
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, u := range []string{"KB", "MB", "GB"} {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f TB", v)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// clientDownloadItems 合并两个来源的文件列表，custom 同名优先，
// custom 里已有某平台安装包时跳过内置的同平台包。
func clientDownloadItems() []clientDownloadItem {
	customKeys := map[string]bool{}
	if entries, err := os.ReadDir(customDownloadDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && safeDownloadName(e.Name()) {
				if k := downloadPlatformKey(e.Name()); k != "" {
					customKeys[k] = true
				}
			}
		}
	}
	seen := map[string]bool{}
	items := []clientDownloadItem{}
	// 内置目录里可能并存多个版本的同平台安装包（例如增量解包时旧包未被清理，
	// v0.4.6 与 v0.5.0 同时留存在镜像内置目录）。只保留版本号最高的内置包，
	// 避免下载页列出已被取代的旧包。无版本号的辅助文件（如说明文档）不参与去重。
	type bestEntry struct {
		name string
		ver  [3]int
	}
	bestBuiltin := map[string]bestEntry{}
	if bentries, err := os.ReadDir(builtinDownloadDir); err == nil {
		for _, e := range bentries {
			if e.IsDir() || !safeDownloadName(e.Name()) {
				continue
			}
			k := downloadPlatformKey(e.Name())
			if k == "" {
				continue
			}
			v, ok := extractVersion(e.Name())
			if !ok {
				continue
			}
			// 同版本时取文件名靠后者：重新打包并更换命名（如统一品牌前缀）后，
			// 增量解包残留的旧命名包会被新命名包覆盖，不会重新出现在下载页。
			if cur, exists := bestBuiltin[k]; !exists || versionGreater(v, cur.ver) ||
				(v == cur.ver && e.Name() > cur.name) {
				bestBuiltin[k] = bestEntry{e.Name(), v}
			}
		}
	}
	for _, src := range []struct{ dir, tag string }{
		{customDownloadDir, "custom"},
		{builtinDownloadDir, "builtin"},
	} {
		entries, err := os.ReadDir(src.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !safeDownloadName(name) || seen[name] {
				continue
			}
			if src.tag == "builtin" {
				if k := downloadPlatformKey(name); k != "" {
					// 同平台只展示版本号最高的内置包，跳过被取代的旧版本
					if best, ok := bestBuiltin[k]; ok && best.name != name {
						continue
					}
				}
				if k := downloadPlatformKey(name); k != "" && customKeys[k] {
					continue
				}
			}
			st, err := e.Info()
			if err != nil {
				continue
			}
			seen[name] = true
			platform, desc := downloadMeta(name)
			size := humanSize(st.Size())
			if name == gatewayScriptName && src.tag == "builtin" {
				desc = "按当前「全局设置 → 公网地址」自动生成，域名与端口自动跟随"
				size = "自动生成"
			}
			items = append(items, clientDownloadItem{
				Name: name, URL: "/downloads/" + url.PathEscape(name), Size: size,
				Platform: platform, Desc: desc, Source: src.tag,
				AdminOnly: adminOnlyDownload(name),
			})
		}
	}
	// 主安装包排在前面：用户在 macOS 页第一眼应看到可双击安装的 pkg，
	// 而不是需要自行编译的源码包；网关脚本排在最后。
	sort.Slice(items, func(i, j int) bool {
		ri, rj := downloadItemRank(items[i].Name), downloadItemRank(items[j].Name)
		if ri != rj {
			return ri < rj
		}
		return items[i].Name < items[j].Name
	})
	return items
}

// downloadItemRank 列表排序权重：主安装包 → 源码包 → 配置脚本 → 卸载工具
func downloadItemRank(name string) int {
	if isUninstallTool(name) {
		return 3
	}
	switch downloadPlatformKey(name) {
	case "windows", "macos":
		return 0
	case "macos-source":
		return 1
	}
	if strings.HasSuffix(strings.ToLower(name), ".ps1") {
		return 2
	}
	return 3
}

// resolveClientDownload 返回实际文件路径；generated=true 表示该脚本由后端动态生成
func resolveClientDownload(name string) (path string, generated bool) {
	if p := filepath.Join(customDownloadDir, name); fileExists(p) {
		return p, false
	}
	if name == gatewayScriptName {
		return "", true
	}
	if p := filepath.Join(builtinDownloadDir, name); fileExists(p) {
		return p, false
	}
	return "", false
}

// gatewayScriptBody 网关配置脚本模板，__GATEWAY__ 由当前公网地址替换
const gatewayScriptBody = `#requires -Version 5.1
<#
  安装 KSVPN Windows 客户端后运行一次，把认证网关指向当前服务器。
  本文件由服务器下载页自动生成，网关地址跟随「全局设置 → 服务器公网地址」。
  用法：右键「使用 PowerShell 运行」，或命令行：
    powershell -ExecutionPolicy Bypass -File .\configure-gateway.ps1
  说明：客户端界面不暴露网关输入框，地址保存在 %LOCALAPPDATA%\KSVPN\client.json。
#>
param(
    [string]$Gateway = '__GATEWAY__'
)
$ErrorActionPreference = 'Stop'

$Gateway = $Gateway.Trim().TrimEnd('/')
if ($Gateway -notmatch '^https?://') {
    throw "网关地址必须以 http:// 或 https:// 开头，例如 https://vpn.example.com:58443"
}

$dir = Join-Path $env:LOCALAPPDATA 'KSVPN'
$cfg = Join-Path $dir 'client.json'
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$values = [ordered]@{}
if (Test-Path -LiteralPath $cfg) {
    try {
        $old = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
        foreach ($p in $old.PSObject.Properties) { $values[$p.Name] = $p.Value }
    } catch { }
}
if (-not $values.Contains('openvpn_exe')) {
    $values['openvpn_exe'] = 'C:\Program Files\OpenVPN\bin\openvpn.exe'
}
$values['gateway_url'] = $Gateway

[IO.File]::WriteAllText($cfg, ($values | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Host "已写入：$cfg" -ForegroundColor Green
Write-Host "认证网关：$Gateway" -ForegroundColor Green
Write-Host "注意：不要带 /feishu-sso 后缀；当前 Go 版服务端的 /api/v1/* 是绝对路径。" -ForegroundColor Yellow
Write-Host "重新打开客户端即可生效。" -ForegroundColor Green
`

// gatewayScript 生成带当前公网地址（含端口）的网关配置脚本
func gatewayScript(r *http.Request) string {
	origin := ssoDerivedOrigin(r)
	origin = strings.NewReplacer("'", "''", "\r", "", "\n", "").Replace(origin)
	return strings.ReplaceAll(gatewayScriptBody, "__GATEWAY__", origin)
}

// clientPlatform 按 User-Agent 判断访问者系统，让下载页只展示对应平台的安装包。
// ?platform=windows|macos|all 可手动覆盖，供管理员代下、UA 误判或帮同事下载时使用。
// 返回 "other" 表示未识别，此时展示全部文件并给出平台切换入口，不会把人挡在门外。
func clientPlatform(r *http.Request) string {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform"))) {
	case "windows", "win":
		return "windows"
	case "macos", "mac", "darwin":
		return "macos"
	case "all", "other", "unknown":
		return "other"
	}
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return "other"
	}
	if strings.Contains(ua, "windows") && !strings.Contains(ua, "windows phone") {
		return "windows"
	}
	// 移动端优先排除：iPadOS 会伪装成 Macintosh，部分 Android 平板 UA 也带 Macintosh 字样
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") ||
		strings.Contains(ua, "android") || strings.Contains(ua, "mobile") {
		return "other"
	}
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x") {
		return "macos"
	}
	return "other"
}

// downloadItemGroup 把安装包归到 windows / macos / common 三组，供下载页按平台筛选。
// 网关配置脚本是 PowerShell，仅 Windows 客户端需要；说明文档等 common 组两个平台都显示。
func downloadItemGroup(name string) string {
	if p := uninstallPlatform(name); p != "" {
		return p
	}
	switch downloadPlatformKey(name) {
	case "windows":
		return "windows"
	case "macos", "macos-source":
		return "macos"
	}
	if strings.HasSuffix(strings.ToLower(name), ".ps1") {
		return "windows"
	}
	return "common"
}

type clientDownloadsPage struct {
	Enabled       bool
	NeedLogin     bool
	Items         []clientDownloadItem // 当前平台 + 通用
	OtherItems    []clientDownloadItem // 其它平台，折叠收纳
	Platform      string               // windows / macos / other
	PlatformLabel string
	PlatformKnown bool
	Gateway       string
}

var clientDownloadsTmpl = template.Must(template.New("downloads").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>客户端下载 · KSVPN</title>
<style>
:root{--bg:#f5f7fa;--card:#fff;--line:#e3e8ef;--text:#1f2d3d;--sub:#6b7a90;--dark:#16202a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px 60px}
h1{font-size:26px;margin:0 0 6px} .sub{color:var(--sub);margin:0 0 26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 22px;margin-bottom:14px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.badge{font-size:12px;padding:3px 10px;border-radius:20px;background:#eef3f8;color:#40566e;white-space:nowrap}
.badge.custom{background:#e8f5e9;color:#2e7d32}
.info{flex:1;min-width:240px} .name{font-weight:600;word-break:break-all} .desc{color:var(--sub);font-size:13px}
a.dl{display:inline-block;background:var(--dark);color:#fff;text-decoration:none;padding:9px 20px;border-radius:8px;white-space:nowrap}
a.dl:hover{background:#2b3f52}
.tip{background:#eef7ff;border:1px solid #cfe6ff;border-radius:10px;padding:14px 18px;margin-top:24px;color:#274b6d;font-size:13px}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:12px;padding:38px 26px;text-align:center;color:var(--sub)}
.empty b{display:block;color:var(--text);font-size:17px;margin-bottom:8px}
.empty a{color:#185FA5}
code{background:#eef3f8;padding:2px 6px;border-radius:4px}
.pbar{background:#eaf5f1;border:1px solid #c9e6da;border-radius:10px;padding:12px 16px;margin-bottom:18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px;color:#225c49}
.pbar .ptag{background:#0f766e;color:#fff;border-radius:6px;padding:3px 10px;font-weight:600;white-space:nowrap}
.pbar .psp{flex:1;min-width:210px}
.pbar a{color:#0f766e;font-weight:600;text-decoration:none;white-space:nowrap;margin-left:14px}
.pbar a:hover{text-decoration:underline}
details.other{margin-top:18px;border:1px dashed var(--line);border-radius:10px;padding:12px 18px;background:#fafcfd}
details.other summary{cursor:pointer;color:var(--sub);font-size:13px;font-weight:600}
details.other .card{margin:12px 0 0;background:#fbfdfe}
.tseg{display:block;margin:7px 0}
.gwc{display:block;background:#0f2233;color:#d7e7f5;padding:10px 12px;border-radius:8px;font:12px/1.5 Consolas,Menlo,monospace;word-break:break-all;user-select:all;margin:6px 0}
.copybtn{background:#0f766e;color:#fff;border:0;border-radius:6px;padding:5px 16px;font-size:12px;cursor:pointer}
.copybtn:hover{background:#0d665c}
</style></head><body><div class="wrap">
<h1>客户端下载</h1>
<p class="sub">KSVPN · 飞书扫码 / 本地账号 / LDAP 账号登录，自动获取个人配置</p>
{{if not .Enabled}}
<div class="empty"><b>客户端下载暂未开放</b>管理员尚未开启客户端下载，请稍后再试或联系管理员。</div>
{{else if .NeedLogin}}
<div class="empty"><b>请先登录管理后台</b>当前仅允许管理员登录后下载客户端。<br><br><a href="/">前往管理后台登录 →</a></div>
{{else}}
<div class="pbar">
<span class="ptag">{{if .PlatformKnown}}{{.PlatformLabel}}{{else}}全部平台{{end}}</span>
<span class="psp">{{if .PlatformKnown}}已按你的系统自动筛选，下面只显示 <b>{{.PlatformLabel}}</b> 客户端及所需工具。{{else}}未能识别你的系统，已显示全部安装包，请选择对应平台。{{end}}</span>
<span>{{if eq .Platform "windows"}}<a href="?platform=macos">我是 macOS 用户 →</a><a href="?platform=all">查看全部</a>{{end}}{{if eq .Platform "macos"}}<a href="?platform=windows">我是 Windows 用户 →</a><a href="?platform=all">查看全部</a>{{end}}{{if eq .Platform "other"}}<a href="?platform=windows">Windows</a><a href="?platform=macos">macOS</a>{{end}}</span>
</div>
{{range .Items}}
<div class="card"><span class="badge {{if eq .Source "custom"}}custom{{end}}">{{.Platform}}{{if eq .Source "custom"}} · 自定义{{end}}</span>
<div class="info"><div class="name">{{.Name}}</div><div class="desc">{{.Desc}} · {{.Size}}</div></div>
<a class="dl" href="{{.URL}}">下载</a></div>
{{end}}{{if not .Items}}<div class="empty"><b>当前系统暂无对应安装包</b>请管理员在「系统设置 → 客户端下载」上传，或展开下方查看其它平台。</div>{{end}}
{{if .OtherItems}}
<details class="other"><summary>为其它系统下载 / 查看全部（{{len .OtherItems}} 个）</summary>
{{range .OtherItems}}
<div class="card"><span class="badge {{if eq .Source "custom"}}custom{{end}}">{{.Platform}}{{if eq .Source "custom"}} · 自定义{{end}}</span>
<div class="info"><div class="name">{{.Name}}</div><div class="desc">{{.Desc}} · {{.Size}}</div></div>
<a class="dl" href="{{.URL}}">下载</a></div>
{{end}}</details>
{{end}}
<div class="tip"><b>首次使用必读{{if .PlatformKnown}} · {{.PlatformLabel}}{{end}}</b>
{{if or (eq .Platform "windows") (eq .Platform "other")}}
<span class="tseg"><b>Windows</b>：运行 <code>.exe</code> 安装包（已自带 OpenVPN 2.7.8，无需另装）；装完运行
<code>configure-gateway.ps1</code> 把认证网关指向本服务器。该脚本由服务器自动生成，当前网关为
<code>{{.Gateway}}</code>，换域名或端口后重新下载即可，<b>无需重新打安装包</b>。</span>
{{end}}
{{if or (eq .Platform "macos") (eq .Platform "other")}}
<span class="tseg"><b>macOS</b>（Apple Silicon / macOS 13+）：双击 <code>.pkg</code> 全量包（v0.5.0）即可，内含独立 OpenVPN 2.7.8 引擎和后台服务，
不依赖 Homebrew / Tunnelblick；支持本地账号 / LDAP / TOTP 动态码与飞书扫码登录。</span>
<span class="tseg"><b>换服务器 / 换域名</b>：v0.5.0 已内置本服务器网关，无需重新打安装包——把新地址写成一行写入
<code>~/Library/Application Support/KSVPN/gateway.txt</code> 即可覆盖（下面的一键命令会同时写入新版目录和已安装的旧版客户端目录）。
需要深度定制时改用源码包（仅管理员登录后可见），在 Mac 上执行 <code>bash build-macos.sh</code>。</span>
<span class="tseg"><b>终端一键改网关</b>：复制下面命令到 Mac 终端直接执行，即写入当前网关 <code>{{.Gateway}}</code>（同时兼容新旧客户端目录）：</span>
<span class="tseg"><code class="gwc" id="gwCmd">mkdir -p "$HOME/Library/Application Support/KSVPN"; for d in "$HOME/Library/Application Support"/KSVPN "$HOME/Library/Application Support"/*VPN; do [ -d "$d" ] || continue; printf '%s\n' '{{.Gateway}}' &gt; "$d/gateway.txt"; done</code><button class="copybtn" type="button" onclick="copyGwCmd(this)">复制</button></span>
{{end}}
<span class="tseg">网关地址写法：<code>https://域名:58443</code>，<b>不要</b>带 <code>/feishu-sso</code> 后缀。</span></div>
{{end}}
<script>
function copyGwCmd(b){var t=document.getElementById('gwCmd').textContent;var p=navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject();p.then(function(){b.textContent='已复制';setTimeout(function(){b.textContent='复制'},1500)}).catch(function(){var n=document.getElementById('gwCmd'),r=document.createRange();r.selectNodeContents(n);var s=window.getSelection();s.removeAllRanges();s.addRange(r)})}
</script>
</div></body></html>`))

// ClientDownloads GET /downloads —— 按开关与权限展示可下载的安装包
func ClientDownloads(w http.ResponseWriter, r *http.Request) {
	enabled, needLogin := downloadPageState(r)
	platform := clientPlatform(r)
	page := clientDownloadsPage{
		Enabled: enabled, NeedLogin: needLogin, Platform: platform,
		Gateway: ssoDerivedOrigin(r),
	}
	switch platform {
	case "windows":
		page.PlatformLabel, page.PlatformKnown = "Windows", true
	case "macos":
		page.PlatformLabel, page.PlatformKnown = "macOS", true
	default:
		page.PlatformLabel = "全部平台"
	}
	if enabled && !needLogin {
		// 源码包与卸载工具仅对已登录管理员可见，普通用户不展示、直链也拦截
		isAdmin := middleware.CheckRequest(r)
		// 主区只放当前平台 + 通用文件，其它平台收进折叠区，避免用户下错包
		for _, it := range clientDownloadItems() {
			if adminOnlyDownload(it.Name) && !isAdmin {
				continue
			}
			g := downloadItemGroup(it.Name)
			if !page.PlatformKnown || g == "common" || g == platform {
				page.Items = append(page.Items, it)
			} else {
				page.OtherItems = append(page.OtherItems, it)
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = clientDownloadsTmpl.Execute(w, page)
}

// ClientDownloadFile GET /downloads/<文件名>。与下载页共用同一套开关/权限校验，
// 防止绕过页面直接拿链接下载。
func ClientDownloadFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/downloads/")
	if !safeDownloadName(name) {
		http.Error(w, "文件名不合法", http.StatusBadRequest)
		return
	}
	if !downloadAllowed(r) {
		http.Error(w, "客户端下载未开放或需要管理员登录", http.StatusForbidden)
		return
	}
	// 源码包与卸载工具单独门禁：无论下载页是否对公众开放，都只允许管理员登录后下载
	if adminOnlyDownload(name) && !middleware.CheckRequest(r) {
		http.Error(w, "该文件仅管理员可下载", http.StatusForbidden)
		return
	}
	path, generated := resolveClientDownload(name)
	if generated {
		script := gatewayScript(r)
		writeDownload(w, name, int64(len(script)), strings.NewReader(script))
		return
	}
	if path == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	writeDownload(w, name, st.Size(), f)
}

func writeDownload(w http.ResponseWriter, name string, size int64, body io.Reader) {
	ascii := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '_'
		}
		return r
	}, name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii, url.PathEscape(name)))
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, body)
}
