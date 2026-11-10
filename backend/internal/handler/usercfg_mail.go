package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/vpn"
)

// pickUserService 取该用户应使用的服务实例名：
// 优先取所属分组关联的第一个服务；未分组/未关联则退回系统内第一个可用服务。
func pickUserService(a *Account) (string, error) {
	if a.GroupID > 0 {
		var name string
		err := db.DB.QueryRow(`SELECT s.name FROM group_service gs
			JOIN service s ON s.id=gs.service_id WHERE gs.group_id=? AND s.status=1
			ORDER BY s.id LIMIT 1`, a.GroupID).Scan(&name)
		if err == nil && name != "" {
			return name, nil
		}
	}
	var name string
	err := db.DB.QueryRow(`SELECT name FROM service WHERE status=1 ORDER BY id LIMIT 1`).Scan(&name)
	if err != nil || name == "" {
		return "", fmt.Errorf("没有可用的服务实例")
	}
	return name, nil
}

// buildUserCfgTgz 生成 "<用户名>_<实例>.tgz"，内含同名 .ovpn 客户端配置。
// 失败返回空（邮件仍会发出，仅无附件），不阻断通知流程。
func buildUserCfgTgz(a *Account) (string, []byte) {
	svcName, err := pickUserService(a)
	if err != nil {
		return "", nil
	}
	svc, err := serviceByName(svcName)
	if err != nil {
		return "", nil
	}
	host := vpnRemoteHost(db.GetSetting("public_host"))
	if host == "" {
		host = fw.OutInterfaceIP()
	}
	ovpn, err := vpn.BuildClientConf(svc.Name, a.Username, vpn.ClientConfData{
		Host: host, Port: svc.Port, Proto: svc.Proto, ServerName: svc.Name,
	})
	if err != nil {
		// 证书可能尚未签发（如早期导入的 LDAP 用户），补签后再试一次
		if vpn.IssueUserCert(a.Username) != nil {
			return "", nil
		}
		ovpn, err = vpn.BuildClientConf(svc.Name, a.Username, vpn.ClientConfData{
			Host: host, Port: svc.Port, Proto: svc.Proto, ServerName: svc.Name,
		})
		if err != nil {
			return "", nil
		}
	}
	inner := fmt.Sprintf("%s_%s.ovpn", a.Username, svc.Name)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{
		Name: inner, Mode: 0o644, Size: int64(len(ovpn)), Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(ovpn)
	_ = tw.Close()
	_ = gz.Close()
	return fmt.Sprintf("%s_%s.tgz", a.Username, svc.Name), buf.Bytes()
}

// isLDAP 是否 LDAP 认证账号（密码由域/LDAP 校验，系统内不发密码）
func isLDAP(a *Account) bool {
	return strings.EqualFold(strings.TrimSpace(a.AuthType), "ldap")
}

// isSSOScan 是否扫码登录账号（飞书/钉钉/企业微信，无本地密码，凭一次性口令连接）
func isSSOScan(a *Account) bool {
	switch strings.ToLower(strings.TrimSpace(a.AuthType)) {
	case "feishu", "sso", "dingtalk", "wecom":
		return true
	}
	return false
}

// pwdDisplay 邮件里"密码"一栏的展示文本
func pwdDisplay(a *Account) string {
	if isLDAP(a) {
		return `<span style="color:#409eff">LDAP 统一认证</span>（使用您的 LDAP/域账号密码，无需单独发放）`
	}
	if isSSOScan(a) {
		return `<span style="color:#409eff">扫码登录</span>（无需密码，客户端选择「飞书 / 钉钉 / 企业微信登录」扫码即可）`
	}
	if a.Password == "" || a.Password == "-" {
		return `-`
	}
	return `<b style="color:#f56c6c">` + htmlEscape(a.Password) + `</b>`
}

// installHint 邮件已附带客户端安装包时的使用说明：直接安装客户端、用账号登录即可，
// 不再提示“解压导入配置文件”。仅按实际勾选的平台描述，避免多出口径。
// 未开启（默认）时返回空串，由 authNote 走原有的配置文件提示。
func installHint() string {
	attach, _, win, mac := accountMailAttachMode()
	if !attach {
		return ""
	}
	var parts []string
	if win {
		parts = append(parts, "Windows 双击 <b>.exe</b>")
	}
	if mac {
		parts = append(parts, "macOS 双击 <b>.pkg</b>")
	}
	how := "附件中的客户端安装包"
	if len(parts) > 0 {
		how = strings.Join(parts, "、") + " 完成安装"
	}
	return `邮件已附带 VPN 客户端安装包：` + how + `，打开客户端后<b>直接使用上方账号密码登录</b>即可，<b>无需解压或导入配置文件</b>。`
}

// authNote 邮件末尾的动态说明（本地/LDAP 默认模板均含 {auth_note} 占位符）。
// 开启“账号邮件附件 → 附带客户端”后改为安装客户端即登录的说明；
// 默认关闭时保持原有的配置文件导入提示不变。
func authNote(a *Account) string {
	if h := installHint(); h != "" {
		switch {
		case isLDAP(a):
			return h + `<br>请妥善保管您的账户信息，建议首次登录后及时修改 LDAP 密码。`
		case isSSOScan(a):
			return `本账号通过 <b>扫码登录</b>，无需密码：打开 VPN 客户端后选择「飞书 / 钉钉 / 企业微信登录」，用手机扫码并在页面中确认，客户端会自动取回一次性凭证并完成连接。<br>` + h
		case strings.EqualFold(strings.TrimSpace(a.AuthType), "totp"):
			return `本账号已启用 <b>动态口令（TOTP）双重认证</b>：连接 VPN 时，在客户端的「密码」一栏请按 <b>密码,动态码</b> 格式填写——先输入登录密码，紧跟一个英文逗号，再输入身份验证器 App 当前显示的 6 位动态码（例如 <code>abc123,654321</code>）。<br>` + h
		}
		return h
	}
	if isLDAP(a) {
		return `请下载附件中的tgz 文件，解压后双击导入VPN客户端。请妥善保管您的账户信息，建议首次登录后及时修改LDAP密码。`
	}
	if isSSOScan(a) {
		return `本账号通过 <b>扫码登录</b>，无需密码：打开 VPN 客户端后选择「飞书 / 钉钉 / 企业微信登录」，用手机扫码并在页面中确认，客户端会自动取回一次性凭证并完成连接。<br>附件为该账号的 VPN 客户端配置文件，解压后导入 VPN 客户端即可使用。`
	}
	if strings.EqualFold(strings.TrimSpace(a.AuthType), "totp") {
		return `本账号已启用 <b>动态口令（TOTP）双重认证</b>：连接 VPN 时，在客户端的「密码」一栏请按 <b>密码,动态码</b> 格式填写——先输入登录密码，紧跟一个英文逗号，再输入身份验证器 App 当前显示的 6 位动态码（例如 <code>abc123,654321</code>）。<br>附件为该账号的 VPN 客户端配置文件，解压后导入 VPN 客户端即可使用。`
	}
	return `附件为该账号的 VPN 客户端配置文件，解压后导入 VPN 客户端即可使用。`
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
