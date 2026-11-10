package vpn

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"sslvpn/internal/util"
)

// DBPath auth-verify / LDAP 子进程使用的数据库路径。
// 优先级：SSLVPN_DB > SSLVPN_DATA_DIR/sslvpn.db > /var/lib/sslvpn/sslvpn.db
// （必须与主进程 db.Open 落盘位置一致，否则认证必然失败）
func DBPath() string {
	if p := os.Getenv("SSLVPN_DB"); p != "" {
		return p
	}
	if d := os.Getenv("SSLVPN_DATA_DIR"); d != "" {
		return strings.TrimRight(d, "/") + "/sslvpn.db"
	}
	return "/var/lib/sslvpn/sslvpn.db"
}

// VerifyVPNCredentials OpenVPN auth-user-pass-verify 回调入口。
// via-file 格式：第一行用户名，最后一行密码（含 TOTP 追加在密码后以逗号分隔可选）。
// 退出码 0=通过，1=拒绝。
func VerifyVPNCredentials(viaFile string) int {
	dbPath := DBPath()
	d, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return deny("数据库打开失败", "")
	}
	defer d.Close()

	raw, err := os.ReadFile(viaFile)
	if err != nil {
		return deny("认证文件读取失败", "")
	}
	lines := nonEmptyLines(string(raw))
	if len(lines) < 2 {
		return deny("认证文件格式错误", "")
	}
	username, password := lines[0], lines[len(lines)-1]
	// 管理员开启登录别名后，把邮箱 / UPN(DN) 解析成真实 VPN 用户名再校验，
	// 与配置下发链路保持一致；未开启或无法解析时保持原值，后续按「用户不存在」拒绝。
	if real, ok := ResolveLoginName(d, username); ok {
		username = real
	}

	var hash, authType, totpSecret string
	var status int
	err = d.QueryRow(`SELECT password, auth_type, totp_secret, status FROM account WHERE username=?`, username).
		Scan(&hash, &authType, &totpSecret, &status)
	if err == sql.ErrNoRows {
		return deny("用户不存在", username)
	}
	if err != nil {
		return deny("数据库查询失败", username)
	}
	if status != 1 {
		return deny("用户已被禁用", username)
	}
	// 过期检查
	var expire sql.NullString
	_ = d.QueryRow(`SELECT expire_date FROM account WHERE username=?`, username).Scan(&expire)
	if expire.Valid && expire.String != "" {
		if t, e := time.Parse("2006-01-02", expire.String); e == nil && time.Now().After(t.Add(24*time.Hour)) {
			return deny("账号已过期", username)
		}
	}

	// 飞书扫码登录：客户端把一次性口令填在「密码」位，形如 FS1.<base64url>
	// 必须在认证类型分支之前拦截：口令本身即凭证，与 auth_type 无关
	if strings.HasPrefix(password, FeishuTokenPrefix) {
		if ok, reason := ConsumeFeishuToken(d, username, password); ok {
			return allow(username, "飞书扫码")
		} else {
			return deny(reason, username)
		}
	}

	switch authType {
	case "ldap":
		// LDAP 认证走外部配置，由主进程提供的辅助脚本处理
		if ok := ldapBindCheck(username, password); ok {
			return allow(username, "LDAP")
		}
		return deny("LDAP 认证失败", username)
	case "totp":
		// 密码格式：password 或 password,TOTP
		pass, otp := password, ""
		if i := lastIndexComma(password); i > 0 {
			pass, otp = password[:i], password[i+1:]
		}
		if hash != pass { // totp 模式密码字段存明文口令（认证文件方式）
			return deny("密码错误", username)
		}
		if util.VerifyTOTP(totpSecret, otp) {
			return allow(username, "TOTP")
		}
		return deny("动态码验证失败", username)
	default: // local
		if hash == password {
			return allow(username, "本地")
		}
		return deny("密码错误", username)
	}
}

func lastIndexComma(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range splitLines(s) {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			line = trimCR(line)
			out = append(out, line)
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, trimCR(s[start:]))
	}
	return out
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

func allow(user, typ string) int {
	appendAccessLog(map[string]any{"date": time.Now().Format("2006-01-02 15:04:05"),
		"type": "认证成功(" + typ + ")", "msg": "用户名=" + user, "ip": authClientIP(),
		"id": util.RandomHex(8)})
	fmt.Println("OK")
	return 0
}

func deny(reason, user string) int {
	// 输出到 stdout，OpenVPN（verb 3）会写入日志，便于排查 AUTH_FAILED
	fmt.Printf("DENY: %s (user=%s)\n", reason, user)
	appendAccessLog(map[string]any{"date": time.Now().Format("2006-01-02 15:04:05"),
		"type": reason, "msg": "用户名=" + user, "ip": authClientIP(),
		"id": util.RandomHex(8)})
	return 1
}

// authClientIP 认证阶段客户端来源 IP（OpenVPN 回调环境变量 untrusted_ip）
func authClientIP() string {
	ip := os.Getenv("untrusted_ip")
	if ip == "" {
		ip = os.Getenv("trusted_ip")
	}
	if ip == "" {
		return "-"
	}
	if p := os.Getenv("untrusted_port"); p != "" {
		return ip + ":" + p
	}
	return ip
}

func appendAccessLog(entry map[string]any) {
	logDir := os.Getenv("SSLVPN_LOGDIR")
	if logDir == "" {
		logDir = "/var/lib/sslvpn/logs"
	}
	_ = os.MkdirAll(logDir, 0o755)
	f, err := os.OpenFile(fmt.Sprintf("%s/%s-openvpn-access.log", logDir, time.Now().Format("2006-01-02")),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(entry)
	_, _ = f.Write(append(b, '\n'))
}

// ldapBindCheck 由主进程注入实现（见 handler/ldap.go 的 SetLDAPChecker）
var LdapChecker func(username, password string) bool

func ldapBindCheck(username, password string) bool {
	if LdapChecker != nil {
		return LdapChecker(username, password)
	}
	return false
}
