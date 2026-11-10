// 公共工具：SMTP 配置加载、认证文件同步
package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/mail"
)

// 默认发件邮箱（未配置 SMTP 时表单预填值，避免空发件人）
const defaultSenderEmail = "421381118@qq.com"

// loadSMTP 从 settings 读取 SMTP 配置；发件人/显示名缺省时回落到品牌默认值
func loadSMTP() *mail.Config {
	raw := db.GetSetting("smtp")
	c := &mail.Config{Port: 465, Sender: defaultSenderEmail, Title: defaultBrandName}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), c)
	}
	if strings.TrimSpace(c.Sender) == "" {
		c.Sender = defaultSenderEmail
	}
	if strings.TrimSpace(c.Title) == "" {
		c.Title = defaultBrandName
	}
	return c
}

func saveSMTP(c *mail.Config) {
	b, _ := json.Marshal(c)
	db.SetSetting("smtp", string(b))
}

// syncAuthFiles 将用户认证数据同步到文本文件（与原系统 user_passwd.txt/user_type.txt 行为对齐，
// 供外部脚本兼容读取；Go 版 auth-verify 直接读库，此文件仅作审计与兼容用途）
func syncAuthFiles() {
	authDir := os.Getenv("SSLVPN_AUTH_DIR")
	if authDir == "" {
		authDir = "/var/lib/sslvpn/auth"
	}
	_ = os.MkdirAll(authDir, 0o700)
	passFile := filepath.Join(authDir, "user_passwd.txt")
	typeFile := filepath.Join(authDir, "user_type.txt")

	rows, err := db.DB.Query(`SELECT username, password, auth_type FROM account WHERE status=1`)
	if err != nil {
		return
	}
	defer rows.Close()

	var passBuf, typeBuf []byte
	for rows.Next() {
		var u, p, t string
		if err := rows.Scan(&u, &p, &t); err != nil {
			continue
		}
		if t == "" {
			t = "local"
		}
		passBuf = append(passBuf, []byte(u+" "+p+"\n")...)
		typeBuf = append(typeBuf, []byte(u+":"+t+"\n")...)
	}
	_ = os.WriteFile(passFile, passBuf, 0o600)
	_ = os.WriteFile(typeFile, typeBuf, 0o600)
}

// refreshSNAT 根据所有运行实例网段刷新 NAT 伪装
func refreshSNAT() {
	iface := fw.OutInterface()
	rows, err := db.DB.Query(`SELECT subnet, mask FROM service WHERE status=1`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var subnet, mask string
		if rows.Scan(&subnet, &mask) == nil && subnet != "" {
			_ = fw.EnableSNAT(subnet+"/"+maskToCIDR(mask), iface)
		}
	}
}

// SetupSNAT 供启动流程调用：为所有启用实例网段重建 NAT 伪装（容器重建后 iptables 规则丢失）
func SetupSNAT() { refreshSNAT() }

func maskToCIDR(mask string) string {
	n := 0
	var o [4]int
	_, _ = fmt.Sscanf(mask, "%d.%d.%d.%d", &o[0], &o[1], &o[2], &o[3])
	for _, b := range o {
		for b > 0 {
			n += b & 1
			b >>= 1
		}
	}
	return strconv.Itoa(n)
}

// dbTime 把驱动返回的 DATETIME（RFC3339 UTC 字符串）转回 "2006-01-02 15:04:05" 本地显示
// SQLite 存的是本地墙上时间，驱动解析成 time.Time 后 JSON 会带 Z 后缀，这里去掉并还原
func dbTime(s string) string {
	if s == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return s
}

// vpnRemoteHost 客户端 .ovpn 的 remote 主机名：去掉协议与端口。
// 「服务器公网地址」允许写成 1.2.3.4:58443（管理页端口，供扫码回调拼接），
// 但 OpenVPN 连接端口取自实例监听端口，因此这里必须剥离端口。
func vpnRemoteHost(raw string) string {
	h := strings.TrimSpace(raw)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimSuffix(strings.TrimRight(h, "/"), "/")
	// IPv6 字面量 [::1]:8443 / 普通 host:port
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ":") {
		return h[:i]
	}
	return h
}
