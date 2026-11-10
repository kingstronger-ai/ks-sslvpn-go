// 证书自动签发/续签 API（阿里云 / 腾讯云 DNS-01）
package handler

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sslvpn/internal/acme"
	"sslvpn/internal/db"
	"sslvpn/internal/mail"
	"sslvpn/internal/util"
)

// ApplyTLSCertPEM 校验证书与私钥配对 → 落盘 → 热替换（ACME 签发与手工上传共用）
func ApplyTLSCertPEM(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	dir := sslDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), keyPEM, 0o600); err != nil {
		return err
	}
	SetWebTLSCert(&pair)
	return nil
}

// SendSystemMail 向所有绑定了邮箱的管理员发系统通知（证书到期提醒用）
func SendSystemMail(subject, html string) error {
	rows, err := db.DB.Query(`SELECT email FROM admin WHERE status=1 AND email<>''`)
	if err != nil {
		return err
	}
	var to []string
	for rows.Next() {
		var e string
		if rows.Scan(&e) == nil && strings.TrimSpace(e) != "" {
			to = append(to, strings.TrimSpace(e))
		}
	}
	rows.Close()
	if len(to) == 0 {
		return errNoAdminMail
	}
	cfg := loadSMTP()
	if cfg.Host == "" {
		return errNoSMTP
	}
	var lastErr error
	sent := 0
	for _, addr := range to {
		if err := mail.Send(cfg, addr, subject, html); err != nil {
			lastErr = err
			continue
		}
		sent++
	}
	if sent == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

var (
	errNoAdminMail = &certErr{"没有已绑定邮箱的管理员，无法发送提醒（到「管理员」页补充邮箱）"}
	errNoSMTP      = &certErr{"SMTP 未配置，无法发送提醒（到「邮件服务」页配置）"}
)

type certErr struct{ msg string }

func (e *certErr) Error() string { return e.msg }

// CertAutoGet 读取自动续签配置（凭证打码）与证书状态
func CertAutoGet(w http.ResponseWriter, r *http.Request) {
	c := acme.Load()
	st := acme.CurrentStatus()
	util.OK(w, map[string]any{
		"enabled":     c.Enabled,
		"domains":     strings.Join(c.Domains, ","),
		"email":       c.Email,
		"provider":    c.Provider,
		"access_key":  acme.Mask(c.AccessKey),
		"secret_key":  acme.Mask(c.SecretKey),
		"has_key":     c.AccessKey != "" && c.SecretKey != "",
		"days":        c.Days,
		"staging":     c.Staging,
		"status":      st,
		"source_name": certSourceName(st.Source),
	})
}

func certSourceName(s string) string {
	switch s {
	case "acme":
		return "Let's Encrypt 自动签发"
	case "upload":
		return "手工上传"
	default:
		return "内置自签证书"
	}
}

type certAutoReq struct {
	Enabled   bool   `json:"enabled"`
	Domains   string `json:"domains"`
	Email     string `json:"email"`
	Provider  string `json:"provider"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Days      int    `json:"days"`
	Staging   bool   `json:"staging"`
}

// merge 把请求合并到已存配置：凭证仍是打码值 / 空值时沿用旧凭证
func (req certAutoReq) merge() acme.Config {
	saved := acme.Load()
	c := acme.Config{
		Enabled:  req.Enabled,
		Email:    strings.TrimSpace(req.Email),
		Provider: strings.TrimSpace(req.Provider),
		Days:     req.Days,
		Staging:  req.Staging,
		Domains:  splitDomains(req.Domains),
	}
	c.AccessKey, c.SecretKey = saved.AccessKey, saved.SecretKey
	if ak := strings.TrimSpace(req.AccessKey); ak != "" && !strings.Contains(ak, "***") {
		c.AccessKey = ak
	}
	if sk := strings.TrimSpace(req.SecretKey); sk != "" && !strings.Contains(sk, "***") {
		c.SecretKey = sk
	}
	if c.Provider == "" {
		c.Provider = saved.Provider
	}
	if c.Days <= 0 {
		c.Days = 30
	}
	return c
}

func splitDomains(s string) []string {
	out := []string{}
	for _, d := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// CertAutoSave 保存配置（凭证 AES-GCM 加密入库）
func CertAutoSave(w http.ResponseWriter, r *http.Request) {
	var req certAutoReq
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	c := req.merge()
	if req.Enabled && (len(c.Domains) == 0 || c.Email == "") {
		util.Fail(w, "开启自动续签需填写域名与邮箱")
		return
	}
	if err := acme.Save(c); err != nil {
		util.Fail(w, "保存失败: "+err.Error())
		return
	}
	db.Syslog("admin", "保存证书自动续签配置", strings.Join(c.Domains, ","), clientIP(r))
	util.OKMsg(w, "配置已保存", nil)
}

// CertAutoTestDNS 校验云 DNS 凭证（写一条临时 TXT 再删除）
func CertAutoTestDNS(w http.ResponseWriter, r *http.Request) {
	var req certAutoReq
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	c := req.merge()
	if err := acme.TestDNS(c); err != nil {
		util.Fail(w, "验证失败: "+err.Error())
		return
	}
	util.OKMsg(w, "凭证可用，已在 "+c.Domains[0]+" 上完成 TXT 读写测试并清理", nil)
}

// CertAutoIssue 立即签发/续签（异步执行，结果通过状态接口轮询）
func CertAutoIssue(w http.ResponseWriter, r *http.Request) {
	var req certAutoReq
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	c := req.merge()
	if len(c.Domains) == 0 {
		util.Fail(w, "请先填写域名")
		return
	}
	if c.Email == "" {
		util.Fail(w, "请填写 ACME 注册邮箱")
		return
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		util.Fail(w, "请先填写云 DNS 凭证")
		return
	}
	go func() {
		if _, err := acme.Issue(c); err != nil {
			log.Printf("证书签发失败: %v", err)
		}
	}()
	db.Syslog("admin", "手动触发证书签发", strings.Join(c.Domains, ","), clientIP(r))
	util.OKMsg(w, "已开始签发，通常 1-3 分钟；可点「刷新状态」查看结果", nil)
}

// CertAutoStatus 轮询状态
func CertAutoStatus(w http.ResponseWriter, r *http.Request) {
	st := acme.CurrentStatus()
	util.OK(w, map[string]any{"status": st, "source_name": certSourceName(st.Source)})
}
