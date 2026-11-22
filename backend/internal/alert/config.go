// Package alert 实现可观测最小闭环的告警调度：证书 / 实例 / 磁盘 / 登录爆破四类规则，
// 30 分钟去重，多渠道推送（邮件、飞书、企微、钉钉、通用 webhook）。
package alert

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"sslvpn/internal/db"
)

// ConfigKey settings 表中的 KV 键
const ConfigKey = "alert_config"

// Channel 单个推送渠道。email 用 Email 作收件人；webhook 类用 URL。
type Channel struct {
	Type  string `json:"type"`            // email | feishu | wecom | dingtalk | webhook
	URL   string `json:"url,omitempty"`   // webhook 地址，必须 https 且非内网
	Email string `json:"email,omitempty"` // email 渠道收件人
}

// Config 告警配置
type Config struct {
	Enabled  bool      `json:"enabled"`
	Channels []Channel `json:"channels"`
}

// lookupIP 可注入，便于单测 SSRF 判定而不用真实 DNS。
var lookupIP = net.LookupIP

// LoadConfig 从 settings 读取告警配置；空配置返回 Enabled=false。
func LoadConfig() (Config, error) {
	var c Config
	raw := strings.TrimSpace(db.GetSetting(ConfigKey))
	if raw == "" {
		return c, nil
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, fmt.Errorf("alert_config 解析失败：%w", err)
	}
	return c, nil
}

// SaveConfig 校验配置后落库（复用 settings KV，不改表结构）。
func SaveConfig(c Config) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	db.SetSetting(ConfigKey, string(b))
	return nil
}

// ValidateConfig 校验渠道类型与 webhook URL 的 SSRF 约束。
func ValidateConfig(c Config) error {
	valid := map[string]bool{"email": true, "feishu": true, "wecom": true, "dingtalk": true, "webhook": true}
	for i, ch := range c.Channels {
		typ := strings.ToLower(strings.TrimSpace(ch.Type))
		if !valid[typ] {
			return fmt.Errorf("渠道[%d] 类型 %q 不支持（可选 email/feishu/wecom/dingtalk/webhook）", i, ch.Type)
		}
		if typ == "email" {
			if !strings.Contains(ch.Email, "@") {
				return fmt.Errorf("渠道[%d] 缺少合法收件邮箱", i)
			}
			continue
		}
		if err := ValidateWebhookURL(ch.URL); err != nil {
			return fmt.Errorf("渠道[%d] %w", i, err)
		}
	}
	return nil
}

// ValidateWebhookURL 强制 https，并拒绝解析到内网/回环/链路本地地址的 URL（防 SSRF）。
func ValidateWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("webhook URL 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("webhook URL 格式错误：%w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("webhook URL 必须使用 https（当前 %q）", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL 不允许携带用户名/密码")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL 缺少主机名")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("webhook URL 拒绝内网地址：localhost")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isForbiddenIP(ip) {
			return fmt.Errorf("webhook URL 拒绝内网地址：%s", host)
		}
		return nil
	}
	ips, err := lookupIP(host)
	if err != nil {
		return fmt.Errorf("webhook 域名解析失败：%w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("webhook 域名无可用解析结果")
	}
	for _, ip := range ips {
		if isForbiddenIP(ip) {
			return fmt.Errorf("webhook 域名解析到内网地址：%s", ip)
		}
	}
	return nil
}

// isForbiddenIP 覆盖 127/8、10/8、172.16/12、192.168/16、::1、169.254、0.0.0.0、组播。
func isForbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// MaskConfig 返回用于展示的配置副本：URL 的 path/query/fragment 打码，host 保留便于排障。
func MaskConfig(c Config) Config {
	out := c
	out.Channels = make([]Channel, len(c.Channels))
	for i, ch := range c.Channels {
		out.Channels[i] = ch
		if ch.URL != "" {
			out.Channels[i].URL = MaskURL(ch.URL)
		}
	}
	return out
}

// MaskURL 打码 URL 的敏感部分（token 通常在 path/query）。
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	u.User = nil
	u.Path = "/***"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
