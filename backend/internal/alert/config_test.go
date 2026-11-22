package alert

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateWebhookURLSSRF(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	lookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "good.example.com":
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		case "evil.example.com":
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		case "mixed.example.com":
			return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("192.168.1.10")}, nil
		default:
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
	}
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http 拒绝", "http://good.example.com/hook", true},
		{"空 URL 拒绝", "", true},
		{"localhost 拒绝", "https://localhost/hook", true},
		{"回环 IP 拒绝", "https://127.0.0.1/hook", true},
		{"A 类内网拒绝", "https://10.1.2.3/hook", true},
		{"B 类内网拒绝", "https://172.16.0.1/hook", true},
		{"C 类内网拒绝", "https://192.168.1.1/hook", true},
		{"IPv6 回环拒绝", "https://[::1]/hook", true},
		{"携带凭据拒绝", "https://u:p@good.example.com/hook", true},
		{"域名解析到内网拒绝", "https://evil.example.com/hook", true},
		{"多 A 记录含内网拒绝", "https://mixed.example.com/hook", true},
		{"公网 https 通过", "https://good.example.com/hook/token", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWebhookURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateWebhookURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestDedupWindow(t *testing.T) {
	dedupMu.Lock()
	dedup = map[string]time.Time{}
	dedupMu.Unlock()

	now := time.Now()
	key := "cert:server"
	if !shouldSend(key, now) {
		t.Fatal("首次应允许发送")
	}
	markSent(key, now)
	if shouldSend(key, now.Add(29*time.Minute)) {
		t.Fatal("29 分钟内不应重复发送")
	}
	if !shouldSend(key, now.Add(31*time.Minute)) {
		t.Fatal("超过 30 分钟应允许再次发送")
	}
	cleanupDedup(now.Add(31 * time.Minute))
	dedupMu.Lock()
	n := len(dedup)
	dedupMu.Unlock()
	if n != 0 {
		t.Fatalf("过期项应被清理，剩余 %d", n)
	}
}

func TestMaskURL(t *testing.T) {
	raw := "https://open.feishu.cn/open-apis/bot/v2/hook/SECRET_TOKEN?sign=ABC"
	masked := MaskURL(raw)
	if strings.Contains(masked, "SECRET_TOKEN") || strings.Contains(masked, "sign=ABC") {
		t.Fatalf("token 未打码：%s", masked)
	}
	if !strings.Contains(masked, "open.feishu.cn") {
		t.Fatalf("host 应保留便于排障：%s", masked)
	}
	c := Config{Enabled: true, Channels: []Channel{{Type: "webhook", URL: raw}}}
	out := MaskConfig(c)
	if out.Channels[0].URL == raw {
		t.Fatal("MaskConfig 未打码 URL")
	}
}

func TestValidateConfig(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	lookupIP = func(host string) ([]net.IP, error) { return []net.IP{net.ParseIP("1.1.1.1")}, nil }

	if err := ValidateConfig(Config{Channels: []Channel{{Type: "webhook", URL: "https://good.example.com/h"}}}); err != nil {
		t.Fatalf("合法配置应通过：%v", err)
	}
	if err := ValidateConfig(Config{Channels: []Channel{{Type: "email", Email: "ops@example.com"}}}); err != nil {
		t.Fatalf("合法邮箱渠道应通过：%v", err)
	}
	if err := ValidateConfig(Config{Channels: []Channel{{Type: "webhook", URL: "https://127.0.0.1/h"}}}); err == nil {
		t.Fatal("内网 webhook 应被拒绝")
	}
	if err := ValidateConfig(Config{Channels: []Channel{{Type: "unknown", URL: "https://good.example.com/h"}}}); err == nil {
		t.Fatal("未知渠道类型应被拒绝")
	}
}
