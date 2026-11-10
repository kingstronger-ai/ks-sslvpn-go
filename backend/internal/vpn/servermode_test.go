package vpn

import (
	"strings"
	"testing"
)

// 全局代理与分流两种模式：DNS 只在全局代理时推送
func TestRenderServerConfGlobalVsSplit(t *testing.T) {
	oldDNS := DNSProvider
	defer func() { DNSProvider = oldDNS }()
	DNSProvider = func() []string { return []string{"223.5.5.5", "8.8.8.8"} }

	base := Service{Name: "test", Port: 51194, Proto: "udp",
		Subnet: "10.8.0.0", Mask: "255.255.255.0", PushRoutes: "10.5.0.0 255.255.255.0"}

	// 勾选全局代理：redirect-gateway + DNS 都要有
	gw := base
	gw.RedirectGW = 1
	conf, err := RenderServerConf(&gw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(conf)
	for _, want := range []string{`push "redirect-gateway def1 bypass-dhcp"`,
		`push "dhcp-option DNS 223.5.5.5"`, `push "dhcp-option DNS 8.8.8.8"`,
		`push "route 10.5.0.0 255.255.255.0"`} {
		if !strings.Contains(text, want) {
			t.Errorf("全局代理模式缺少 %q:\n%s", want, text)
		}
	}

	// 未勾选：不能有 redirect-gateway，也不能推 DNS；路由仍要下发
	split := base
	split.RedirectGW = 0
	conf, err = RenderServerConf(&split)
	if err != nil {
		t.Fatal(err)
	}
	text = string(conf)
	if strings.Contains(text, "redirect-gateway") {
		t.Errorf("分流模式不应推送 redirect-gateway:\n%s", text)
	}
	if strings.Contains(text, "dhcp-option DNS") {
		t.Errorf("分流模式不应推送 DNS（DNS 应走客户端本地）:\n%s", text)
	}
	if !strings.Contains(text, `push "route 10.5.0.0 255.255.255.0"`) {
		t.Errorf("分流模式仍须下发推送路由:\n%s", text)
	}
}

// 用户级 CCD：全局模式未单独填 DNS 时沿用全局 DNS；仅内网模式不推 DNS
func TestRenderCcdDnsFollowsProxyMode(t *testing.T) {
	oldDNS := DNSProvider
	defer func() { DNSProvider = oldDNS }()
	DNSProvider = func() []string { return []string{"223.5.5.5"} }

	gw := RenderCcd(&Ccd{ProxyMode: 1})
	if !strings.Contains(gw, `push "dhcp-option DNS 223.5.5.5"`) {
		t.Errorf("全局模式未配 DNS 时应沿用全局 DNS:\n%s", gw)
	}

	intranet := RenderCcd(&Ccd{ProxyMode: 2})
	if strings.Contains(intranet, "dhcp-option DNS") {
		t.Errorf("仅内网模式不应推送 DNS:\n%s", intranet)
	}
}
