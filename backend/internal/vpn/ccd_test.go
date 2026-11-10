package vpn

import (
	"strings"
	"testing"
)

func TestRenderCcdStructured(t *testing.T) {
	c := &Ccd{IfconfigPush: "10.8.0.100 255.255.255.0", Iroutes: "192.168.1.0 255.255.255.0\n\n",
		PushRoutes: "172.16.10.0 255.255.255.0", DNS: "223.5.5.5, 114.114.114.114"}
	out := RenderCcd(c)
	for _, want := range []string{
		"ifconfig-push 10.8.0.100 255.255.255.0",
		"iroute 192.168.1.0 255.255.255.0",
		`push "route 172.16.10.0 255.255.255.0"`,
		`push "dhcp-option DNS 223.5.5.5"`,
		`push "dhcp-option DNS 114.114.114.114"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "push-reset") || strings.Contains(out, "redirect-gateway") {
		t.Errorf("unexpected directives:\n%s", out)
	}
}

func TestRenderCcdProxyModes(t *testing.T) {
	gw := RenderCcd(&Ccd{ProxyMode: 1, PushRoutes: "10.0.0.0 255.0.0.0"})
	if !strings.Contains(gw, `push "redirect-gateway def1 bypass-dhcp"`) {
		t.Errorf("proxy_mode=1 should add redirect-gateway:\n%s", gw)
	}
	intranet := RenderCcd(&Ccd{ProxyMode: 2, PushRoutes: "10.0.0.0 255.0.0.0", DNS: "223.5.5.5"})
	lines := strings.Split(strings.TrimSpace(intranet), "\n")
	if lines[0] != "push-reset" && !strings.HasPrefix(lines[0], "#") {
		t.Errorf("proxy_mode=2 should start with push-reset:\n%s", intranet)
	}
	if !strings.Contains(intranet, `push "route 10.0.0.0 255.0.0.0"`) ||
		!strings.Contains(intranet, `push "dhcp-option DNS 223.5.5.5"`) {
		t.Errorf("proxy_mode=2 must keep own route/dns after push-reset:\n%s", intranet)
	}
	if strings.Contains(intranet, "redirect-gateway") {
		t.Errorf("proxy_mode=2 should not push redirect-gateway:\n%s", intranet)
	}
}

func TestRenderCcdRawWins(t *testing.T) {
	raw := "# 手工配置\npush \"redirect-gateway def1 bypass-dhcp\"\npush \"dhcp-option DNS 8.8.8.8\"\n"
	out := RenderCcd(&Ccd{Raw: raw, IfconfigPush: "10.8.0.9 255.255.255.0", ProxyMode: 1})
	if out != raw {
		t.Errorf("raw should be used verbatim, got:\n%s", out)
	}
}

func TestRenderCcdToleratePushLines(t *testing.T) {
	out := RenderCcd(&Ccd{PushRoutes: "push \"route 1.2.3.0 255.255.255.0\"\n10.0.0.0 255.0.0.0"})
	if !strings.Contains(out, "push \"route 1.2.3.0 255.255.255.0\"\n") {
		t.Errorf("full push line should pass through:\n%s", out)
	}
	if strings.Contains(out, "route push") {
		t.Errorf("should not double-wrap push line:\n%s", out)
	}
}
