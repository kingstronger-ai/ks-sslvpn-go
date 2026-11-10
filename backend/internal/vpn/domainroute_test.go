package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"  OA.Example.COM ":            "oa.example.com",
		"https://gitlab.corp.local/ui": "gitlab.corp.local",
		"http://a.b.cn:8443/x?y=1":     "a.b.cn",
		"user@mail.example.com":        "mail.example.com",
		"host.example.com.":            "host.example.com",
	}
	for in, want := range ok {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "*", "*.example.com", "10.0.0.1", "http://", "no_tld", "a..b", "-bad.com"}
	for _, in := range bad {
		if got, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) 应报错，实际返回 %q", in, got)
		}
	}
}

func TestDedupeIPv4(t *testing.T) {
	got := dedupeIPv4([]string{"10.0.0.10", "10.0.0.2", "10.0.0.10", " ", "2001:db8::1", "bad"})
	want := []string{"10.0.0.2", "10.0.0.10"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dedupeIPv4 = %v, want %v", got, want)
	}
}

func TestResolveDomainIPv4(t *testing.T) {
	old := lookupIPv4
	defer func() { lookupIPv4 = old }()

	lookupIPv4 = func(ctx context.Context, host string) ([]string, error) {
		if host == "none.example.com" {
			return nil, errors.New("no such host")
		}
		if host == "v6.example.com" {
			return []string{"2001:db8::1"}, nil
		}
		return []string{"10.1.2.3", "10.1.2.4", "10.1.2.3"}, nil
	}
	ips, err := ResolveDomainIPv4(context.Background(), "oa.example.com")
	if err != nil || strings.Join(ips, ",") != "10.1.2.3,10.1.2.4" {
		t.Fatalf("解析结果异常: %v %v", ips, err)
	}
	if _, err := ResolveDomainIPv4(context.Background(), "none.example.com"); err == nil {
		t.Error("解析失败应返回错误")
	}
	if _, err := ResolveDomainIPv4(context.Background(), "v6.example.com"); err == nil {
		t.Error("只有 IPv6 时应报错（OpenVPN 无法按域名分流）")
	}
}

func TestDomainRouteLinesAndRefresh(t *testing.T) {
	old := lookupIPv4
	defer func() { lookupIPv4 = old }()
	lookupIPv4 = func(ctx context.Context, host string) ([]string, error) {
		return []string{"192.168.50.10", "192.168.50.11"}, nil
	}

	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,domain,enabled,ttl,ips,resolved_at)
		VALUES(0,'oa.example.com',1,300,'',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,domain,enabled,ttl,ips,resolved_at)
		VALUES(999,'off.example.com',0,300,'198.51.100.9',1)`); err != nil {
		t.Fatal(err)
	}

	changed, affected, err := RefreshDomainRoutes(db.DB, true)
	if err != nil || changed != 1 {
		t.Fatalf("刷新结果异常: changed=%d err=%v", changed, err)
	}
	if len(affected) != 1 || affected[0].ServiceID != 0 || affected[0].Username != "" {
		t.Errorf("受影响作用域应为 [{0 }]（全实例、实例级），实际 %v", affected)
	}

	lines := DomainRouteLines(db.DB, 12)
	want := "192.168.50.10 255.255.255.255,192.168.50.11 255.255.255.255"
	if strings.Join(lines, ",") != want {
		t.Errorf("DomainRouteLines = %v, want %s", lines, want)
	}

	// 关闭/别的实例的规则不应出现
	if _, err := db.DB.Exec(`UPDATE domain_route SET enabled=0 WHERE domain='oa.example.com'`); err != nil {
		t.Fatal(err)
	}
	if lines := DomainRouteLines(db.DB, 12); len(lines) != 0 {
		t.Errorf("禁用后不应再下发，实际 %v", lines)
	}
}

func TestRenderServerConfIncludesDomainRoutes(t *testing.T) {
	oldProvider := DomainRouteProvider
	oldDNS := DNSProvider
	defer func() { DomainRouteProvider = oldProvider; DNSProvider = oldDNS }()

	DomainRouteProvider = func(serviceID int64) []string {
		if serviceID != 7 {
			return nil
		}
		return []string{"203.0.113.5 255.255.255.255", "10.0.0.0 255.255.255.0"}
	}
	DNSProvider = func() []string { return nil }

	conf, err := RenderServerConf(&Service{ID: 7, Name: "test", Port: 1194, Proto: "udp",
		Subnet: "10.8.0.0", Mask: "255.255.255.0", PushRoutes: "10.0.0.0 255.255.255.0"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(conf)
	if !strings.Contains(text, `push "route 203.0.113.5 255.255.255.255"`) {
		t.Errorf("域名分流路由未写入 server.conf:\n%s", text)
	}
	if strings.Count(text, `push "route 10.0.0.0 255.255.255.0"`) != 1 {
		t.Errorf("重复路由应去重:\n%s", text)
	}
}

func TestAllServiceIDs(t *testing.T) {
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(7,'test',1194,'udp','10.8.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}
	ids := AllServiceIDs(db.DB)
	found := false
	for _, id := range ids {
		if id == 7 {
			found = true
		}
	}
	if !found {
		t.Errorf("AllServiceIDs 未包含实例 7: %v", ids)
	}
}
