package vpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

// 按用户的域名分流：路由只下发给指定用户，写进 CCD 文件（用户重连生效，不重启实例）
func TestDomainRouteForUserScoped(t *testing.T) {
	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	mustExec := func(q string, args ...any) {
		if _, err := db.DB.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(0,'alice','oa.example.com',1,'203.0.113.7,203.0.113.8',1,300)`)
	mustExec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(0,'bob','erp.example.com',1,'198.51.100.5',1,300)`)
	// 实例级（无用户名）不应出现在用户路由里
	mustExec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(0,'','global.example.com',1,'192.0.2.1',1,300)`)
	// 停用的不算
	mustExec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(0,'alice','off.example.com',0,'192.0.2.9',1,300)`)

	got := DomainRouteForUser(db.DB, 12, "alice")
	want := []string{"203.0.113.7 255.255.255.255", "203.0.113.8 255.255.255.255"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("alice 路由 = %v, want %v", got, want)
	}
	if got := DomainRouteForUser(db.DB, 12, "nobody"); len(got) != 0 {
		t.Errorf("未配置的用户不应有路由，实际 %v", got)
	}
	// 用户名大小写不敏感
	if got := DomainRouteForUser(db.DB, 12, "ALICE"); len(got) != 2 {
		t.Errorf("用户名应大小写不敏感，实际 %v", got)
	}
}

// RenderCcd 追加域名路由：与 push_routes 去重；raw 模式也要带上
func TestRenderCcdAppendsDomainRoutes(t *testing.T) {
	extra := []string{"203.0.113.7 255.255.255.255", "203.0.113.8 255.255.255.255"}

	out := RenderCcd(&Ccd{Username: "alice", PushRoutes: "203.0.113.7 255.255.255.255", ExtraRoutes: extra})
	if strings.Count(out, "route 203.0.113.7") != 1 {
		t.Errorf("与 push_routes 重复的路由不应二次推送:\n%s", out)
	}
	if !strings.Contains(out, `push "route 203.0.113.8 255.255.255.255"`) {
		t.Errorf("缺少域名路由:\n%s", out)
	}
	if !strings.Contains(out, "域名分流") {
		t.Errorf("应带说明注释:\n%s", out)
	}

	raw := RenderCcd(&Ccd{Username: "alice", Raw: "push \"dhcp-option DNS 8.8.8.8\"\n", ExtraRoutes: extra})
	if !strings.Contains(raw, "dhcp-option DNS 8.8.8.8") || !strings.Contains(raw, "203.0.113.7") {
		t.Errorf("raw 模式下也需追加域名路由:\n%s", raw)
	}

	// 没有域名规则时输出与原来一致（不产生多余注释）
	if plain := RenderCcd(&Ccd{Username: "alice", PushRoutes: "10.0.0.0 255.0.0.0"}); strings.Contains(plain, "域名分流") {
		t.Errorf("无域名规则时不应写注释:\n%s", plain)
	}
}

// WriteCcdWithDomain：没有 CCD 记录的用户也要生成文件（只含路由，不动 ifconfig-push）
func TestWriteCcdWithDomainWithoutRecord(t *testing.T) {
	oldBase := BaseDir
	BaseDir = t.TempDir()
	t.Cleanup(func() { BaseDir = oldBase })

	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DELETE FROM ccd`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(77,'corp77',1194,'udp','10.9.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(77,'alice','oa.example.com',1,'203.0.113.7',1,300)`); err != nil {
		t.Fatal(err)
	}

	if err := WriteCcdWithDomain(db.DB, "corp77", 77, "alice"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(BaseDir, "instance", "corp77", "ccd", "alice")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("CCD 文件未生成: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `push "route 203.0.113.7 255.255.255.255"`) {
		t.Errorf("CCD 缺少域名路由:\n%s", body)
	}
	if strings.Contains(body, "ifconfig-push") {
		t.Errorf("没有 CCD 记录时不应凭空写 ifconfig-push:\n%s", body)
	}

	// 已有 CCD 记录（含固定 IP）时，两者都要在
	if _, err := db.DB.Exec(`INSERT INTO ccd(service_id,username,ifconfig_push,dns)
		VALUES(77,'bob','10.9.0.50 255.255.255.0','223.5.5.5')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(77,'bob','erp.example.com',1,'198.51.100.5',1,300)`); err != nil {
		t.Fatal(err)
	}
	if err := WriteCcdWithDomain(db.DB, "corp77", 77, "bob"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(BaseDir, "instance", "corp77", "ccd", "bob"))
	body = string(raw)
	for _, want := range []string{"ifconfig-push 10.9.0.50", "dhcp-option DNS 223.5.5.5", "route 198.51.100.5"} {
		if !strings.Contains(body, want) {
			t.Errorf("CCD 缺少 %q:\n%s", want, body)
		}
	}
}

// SyncAllDomainCcd 启动时的全量重建
func TestSyncAllDomainCcd(t *testing.T) {
	oldBase := BaseDir
	BaseDir = t.TempDir()
	t.Cleanup(func() { BaseDir = oldBase })

	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DELETE FROM ccd`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(78,'corp78',1194,'udp','10.9.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,enabled,ips,resolved_at,ttl)
		VALUES(78,'carol','oa.example.com',1,'203.0.113.7',1,300)`); err != nil {
		t.Fatal(err)
	}
	n, err := SyncAllDomainCcd(db.DB)
	if err != nil || n == 0 {
		t.Fatalf("全量同步失败: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(BaseDir, "instance", "corp78", "ccd", "carol")); err != nil {
		t.Errorf("CCD 文件应存在: %v", err)
	}
}
