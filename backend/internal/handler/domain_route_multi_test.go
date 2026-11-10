package handler

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/vpn"
)

// 批量域名：同一用户可添加多个域名，解析结果合并进同一个 CCD；重复添加幂等
func TestDomainRouteAddMulti(t *testing.T) {
	oldBase := vpn.BaseDir
	vpn.BaseDir = t.TempDir()
	t.Cleanup(func() { vpn.BaseDir = oldBase })

	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(7,'corp7',1194,'udp','10.12.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"domain":     "oa.example.com, erp.example.com\ncrm.example.com",
		"service_id": 7,
		"usernames":  []string{"alice", "bob"},
		"ttl":        300,
		"enabled":    1,
	}
	w, out := doJSON(t, DomainRouteAddMulti, "POST", "/api/v1/domainRoute/addMulti", body)
	if out["code"] != float64(1) {
		t.Fatalf("批量添加失败: %d %s", w.Code, w.Body.String())
	}
	data, _ := out["data"].(map[string]any)
	if data["added"] != float64(6) || data["domains"] != float64(3) || data["users"] != float64(2) {
		t.Fatalf("应新增 3 域名 × 2 用户 = 6 条，实际 %v", data)
	}

	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE username='alice'`).Scan(&cnt)
	if cnt != 3 {
		t.Fatalf("同一用户应落 3 条域名规则，实际 %d", cnt)
	}

	// 重复提交应整批跳过，不产生重复行
	_, again := doJSON(t, DomainRouteAddMulti, "POST", "/api/v1/domainRoute/addMulti", body)
	d2, _ := again["data"].(map[string]any)
	if d2["added"] != float64(0) || d2["skipped"] != float64(6) {
		t.Errorf("重复添加应全部跳过，实际 %v", d2)
	}
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route`).Scan(&cnt)
	if cnt != 6 {
		t.Errorf("重复添加后总行数应仍为 6，实际 %d", cnt)
	}

	// 解析结果写回后，同一用户的多个域名应合并进一个 CCD
	_, _ = db.DB.Exec(`UPDATE domain_route SET ips='203.0.113.7' WHERE username='alice' AND domain='oa.example.com'`)
	_, _ = db.DB.Exec(`UPDATE domain_route SET ips='203.0.113.8' WHERE username='alice' AND domain='erp.example.com'`)
	if _, err := vpn.SyncDomainCcd(db.DB, []vpn.DomainRouteScope{{ServiceID: 7, Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", "corp7", "ccd", "alice"))
	if err != nil {
		t.Fatalf("CCD 未生成: %v", err)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		if !strings.Contains(string(raw), `push "route `+ip+` 255.255.255.255"`) {
			t.Errorf("CCD 缺少 %s 的 /32 路由:\n%s", ip, raw)
		}
	}
}

// 域名批量规范化：分隔符、去重、非法域名整批拒绝、数量上限
func TestNormalizeDomainList(t *testing.T) {
	got, err := normalizeDomainList(" OA.Example.com , oa.example.com\nhttps://erp.example.com/x ", []string{"crm.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"oa.example.com", "erp.example.com", "crm.example.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("规范化结果不符: %v", got)
	}
	if _, err := normalizeDomainList("*.example.com", nil); err == nil {
		t.Error("通配符应被拒绝")
	}
	if _, err := normalizeDomainList("oa.example.com, 10.0.0.1", nil); err == nil {
		t.Error("IP 应被拒绝（且整批不写入）")
	}
	if _, err := normalizeDomainList("  \n ", nil); err == nil {
		t.Error("空输入应被拒绝")
	}
	big := make([]string, 51)
	for i := range big {
		big[i] = "host" + strconv.Itoa(i) + ".example.com"
	}
	if _, err := normalizeDomainList("", big); err == nil {
		t.Error("超过 50 个域名应被拒绝")
	}
}
