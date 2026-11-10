package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/vpn"
)

// 域名分流的增删改查：不依赖真实 DNS（直接写库，避免用例受网络影响）
func TestDomainRouteCRUD(t *testing.T) {
	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(3,'corp',1194,'udp','10.9.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,domain,note,enabled,ttl,ips,resolved_at,created_at,updated_at)
		VALUES(3,'oa.example.com','办公 OA',1,300,'203.0.113.7,203.0.113.8',1700000000,'','')`); err != nil {
		t.Fatal(err)
	}

	// 列表：要带出实例名与 IP 列表
	w, out := doJSON(t, DomainRouteList, "GET", "/api/v1/domainRoute/list", nil)
	if w.Code != 200 || out["code"] != float64(1) {
		t.Fatalf("list 失败: %d %s", w.Code, w.Body.String())
	}
	data, _ := out["data"].(map[string]any)
	list, _ := data["list"].([]any)
	if len(list) == 0 {
		t.Fatal("list 应至少返回一条规则")
	}
	first, _ := list[0].(map[string]any)
	if first["domain"] != "oa.example.com" || first["service_name"] != "corp（该实例所有用户）" {
		t.Errorf("列表字段异常: %v", first)
	}
	if ips, _ := first["ips"].([]any); len(ips) != 2 {
		t.Errorf("应解析出 2 个 IP，实际 %v", first["ips"])
	}

	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM domain_route WHERE domain='oa.example.com'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// 停用
	if w, _ := doJSON(t, DomainRouteUpdate, "POST", "/api/v1/domainRoute/update",
		map[string]any{"id": id, "enabled": 0}); w.Code != 200 {
		t.Fatalf("update 失败: %d %s", w.Code, w.Body.String())
	}
	var enabled int
	_ = db.DB.QueryRow(`SELECT enabled FROM domain_route WHERE id=?`, id).Scan(&enabled)
	if enabled != 0 {
		t.Errorf("enabled 应为 0，实际 %d", enabled)
	}
	if db.GetSetting("domain_route_dirty") == "" {
		t.Error("修改后应标记待生效")
	}

	// 删除
	if w, _ := doJSON(t, DomainRouteDelete, "POST", "/api/v1/domainRoute/delete",
		map[string]any{"id": id}); w.Code != 200 {
		t.Fatalf("delete 失败: %d %s", w.Code, w.Body.String())
	}
	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE id=?`, id).Scan(&cnt)
	if cnt != 0 {
		t.Error("规则未被删除")
	}
}

// 非法域名必须被拒（避免把 IP / 通配符塞进域名表）
func TestDomainRouteAddRejectsBadInput(t *testing.T) {
	cases := []map[string]any{
		{"domain": ""},
		{"domain": "10.0.0.1"},
		{"domain": "*.example.com"},
		{"domain": "not_a_domain"},
	}
	for _, c := range cases {
		w, out := doJSON(t, DomainRouteAdd, "POST", "/api/v1/domainRoute/add", c)
		if out["code"] == float64(1) {
			t.Errorf("非法输入 %v 应被拒绝: %d %s", c["domain"], w.Code, w.Body.String())
		}
	}
}

// 按用户下发：一个域名可以同时给多个用户，规则落在 username 上
func TestDomainRoutePerUser(t *testing.T) {
	oldBase := vpn.BaseDir
	vpn.BaseDir = t.TempDir()
	t.Cleanup(func() { vpn.BaseDir = oldBase })

	if _, err := db.DB.Exec(`DELETE FROM domain_route`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO service(id,name,port,proto,subnet,mask,status)
		VALUES(5,'corp5',1194,'udp','10.11.0.0','255.255.255.0',1)`); err != nil {
		t.Fatal(err)
	}

	w, out := doJSON(t, DomainRouteAdd, "POST", "/api/v1/domainRoute/add", map[string]any{
		"domain": "oa.example.com", "service_id": 5, "username": "alice, bob", "ttl": 300, "enabled": 1,
	})
	if out["code"] != float64(1) {
		t.Fatalf("批量添加失败: %d %s", w.Code, w.Body.String())
	}
	data, _ := out["data"].(map[string]any)
	if data["added"] != float64(2) {
		t.Errorf("应新增 2 个用户，实际 %v", data["added"])
	}

	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE username IN ('alice','bob') AND domain='oa.example.com'`).Scan(&cnt)
	if cnt != 2 {
		t.Fatalf("库里应有 2 条用户规则，实际 %d", cnt)
	}

	// 列表要能区分用户维度与实例级
	_, lout := doJSON(t, DomainRouteList, "GET", "/api/v1/domainRoute/list", nil)
	ldata, _ := lout["data"].(map[string]any)
	for _, item := range ldata["list"].([]any) {
		row := item.(map[string]any)
		if row["scope_user"] != true || row["username"] == "" {
			t.Errorf("用户维度规则标记异常: %v", row)
		}
	}

	// 解析结果入库后，同步应把 /32 路由写进该用户的 CCD
	if _, err := db.DB.Exec(`UPDATE domain_route SET ips='203.0.113.7' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := vpn.SyncDomainCcd(db.DB, []vpn.DomainRouteScope{{ServiceID: 5, Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", "corp5", "ccd", "alice"))
	if err != nil {
		t.Fatalf("CCD 文件未生成: %v", err)
	}
	if !strings.Contains(string(raw), `push "route 203.0.113.7 255.255.255.255"`) {
		t.Errorf("CCD 缺少域名路由:\n%s", raw)
	}

	// 删除规则后重写文件，路由应消失
	var id int64
	_ = db.DB.QueryRow(`SELECT id FROM domain_route WHERE username='alice'`).Scan(&id)
	if _, delOut := doJSON(t, DomainRouteDelete, "POST", "/api/v1/domainRoute/delete", map[string]any{"id": id}); delOut["code"] != float64(1) {
		t.Fatalf("删除失败: %v", delOut)
	}
	raw, _ = os.ReadFile(filepath.Join(vpn.BaseDir, "instance", "corp5", "ccd", "alice"))
	if strings.Contains(string(raw), "203.0.113.7") {
		t.Errorf("删除规则后不应残留路由:\n%s", raw)
	}
}
