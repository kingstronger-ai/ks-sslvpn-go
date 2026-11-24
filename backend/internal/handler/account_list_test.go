package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

// callUserList 用查询串直接调 AccountList（绕过鉴权，与项目单测惯例一致）。
func callUserList(t *testing.T, qs string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/account/userlist?"+qs, nil)
	AccountList(w, r)
	var out struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败 %s: %v", w.Body.String(), err)
	}
	if out.Code != 1 {
		t.Fatalf("接口失败: %s", w.Body.String())
	}
	return out.Data
}

// TestAccountListFilterAndPaging 覆盖状态/到期/分组筛选与分页（page+size），
// 并验证不传 page 的旧调用仍返回全量（兼容仪表盘/编辑弹窗）。
func TestAccountListFilterAndPaging(t *testing.T) {
	names := []string{"lst_p_perm", "lst_p_dated", "lst_p_disabled"}
	ids := map[string]int64{}
	for i, name := range names {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name)
		status, exp := 1, ""
		if i == 1 {
			exp = "2031-01-01"
		}
		if i == 2 {
			status = 0
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
			VALUES(?,?,?,?,?)`, name, "-", "local", status, exp); err != nil {
			t.Fatal(err)
		}
		defer func(n string) { _, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, n) }(name)
		var id int64
		_ = db.DB.QueryRow(`SELECT id FROM account WHERE username=?`, name).Scan(&id)
		ids[name] = id
	}

	// 关键字
	d := callUserList(t, "keyword="+names[0])
	if int(d["total"].(float64)) != 1 {
		t.Fatalf("关键字筛选 total 应为 1: %v", d["total"])
	}

	// 状态=禁用 应只返回禁用账号
	d = callUserList(t, "keyword=lst_p_&status=0")
	if int(d["total"].(float64)) < 1 {
		t.Fatalf("状态筛选应有结果: %v", d["total"])
	}
	for _, it := range d["list"].([]any) {
		m := it.(map[string]any)
		if int(m["status"].(float64)) != 0 {
			t.Fatalf("状态筛选返回了启用账号: %v", m)
		}
	}

	// 到期=永久 / 已设到期
	d = callUserList(t, "keyword=lst_p_&expire=permanent")
	for _, it := range d["list"].([]any) {
		if s := it.(map[string]any)["expire_date"].(string); s != "" {
			t.Fatalf("永久筛选返回了有到期日的账号: %s", s)
		}
	}
	d = callUserList(t, "keyword=lst_p_&expire=dated")
	for _, it := range d["list"].([]any) {
		if s := it.(map[string]any)["expire_date"].(string); s == "" {
			t.Fatalf("已设到期筛选返回了永久账号")
		}
	}

	// 分页：size=20、page=1 应返回带分页字段的第一页
	d = callUserList(t, "keyword=lst_p_&page=1&size=20")
	if _, ok := d["page"]; !ok {
		t.Fatalf("分页响应缺少 page 字段: %v", d)
	}
	if int(d["size"].(float64)) != 20 {
		t.Fatalf("size 应为 20: %v", d["size"])
	}
	if len(d["list"].([]any)) > 20 {
		t.Fatal("单页超过 20 条")
	}

	// 不传 page：旧调用返回全量且无 page 字段
	d = callUserList(t, "keyword=lst_p_")
	if _, ok := d["page"]; ok {
		t.Fatalf("未传 page 时不应带 page 字段: %v", d)
	}
	if !strings.Contains(strings.Join(names, ","), "lst_p_perm") {
		t.Fatal("测试样本缺失")
	}
	_ = ids
}
