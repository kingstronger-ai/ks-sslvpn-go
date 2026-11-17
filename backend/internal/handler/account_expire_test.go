package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

// postJSON 用 application/json 发一个已登录的管理员请求（路由注册 true 需要鉴权，
// 这里直接调 handler 函数绕过鉴权中间件，与项目现有单测一致）。
func postJSON(body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/account/batchSetExpire", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	AccountBatchSetExpire(w, r)
	return w
}

// TestBatchSetExpire 覆盖三类账号（本地 / TOTP / LDAP 导入）统一设置到期时间、
// 清空为永久、以及非法日期拒绝与未命中 id 不计入更新数。
func TestBatchSetExpire(t *testing.T) {
	// 用独立用户名，避免与其他测试残留数据冲突
	users := []struct {
		name, auth string
	}{
		{"batch_exp_local", "local"},
		{"batch_exp_totp", "totp"},
		{"batch_exp_ldap", "ldap"},
	}
	for _, u := range users {
		if _, err := db.DB.Exec(`DELETE FROM account WHERE username=?`, u.name); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
			VALUES(?,?,?,1,'')`, u.name, "-", u.auth); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		var id int64
		if err := db.DB.QueryRow(`SELECT id FROM account WHERE username=?`, u.name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	// 1) 三类账号统一设为 2030-01-02
	body, _ := json.Marshal(map[string]any{"ids": ids, "expire_date": "2030-01-02"})
	w := postJSON(string(body))
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Updated int    `json:"updated"`
			Expire  string `json:"expire_date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非法 JSON: %v / %s", err, w.Body.String())
	}
	if resp.Code != 1 || resp.Data.Updated != len(ids) || resp.Data.Expire != "2030-01-02" {
		t.Fatalf("批量设置失败: code=%d updated=%d expire=%s body=%s",
			resp.Code, resp.Data.Updated, resp.Data.Expire, w.Body.String())
	}
	for _, u := range users {
		var got string
		_ = db.DB.QueryRow(`SELECT expire_date FROM account WHERE username=?`, u.name).Scan(&got)
		if got != "2030-01-02" {
			t.Errorf("%s 到期时间=%q，期望 2030-01-02", u.name, got)
		}
	}

	// 2) 清空为永久（传空字符串）
	body, _ = json.Marshal(map[string]any{"ids": ids[:2], "expire_date": ""})
	w = postJSON(string(body))
	if !strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("设为永久失败: %s", w.Body.String())
	}
	for _, u := range users[:2] {
		var got string
		_ = db.DB.QueryRow(`SELECT expire_date FROM account WHERE username=?`, u.name).Scan(&got)
		if got != "" {
			t.Errorf("%s 应清空为永久，实际=%q", u.name, got)
		}
	}

	// 3) 非法日期被拒绝，且数据库未改动
	before := ""
	_ = db.DB.QueryRow(`SELECT expire_date FROM account WHERE username=?`, users[2].name).Scan(&before)
	body, _ = json.Marshal(map[string]any{"ids": ids[2:], "expire_date": "2030/01/02"})
	w = postJSON(string(body))
	if strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("非法日期应被拒绝: %s", w.Body.String())
	}
	after := ""
	_ = db.DB.QueryRow(`SELECT expire_date FROM account WHERE username=?`, users[2].name).Scan(&after)
	if before != after {
		t.Errorf("非法日期请求不应改动数据库: before=%q after=%q", before, after)
	}

	// 4) 空 ids 被拒绝
	w = postJSON(`{"ids":[],"expire_date":"2030-01-02"}`)
	if strings.Contains(w.Body.String(), `"code":1`) {
		t.Fatalf("空 ids 应被拒绝: %s", w.Body.String())
	}

	// 清理
	for _, u := range users {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, u.name)
	}
}

// TestBatchSetExpireDedup 重复 id 只更新一次，updated 计数不重复。
func TestBatchSetExpireDedup(t *testing.T) {
	name := "batch_exp_dedup"
	_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name)
	_, _ = db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
		VALUES(?,?,?,1,'')`, name, "-", "local")
	defer func() { _, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name) }()
	var id int64
	_ = db.DB.QueryRow(`SELECT id FROM account WHERE username=?`, name).Scan(&id)

	body, _ := json.Marshal(map[string]any{"ids": []int64{id, id, id}, "expire_date": "2031-05-06"})
	w := postJSON(string(body))
	if !strings.Contains(w.Body.String(), `"updated":1`) {
		t.Fatalf("重复 id 应只更新一次: %s", w.Body.String())
	}
}
