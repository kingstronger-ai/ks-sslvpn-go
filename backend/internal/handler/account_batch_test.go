package handler

import (
	"testing"

	"sslvpn/internal/db"
)

// TestSelectedAccounts 覆盖批量勾选账号的 id 解析：去重、丢弃非法/不存在 id、上限与空选。
func TestSelectedAccounts(t *testing.T) {
	names := []string{"batch_sel_a", "batch_sel_b"}
	ids := make([]int64, 0, len(names))
	for _, name := range names {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name)
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
			VALUES(?,?,?,1,'')`, name, "-", "local"); err != nil {
			t.Fatal(err)
		}
		defer func(n string) { _, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, n) }(name)
		var id int64
		if err := db.DB.QueryRow(`SELECT id FROM account WHERE username=?`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	// 去重 + 丢弃 0 / 负数 / 不存在的 id，保持顺序
	got, err := selectedAccounts([]int64{ids[1], 0, -1, ids[0], ids[1], 99999999}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != ids[1] || got[1].ID != ids[0] {
		t.Fatalf("去重/过滤结果不符: %+v (want %v)", got, ids)
	}

	// 空选
	if _, err := selectedAccounts(nil, 100); err == nil {
		t.Fatal("空选应返回错误")
	}
	// 超过上限
	many := make([]int64, 101)
	for i := range many {
		many[i] = int64(i + 1)
	}
	if _, err := selectedAccounts(many, 100); err == nil {
		t.Fatal("超过上限应返回错误")
	}
	// 全部非法 → 空列表（不报错，由 handler 返回 0 个目标）
	empty, err := selectedAccounts([]int64{0, -5, 99999999}, 100)
	if err != nil || len(empty) != 0 {
		t.Fatalf("全非法 id 应返回空列表: err=%v len=%d", err, len(empty))
	}
}
