package db

import "testing"

// 旧库的 domain_route 带 UNIQUE(service_id,domain)，无法同一域名按用户配多条；
// 迁移必须重建表并保留历史数据（旧数据 username=” 继续表示实例级）。
func TestMigrateDomainRouteUser(t *testing.T) {
	if err := Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
		}
	})

	for _, s := range []string{
		`DROP TABLE IF EXISTS domain_route`,
		`CREATE TABLE domain_route(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER DEFAULT 0,
			domain TEXT NOT NULL,
			note TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			ips TEXT DEFAULT '',
			resolved_at INTEGER DEFAULT 0,
			ttl INTEGER DEFAULT 300,
			last_error TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(service_id, domain))`,
		`INSERT INTO domain_route(service_id,domain,note,enabled,ips,resolved_at,ttl)
			VALUES(3,'oa.example.com','旧规则',1,'203.0.113.7',1700000000,300)`,
	} {
		if _, err := DB.Exec(s); err != nil {
			t.Fatal(err)
		}
	}

	if err := migrateDomainRouteUser(); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	var note, username, ips string
	if err := DB.QueryRow(`SELECT note,username,ips FROM domain_route WHERE domain='oa.example.com'`).
		Scan(&note, &username, &ips); err != nil {
		t.Fatalf("历史数据丢失: %v", err)
	}
	if note != "旧规则" || username != "" || ips != "203.0.113.7" {
		t.Errorf("历史数据未正确迁移: note=%q user=%q ips=%q", note, username, ips)
	}

	// 迁移后：同域名可配多个用户，同用户重复仍受唯一约束限制
	if _, err := DB.Exec(`INSERT INTO domain_route(service_id,username,domain) VALUES(3,'alice','oa.example.com')`); err != nil {
		t.Fatalf("应允许同域名按用户配置: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO domain_route(service_id,username,domain) VALUES(3,'alice','oa.example.com')`); err == nil {
		t.Error("同用户同域名重复应违反唯一约束")
	}
}
