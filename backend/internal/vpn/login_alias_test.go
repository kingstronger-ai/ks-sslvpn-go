package vpn

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func aliasTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	for _, s := range []string{
		`CREATE TABLE settings(k TEXT PRIMARY KEY, v TEXT)`,
		`CREATE TABLE account(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
			email TEXT DEFAULT '', login_aliases TEXT DEFAULT '', status INTEGER DEFAULT 1)`,
		`INSERT INTO account(username,email,login_aliases,status) VALUES
			('zhangsan','zhangsan@example.com','zhangsan@ad.local,qiang_wang@ad.local',1)`,
		`INSERT INTO account(username,email,login_aliases,status) VALUES
			('wqq','zhangsan@example.com','',1)`,
		`INSERT INTO account(username,email,login_aliases,status) VALUES
			('wq','only@example.com','',1)`,
		`INSERT INTO account(username,email,login_aliases,status) VALUES
			('disabled','off@example.com','',0)`,
	} {
		if _, err := d.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func setAlias(d *sql.DB, key, val string) {
	_, _ = d.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, val)
}

func TestResolveLoginNameShortAlwaysAllowed(t *testing.T) {
	d := aliasTestDB(t)
	// 开关全关（默认）时短账号仍可登录
	for _, name := range []string{"zhangsan", "wqq", "wq"} {
		got, ok := ResolveLoginName(d, name)
		if !ok || got != name {
			t.Fatalf("短账号 %q 应始终可用，得到 (%q,%v)", name, got, ok)
		}
	}
	// 别名在默认状态下必须拒绝
	for _, name := range []string{"zhangsan@example.com", "only@example.com", "zhangsan@ad.local"} {
		if got, ok := ResolveLoginName(d, name); ok {
			t.Fatalf("默认关闭时别名 %q 不应放行，得到 %q", name, got)
		}
	}
}

func TestResolveLoginNameMailSwitch(t *testing.T) {
	d := aliasTestDB(t)
	setAlias(d, SetAliasMail, "1")

	if got, ok := ResolveLoginName(d, "only@example.com"); !ok || got != "wq" {
		t.Fatalf("邮箱别名应解析为 wq，得到 (%q,%v)", got, ok)
	}
	// 大小写不敏感
	if got, ok := ResolveLoginName(d, "ONLY@EXAMPLE.COM"); !ok || got != "wq" {
		t.Fatalf("邮箱别名应忽略大小写，得到 (%q,%v)", got, ok)
	}
	// 两个账号共用一个邮箱 -> 歧义必须拒绝
	if got, ok := ResolveLoginName(d, "zhangsan@example.com"); ok {
		t.Fatalf("共用邮箱应拒绝登录，却解析为 %q", got)
	}
	// 禁用账号的邮箱不可登录
	if got, ok := ResolveLoginName(d, "off@example.com"); ok {
		t.Fatalf("禁用账号的邮箱应拒绝，却解析为 %q", got)
	}
}

func TestResolveLoginNameExplicitAliasBeatsAmbiguousEmail(t *testing.T) {
	d := aliasTestDB(t)
	setAlias(d, SetAliasMail, "1")
	setAlias(d, SetAliasUPN, "1")
	// 真实场景：短账号 zhangsan 与 DN zhangsan@example.com 无字符串对应关系，
	// 且多个账号共用同一「联系邮箱」。显式别名必须优先于歧义的 email 匹配。
	if _, err := d.Exec(`UPDATE account SET login_aliases='zhangsan@example.com,zhangsan@ad.local'
		WHERE username='zhangsan'`); err != nil {
		t.Fatal(err)
	}
	if got, ok := ResolveLoginName(d, "zhangsan@example.com"); !ok || got != "zhangsan" {
		t.Fatalf("显式别名应解析为 zhangsan，得到 (%q,%v)", got, ok)
	}
}

func TestResolveLoginNameUPNSwitch(t *testing.T) {
	d := aliasTestDB(t)
	setAlias(d, SetAliasUPN, "1")

	if got, ok := ResolveLoginName(d, "zhangsan@ad.local"); !ok || got != "zhangsan" {
		t.Fatalf("UPN 别名应解析为 zhangsan，得到 (%q,%v)", got, ok)
	}
	// 别名含下划线：验证 instr 字面匹配，不会被 LIKE 通配符误伤
	if got, ok := ResolveLoginName(d, "qiang_wang@ad.local"); !ok || got != "zhangsan" {
		t.Fatalf("含下划线的 UPN 应精确匹配，得到 (%q,%v)", got, ok)
	}
	if got, ok := ResolveLoginName(d, "qiangXwang@ad.local"); ok {
		t.Fatalf("下划线不应被当作通配符，却解析为 %q", got)
	}
	// 只开 UPN 时邮箱别名仍不可用
	if got, ok := ResolveLoginName(d, "only@example.com"); ok {
		t.Fatalf("未开启邮箱开关时不应放行，得到 %q", got)
	}
}

func TestResolveLoginNameInvalidInput(t *testing.T) {
	d := aliasTestDB(t)
	setAlias(d, SetAliasMail, "1")
	setAlias(d, SetAliasUPN, "1")
	for _, s := range []string{
		"", "   ", "a@b.com/../../x", "a@b.com*(uid=*)", "a b@c.com",
		"a@b.com;DROP TABLE account", string(make([]byte, 70)),
	} {
		if got, ok := ResolveLoginName(d, s); ok {
			t.Fatalf("非法输入 %q 不应放行，得到 %q", s, got)
		}
	}
	if _, ok := ResolveLoginName(nil, "zhangsan"); ok {
		t.Fatal("nil DB 应安全降级为拒绝")
	}
}

func TestResolveLoginNameMissingAliasColumnDegrades(t *testing.T) {
	// 老库尚未补 login_aliases 列时，UPN 查询失败应安全降级，不能 panic 或误放行。
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetMaxOpenConns(1)
	for _, s := range []string{
		`CREATE TABLE settings(k TEXT PRIMARY KEY, v TEXT)`,
		`CREATE TABLE account(id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, status INTEGER)`,
		`INSERT INTO account(username,email,status) VALUES('wq','only@example.com',1)`,
		`INSERT INTO settings(k,v) VALUES('` + SetAliasUPN + `','1')`,
	} {
		if _, err := d.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := ResolveLoginName(d, "only@example.com"); ok {
		t.Fatalf("缺列时应降级拒绝，得到 %q", got)
	}
	if got, ok := ResolveLoginName(d, "wq"); !ok || got != "wq" {
		t.Fatalf("缺列时短账号仍应可用，得到 (%q,%v)", got, ok)
	}
}
