package handler

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"

	"sslvpn/internal/db"
	"sslvpn/internal/ldaputil"
)

func newFakeLDAPEntry(attr, val string) *goldap.Entry {
	return goldap.NewEntry("uid=test,dc=example,dc=com", map[string][]string{attr: {val}})
}

// setupLDAPStatusAccounts 建三账号：两个 LDAP（一个将被停用、一个将被恢复）+ 一个本地（不应被动）。
func setupLDAPStatusAccounts(t *testing.T) {
	t.Helper()
	rows := []struct {
		name, auth string
		status     int
	}{
		{"ldap_status_del_me", "ldap", 1},  // LDAP 里已删除 → 应禁用
		{"ldap_status_restore", "ldap", 0}, // LDAP 里已恢复 → 应启用
		{"ldap_status_attr", "ldap", 1},    // LDAP 里存在但带停用标记 → 应禁用
		{"ldap_status_local", "local", 1},  // 本地账号 → 不应被触碰
	}
	for _, r := range rows {
		if _, err := db.DB.Exec(`DELETE FROM account WHERE username=?`, r.name); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
			VALUES(?,?,?,?, '')`, r.name, "-", r.auth, r.status); err != nil {
			t.Fatal(err)
		}
	}
}

func statusOf(t *testing.T, name string) int {
	t.Helper()
	var s int
	if err := db.DB.QueryRow(`SELECT status FROM account WHERE username=?`, name).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestReconcileLDAPStatus 覆盖删除型停用、属性停用、恢复启用、不动本地账号。
func TestReconcileLDAPStatus(t *testing.T) {
	setupLDAPStatusAccounts(t)
	defer func() {
		for _, n := range []string{"ldap_status_del_me", "ldap_status_restore", "ldap_status_attr", "ldap_status_local"} {
			_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, n)
		}
	}()

	// LDAP 当前列表：restore 已恢复（未停用）；attr 存在但被标记停用；del_me 已不在列表中
	users := []LdapUser{
		{Username: "ldap_status_restore", Disabled: false},
		{Username: "ldap_status_attr", Disabled: true},
		{Username: "ldap_status_brandnew", Disabled: false},
	}
	disabled, enabled, err := reconcileLDAPStatus(users)
	if err != nil {
		t.Fatal(err)
	}
	if disabled != 2 || enabled != 1 {
		t.Fatalf("统计错误: disabled=%d enabled=%d，期望 2/1", disabled, enabled)
	}
	if got := statusOf(t, "ldap_status_del_me"); got != 0 {
		t.Errorf("LDAP 已删除的账号应被禁用，实际 status=%d", got)
	}
	if got := statusOf(t, "ldap_status_attr"); got != 0 {
		t.Errorf("LDAP 带停用标记的账号应被禁用，实际 status=%d", got)
	}
	if got := statusOf(t, "ldap_status_restore"); got != 1 {
		t.Errorf("LDAP 恢复的账号应被启用，实际 status=%d", got)
	}
	if got := statusOf(t, "ldap_status_local"); got != 1 {
		t.Errorf("本地密码账号不应被动，实际 status=%d", got)
	}
}

// TestReconcileLDAPStatusEmptyList 空列表保护：LDAP 返回 0 用户时不做任何变更。
func TestReconcileLDAPStatusEmptyList(t *testing.T) {
	setupLDAPStatusAccounts(t)
	defer func() {
		for _, n := range []string{"ldap_status_del_me", "ldap_status_restore", "ldap_status_attr", "ldap_status_local"} {
			_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, n)
		}
	}()

	before := statusOf(t, "ldap_status_del_me")
	_, _, err := reconcileLDAPStatus([]LdapUser{})
	if err == nil {
		t.Fatal("空列表应返回错误以触发跳过")
	}
	if got := statusOf(t, "ldap_status_del_me"); got != before {
		t.Errorf("空列表不应改动账号状态: before=%d after=%d", before, got)
	}
}

// TestLDAPEntryDisabled 标准停用属性判定（handler 包的判定函数）。
func TestLDAPEntryDisabled(t *testing.T) {
	cases := []struct {
		name string
		attr string
		val  string
		want bool
	}{
		{"AD 禁用位 514", "userAccountControl", "514", true},
		{"AD 禁用位 546（含密码永不过期）", "userAccountControl", "546", true},
		{"AD 锁定位 16", "userAccountControl", "528", true},
		{"AD 正常 512", "userAccountControl", "512", false},
		{"AD 账号过期 FILETIME（已过期 2020）", "accountExpires", "132230400000000000", true},
		{"AD 永不过期 0", "accountExpires", "0", false},
		{"AD 永不过期最大值", "accountExpires", "9223372036854775807", false},
		{"AD 账号未过期（2099）", "accountExpires", "265046774400000000", false},
		{"AD lockoutTime 锁定", "lockoutTime", "132230400000000000", true},
		{"AD lockoutTime 哨兵", "lockoutTime", "9223372036854775807", false},
		{"AD msDS-UserAccountDisabled TRUE", "msDS-UserAccountDisabled", "TRUE", true},
		{"AD msDS-UserAccountDisabled FALSE", "msDS-UserAccountDisabled", "FALSE", false},
		{"ppolicy 锁定", "pwdAccountLockedTime", "20260101000000Z", true},
		{"ppolicy 从不锁定", "pwdAccountLockedTime", "000001010000Z", false},
		{"389DS 锁定", "nsAccountLock", "TRUE", true},
		{"自定义 status", "employeeStatus", "disabled", true},
		{"enabled=0", "enabled", "0", true},
		{"enabled=1", "enabled", "1", false},
	}
	for _, tc := range cases {
		e := newFakeLDAPEntry(tc.attr, tc.val)
		if got := ldapEntryDisabled(e); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestUsernameAttr AD/普通 LDAP 各类过滤器的用户名属性提取。
func TestUsernameAttr(t *testing.T) {
	cases := []struct{ filter, want string }{
		{"(uid=%s)", "uid"},
		{"(sAMAccountName=%s)", "sAMAccountName"},
		{"(userPrincipalName=%s)", "userPrincipalName"},
		{"(mail=%s)", "mail"},
		{"(&(objectClass=user)(sAMAccountName=%s))", "sAMAccountName"},
		{"(&(objectClass=person)(|(uid=%s)(mail=%s)))", "uid"},
		{"", "uid"},
	}
	for _, tc := range cases {
		if got := ldaputil.UsernameAttr(tc.filter); got != tc.want {
			t.Errorf("filter %q: got %q want %q", tc.filter, got, tc.want)
		}
	}
}

// TestReconcileLDAPStatusCaseInsensitive AD 用户名大小写不敏感，不能因大小写差异误禁用。
func TestReconcileLDAPStatusCaseInsensitive(t *testing.T) {
	const name = "ldap_status_ADCase"
	_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name)
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,expire_date)
		VALUES(?,?,?,?, '')`, name, "-", "ldap", 1); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, name) }()

	users := []LdapUser{{Username: "LDAP_STATUS_ADCASE", Disabled: false}}
	if _, _, err := reconcileLDAPStatus(users); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(t, name); got != 1 {
		t.Errorf("AD 大小写差异不应误禁用，实际 status=%d", got)
	}
}

// TestReconcileLDAPStatusCircuitBreaker OU 配错导致目录只返回极少用户时，
// 必须整批跳过状态同步，不能把绝大多数本地账号一次性禁用。
func TestReconcileLDAPStatusCircuitBreaker(t *testing.T) {
	names := []string{"ldap_cb_1", "ldap_cb_2", "ldap_cb_3", "ldap_cb_4", "ldap_cb_5", "ldap_cb_6"}
	defer func() {
		for _, n := range names {
			_, _ = db.DB.Exec(`DELETE FROM account WHERE username=?`, n)
		}
	}()
	for _, n := range names {
		if _, err := db.DB.Exec(`DELETE FROM account WHERE username=?`, n); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status) VALUES(?,'-','ldap',1)`, n); err != nil {
			t.Fatal(err)
		}
	}
	// 目录只返回 1 个 → 5/6 账号将被禁用，超过 40% 熔断阈值
	if _, _, err := reconcileLDAPStatus([]LdapUser{{Username: "ldap_cb_1", Disabled: false}}); err == nil {
		t.Fatal("用户数骤降时应熔断并返回错误")
	}
	for _, n := range names {
		if got := statusOf(t, n); got != 1 {
			t.Errorf("熔断后账号 %s 不应被改动，实际 status=%d", n, got)
		}
	}
}
