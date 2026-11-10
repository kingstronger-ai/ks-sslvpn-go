package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/vpn"
)

func TestNormalizeLoginAliases(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"zhangsan@example.com", "zhangsan@example.com"},
		{"Zhangsan@Example.Com, zhangsan@ad.local", "zhangsan@example.com,zhangsan@ad.local"},
		{"a@b.com;a@b.com\n c@d.com", "a@b.com,c@d.com"},
		{"not-an-email", ""},
		{"(uid=*)@x.com", ""}, // LDAP filter 元字符必须被拒
		{"user+tag@x.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeLoginAliases(c.in); got != c.want {
			t.Errorf("normalizeLoginAliases(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 端到端：短账号 zhangsan ↔ DN zhangsan@example.com（无字符串对应关系），
// 且另一个账号共用同一联系邮箱。默认只短账号；开启 UPN/DN 后别名可用，
// 只开邮箱时因歧义必须拒绝。配置下发链路（LDAPProfile）与 auth-verify 共用解析函数。
func TestLDAPProfileAliasLogin(t *testing.T) {
	clean := func() {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username IN ('zhangsan','aliaspeer')`)
		_, _ = db.DB.Exec(`DELETE FROM settings WHERE k IN (?,?)`, vpn.SetAliasMail, vpn.SetAliasUPN)
	}
	clean()
	t.Cleanup(clean)

	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,email,login_aliases,status,group_id)
		VALUES('zhangsan','Passw0rd123','local','zhangsan@example.com','zhangsan@example.com',1,0)`); err != nil {
		t.Fatal(err)
	}
	// 共用邮箱制造歧义：只开邮箱开关时不能误登
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,email,status,group_id)
		VALUES('aliaspeer','Passw0rd123','local','zhangsan@example.com',1,0)`); err != nil {
		t.Fatal(err)
	}

	ip := 0
	req := func(name string) int {
		ip++
		b, _ := json.Marshal(map[string]any{"username": name, "password": "Passw0rd123"})
		r := httptest.NewRequest("POST", "/api/v1/profile/account", strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", "10.79.0."+string(rune('0'+ip))) // 独立限流键
		w := httptest.NewRecorder()
		LDAPProfile(w, r)
		return w.Code
	}

	// 短账号始终可用
	if code := req("zhangsan"); code == 401 {
		t.Fatalf("短账号在默认状态下应可用，实际 %d", code)
	}
	// 默认关闭：别名必须拒绝
	if code := req("zhangsan@example.com"); code != 401 {
		t.Fatalf("默认关闭时别名应 401，实际 %d", code)
	}
	// 只开邮箱：两个账号共用邮箱 -> 歧义拒绝
	db.SetSetting(vpn.SetAliasMail, "1")
	if code := req("zhangsan@example.com"); code != 401 {
		t.Fatalf("邮箱歧义时应 401，实际 %d", code)
	}
	// 开启 UPN/DN：显式别名优先，解析到 zhangsan
	db.SetSetting(vpn.SetAliasUPN, "1")
	if code := req("zhangsan@example.com"); code == 401 || code == 400 {
		t.Fatalf("开启 UPN/DN 后别名不应被拒：%d", code)
	}
	// 关闭全部开关后立即恢复默认行为
	db.SetSetting(vpn.SetAliasMail, "0")
	db.SetSetting(vpn.SetAliasUPN, "0")
	if code := req("zhangsan@example.com"); code != 401 {
		t.Fatalf("关闭开关后别名应重新被拒，实际 %d", code)
	}
}
