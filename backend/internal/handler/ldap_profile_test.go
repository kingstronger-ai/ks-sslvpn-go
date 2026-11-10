package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sslvpn/internal/db"
)

// v0.4.6 macOS 客户端把 /api/v1/profile/account 的密码字段从 password 改名为
// secret；同时 local/totp 分支必须查库里的真实密码（ssoAccountByUsername 不查密码列）。
// 本用例锁住：两代字段名、TOTP 逗号格式、错误密码必须 401。
func TestLDAPProfileAccountLogin(t *testing.T) {
	clean := func() {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username IN ('localtest1','totptest1')`)
	}
	clean()
	t.Cleanup(clean)

	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,group_id)
		VALUES('localtest1','Passw0rd123','local',1,0)`); err != nil {
		t.Fatal(err)
	}
	totpSecret := "JBSWY3DPEHPK3PXP" // 标准 Base32 测试密钥
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,totp_secret,status,group_id)
		VALUES('totptest1','Passw0rd123','totp',?,1,0)`, totpSecret); err != nil {
		t.Fatal(err)
	}

	// req 发送请求并断言是否命中「账号或密码错误」
	ip := 0
	req := func(body map[string]any) (int, string) {
		ip++
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/v1/profile/account", strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", "10.77.0."+string(rune('0'+ip))) // 每个请求独立限流键
		w := httptest.NewRecorder()
		LDAPProfile(w, r)
		msg := ""
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if v, ok := out["error"].(string); ok {
			msg = v
		}
		return w.Code, msg
	}

	// 旧字段名 password（Windows v0.4.3 / macOS 源码版）
	if code, msg := req(map[string]any{"username": "localtest1", "password": "Passw0rd123"}); code == 401 && strings.Contains(msg, "账号或密码错误") {
		t.Fatalf("password 字段本地登录被拒: %d %s", code, msg)
	}
	// 新字段名 secret（macOS v0.4.6+）
	if code, msg := req(map[string]any{"username": "localtest1", "secret": "Passw0rd123"}); code == 401 && strings.Contains(msg, "账号或密码错误") {
		t.Fatalf("secret 字段本地登录被拒: %d %s", code, msg)
	}
	// 错误密码：两种字段名都必须 401
	if code, msg := req(map[string]any{"username": "localtest1", "password": "wrong"}); code != 401 {
		t.Fatalf("错误 password 应 401，实际 %d %s", code, msg)
	}
	if code, msg := req(map[string]any{"username": "localtest1", "secret": "wrong"}); code != 401 {
		t.Fatalf("错误 secret 应 401，实际 %d %s", code, msg)
	}

	// TOTP：secret = "password,动态码"
	otp := totpNow(totpSecret)
	if code, msg := req(map[string]any{"username": "totptest1", "secret": "Passw0rd123," + otp}); code == 401 && strings.Contains(msg, "账号或密码") {
		t.Fatalf("TOTP 正确动态码被拒: %d %s", code, msg)
	}
	if code, _ := req(map[string]any{"username": "totptest1", "secret": "Passw0rd123,000000"}); code != 401 {
		t.Fatalf("TOTP 错误动态码应 401，实际 %d", code)
	}
	if code, _ := req(map[string]any{"username": "totptest1", "secret": "Passw0rd123"}); code != 401 {
		t.Fatalf("TOTP 缺少动态码应 401，实际 %d", code)
	}
}

// totpNow 生成当前 30s 窗口的 6 位动态码（RFC 6238，与 util.VerifyTOTP 对齐）
func totpNow(secretB32 string) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	const digits = "0123456789"
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[5-i] = digits[int(code%10)]
		code /= 10
	}
	return string(out)
}

// LDAP/AD 支持两种账号形态：AD 域短账号（sAMAccountName）与邮箱账号（mail / UPN）。
// 邮箱含 '@'，此前 validName 与两端客户端正则都禁止，导致邮箱账号无法登录。
func TestValidNameSupportsEmailAccounts(t *testing.T) {
	ok := []string{"zhangsan", "zs_01", "a.b-c", "user@example.com", "UPN@ad.example.com"}
	for _, s := range ok {
		if !validName(s) {
			t.Errorf("应接受账号名 %q", s)
		}
	}
	// LDAP filter 元字符与其它特殊字符仍必须拒绝，避免注入与文件名问题
	bad := []string{"", "user name", "user/admin", "user+tag@x.com", "用户名",
		"(uid=*)", "a\\b", strings.Repeat("a", 65)}
	for _, s := range bad {
		if validName(s) {
			t.Errorf("应拒绝账号名 %q", s)
		}
	}
}

// 端到端锁定：邮箱形态账号通过 /api/v1/profile/account 时不再被 401 拒绝。
func TestLDAPProfileEmailAccount(t *testing.T) {
	clean := func() {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username = 'user@example.com'`)
	}
	clean()
	t.Cleanup(clean)
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,group_id)
		VALUES('user@example.com','Passw0rd123','local',1,0)`); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"username": "user@example.com", "password": "Passw0rd123"})
	r := httptest.NewRequest("POST", "/api/v1/profile/account", strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Real-IP", "10.78.0.9") // 独立限流键，避免与相邻用例互相影响
	w := httptest.NewRecorder()
	LDAPProfile(w, r)
	if w.Code == 401 || w.Code == 400 {
		t.Fatalf("邮箱形态账号不应被用户名格式拒绝：%d %s", w.Code, w.Body.String())
	}
}
