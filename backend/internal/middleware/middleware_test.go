package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sslvpn-middleware-test")
	if err != nil {
		panic(err)
	}
	if err := db.Open(dir); err != nil {
		panic(err)
	}
	code := m.Run()
	if db.DB != nil {
		_ = db.DB.Close()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// B1-1 核心：带 jti 的会话可被服务端吊销；旧格式 token（无 jti）只验签、不查表。
func TestSessionRevocationAndLegacyCompat(t *testing.T) {
	InitSession("session-revoke-test-secret")
	const username = "session_revoke_admin"
	_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE username=?`, username)
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, username)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,status) VALUES(?,?,1)`, username, "x"); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, username).Scan(&adminID); err != nil {
		t.Fatal(err)
	}

	token, jti := MakeSessionFull(username)
	if jti == "" || strings.Contains(jti, "|") {
		t.Fatalf("jti 应为不含分隔符的随机串，得到 %q", jti)
	}
	if !CheckSession(token) || SessionUser(token) != username || SessionJTI(token) != jti {
		t.Fatal("新会话应验签通过并携带 subject/jti")
	}
	// 上一版格式与最旧匿名格式：无 jti，不查表
	legacyNamed, legacyAnon := MakeSessionFor(username), MakeSession()
	if !CheckSession(legacyNamed) || !CheckSession(legacyAnon) {
		t.Fatal("旧格式 token 应继续验签通过")
	}

	RevokeJTI(jti)
	if !IsRevoked(jti) || SessionActive(jti) || CheckSession(token) {
		t.Fatal("吊销后会话应立即失效")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/list", nil)
	req.AddCookie(&http.Cookie{Name: "sslvpn_session", Value: token})
	rr := httptest.NewRecorder()
	Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})).ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), `"code":401`) {
		t.Fatalf("被吊销的 token 经 Auth 应返回 401，实际 %s", rr.Body.String())
	}
	if !CheckSession(legacyNamed) || !CheckSession(legacyAnon) {
		t.Fatal("旧格式 token 无 jti，不应受吊销影响")
	}

	// RevokeAdmin 一次吊销该管理员全部会话
	t2, j2 := MakeSessionFull(username)
	t3, j3 := MakeSessionFull(username)
	if !CheckSession(t2) || !CheckSession(t3) {
		t.Fatal("新签发的两个会话应有效")
	}
	RevokeAdmin(adminID)
	if SessionActive(j2) || SessionActive(j3) {
		t.Fatal("RevokeAdmin 应吊销该管理员全部会话")
	}
}

// 过期会话由登录时顺带清理，且清理只删过期/不误删有效会话。
func TestDeleteExpiredSessions(t *testing.T) {
	InitSession("session-expire-test-secret")
	_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE username='expire_test'`)
	_, _ = db.DB.Exec(`INSERT INTO admin_session(jti,username,created_at,expires_at,revoked)
		VALUES('expired_jti','expire_test',1,2,0),('live_jti','expire_test',1,9999999999,0)`)
	n, err := DeleteExpiredSessions()
	if err != nil || n < 1 {
		t.Fatalf("清理过期会话失败: n=%d err=%v", n, err)
	}
	if SessionActive("expired_jti") || !SessionActive("live_jti") {
		t.Fatal("只应清理过期会话，未过期会话必须保留")
	}
}

// MFA 票据：5min 有效期 + HMAC 签名 + 单 IP 绑定，篡改/换 IP 均无效。
func TestMFATicketBinding(t *testing.T) {
	InitSession("mfa-ticket-test-secret")
	ticket := MakeMFATicket(42, "203.0.113.10")
	if id, ok := VerifyMFATicket(ticket, "203.0.113.10"); !ok || id != 42 {
		t.Fatal("合法票据应通过校验并返回 admin id")
	}
	if _, ok := VerifyMFATicket(ticket, "203.0.113.11"); ok {
		t.Fatal("换 IP 后票据必须失效")
	}
	tampered := strings.Replace(ticket, "|42|", "|43|", 1)
	if tampered == ticket {
		t.Fatal("票据格式异常，无法构造篡改样本")
	}
	if _, ok := VerifyMFATicket(tampered, "203.0.113.10"); ok {
		t.Fatal("篡改管理员 id 的票据必须失效")
	}
	if strings.Count(ticket, "|") != 3 {
		t.Fatalf("票据应为 4 段格式，得到 %q", ticket)
	}
}
