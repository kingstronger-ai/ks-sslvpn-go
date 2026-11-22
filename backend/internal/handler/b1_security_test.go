package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/db"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
)

// b1TotpCode 生成当前时间窗的 TOTP（与 util.VerifyTOTP 同一算法），供测试断言动态码。
func b1TotpCode(secret string) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000)
}

func b1Call(t *testing.T, h http.HandlerFunc, body any, remote string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func b1SetCaptcha(id, ans string) {
	captchaStore.Lock()
	captchaStore.m[id] = ans
	captchaStore.expired[id] = time.Now().Add(5 * time.Minute)
	captchaStore.Unlock()
}

func b1Sha256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// B1-2 核心：开启 MFA 的管理员密码通过后返回 code=10 + mfa_token，动态码通过后才签发正式会话。
func TestAdminTwoStepLogin(t *testing.T) {
	middleware.InitSession("b1-two-step-secret")
	const username, password = "b1_mfa_admin", "StrongPass123"
	secret := util.TOTPSecret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, username)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,status,totp_enabled,totp_secret)
		VALUES(?,?,1,1,?)`, username, hash, secret); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, username).Scan(&adminID)
	const ip = "198.51.100.77:1234"
	ipKey, userKey := "ip:198.51.100.77", "u:"+strings.ToLower(username)
	cleanup := func() {
		loginAttempts.Lock()
		delete(loginAttempts.m, ipKey)
		delete(loginAttempts.m, userKey)
		loginAttempts.Unlock()
		_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE admin_id=?`, adminID)
		_, _ = db.DB.Exec(`DELETE FROM admin WHERE id=?`, adminID)
	}
	defer cleanup()

	b1SetCaptcha("b1cap1", "7")
	rr := b1Call(t, LoginCheck, map[string]any{
		"username": username, "password": password, "captcha": "7", "code_id": "b1cap1",
	}, ip)
	var first struct {
		Code     int    `json:"code"`
		MFAToken string `json:"mfa_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Code != 10 || first.MFAToken == "" {
		t.Fatalf("密码正确但开了 MFA 应返回 code=10 + mfa_token，实际 %s", rr.Body.String())
	}
	if _, ok := middleware.VerifyMFATicket(first.MFAToken, "198.51.100.77"); !ok {
		t.Fatal("票据应通过单 IP 绑定校验")
	}

	rr = b1Call(t, LoginMFA, map[string]any{"mfa_token": first.MFAToken, "otp": "000000"}, ip)
	var bad struct{ Code int `json:"code"` }
	_ = json.Unmarshal(rr.Body.Bytes(), &bad)
	if bad.Code == 1 {
		t.Fatalf("错误动态码不得签发会话: %s", rr.Body.String())
	}

	rr = b1Call(t, LoginMFA, map[string]any{"mfa_token": first.MFAToken, "otp": b1TotpCode(secret)}, ip)
	var okResp struct {
		Code int `json:"code"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &okResp); err != nil {
		t.Fatal(err)
	}
	if okResp.Code != 1 || okResp.Data.Token == "" {
		t.Fatalf("正确动态码应签发正式会话: %s", rr.Body.String())
	}
	jti := middleware.SessionJTI(okResp.Data.Token)
	if jti == "" || !middleware.SessionActive(jti) || middleware.SessionUser(okResp.Data.Token) != username {
		t.Fatal("二次验证签发的会话应带 jti、在库且绑定真实身份")
	}
}

// 恢复码单次使用：用过后立即从库中移除，同码再次提交必须失败。
func TestAdminMFARecoveryCodeSingleUse(t *testing.T) {
	middleware.InitSession("b1-recovery-secret")
	const username, recovery = "b1_recovery_admin", "B1RECOV7A"
	secret := util.TOTPSecret()
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.DefaultCost)
	hashes, _ := json.Marshal([]string{b1Sha256(recovery)})
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, username)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,status,totp_enabled,totp_secret,totp_recovery)
		VALUES(?,?,1,1,?,?)`, username, hash, secret, string(hashes)); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, username).Scan(&adminID)
	defer func() {
		_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE admin_id=?`, adminID)
		_, _ = db.DB.Exec(`DELETE FROM admin WHERE id=?`, adminID)
	}()
	const ip = "198.51.100.88:1234"
	ticket := middleware.MakeMFATicket(adminID, "198.51.100.88")
	rr := b1Call(t, LoginMFA, map[string]any{"mfa_token": ticket, "otp": recovery}, ip)
	if !strings.Contains(rr.Body.String(), `"code":1`) {
		t.Fatalf("恢复码首次使用应成功: %s", rr.Body.String())
	}
	var left string
	_ = db.DB.QueryRow(`SELECT totp_recovery FROM admin WHERE id=?`, adminID).Scan(&left)
	if left != "[]" {
		t.Fatalf("恢复码用后应被移除，实际 %q", left)
	}
	ticket2 := middleware.MakeMFATicket(adminID, "198.51.100.88")
	rr = b1Call(t, LoginMFA, map[string]any{"mfa_token": ticket2, "otp": recovery}, ip)
	if strings.Contains(rr.Body.String(), `"code":1`) {
		t.Fatalf("已使用的恢复码再次提交必须失败: %s", rr.Body.String())
	}
}

// MFA 失败必须计入既有 loginFailState（与密码爆破共用锁定）。
func TestMFALoginFailureCounted(t *testing.T) {
	middleware.InitSession("b1-mfa-fail-secret")
	const username = "b1_mfa_fail_admin"
	secret := util.TOTPSecret()
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.DefaultCost)
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, username)
	_, _ = db.DB.Exec(`INSERT INTO admin(username,password,status,totp_enabled,totp_secret)
		VALUES(?,?,1,1,?)`, username, hash, secret)
	var adminID int64
	_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, username).Scan(&adminID)
	ipKey, userKey := "ip:198.51.100.99", "u:"+strings.ToLower(username)
	loginAttempts.Lock()
	delete(loginAttempts.m, ipKey)
	delete(loginAttempts.m, userKey)
	loginAttempts.Unlock()
	defer func() {
		loginAttempts.Lock()
		delete(loginAttempts.m, ipKey)
		delete(loginAttempts.m, userKey)
		loginAttempts.Unlock()
		_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE admin_id=?`, adminID)
		_, _ = db.DB.Exec(`DELETE FROM admin WHERE id=?`, adminID)
	}()

	for i := 0; i < loginMaxFails; i++ {
		ticket := middleware.MakeMFATicket(adminID, "198.51.100.99")
		b1Call(t, LoginMFA, map[string]any{"mfa_token": ticket, "otp": "111111"}, "198.51.100.99:1234")
	}
	loginAttempts.Lock()
	locked := loginLocked(ipKey) || loginLocked(userKey)
	loginAttempts.Unlock()
	if !locked {
		t.Fatal("MFA 连续失败达到阈值后应触发登录锁定")
	}
}

// 审计导出 CSV 必须对公式注入做转义，且 JSON 格式输出标准可解析。
func TestAuditExportCSVFormulaInjection(t *testing.T) {
	const action = "CSV注入测试"
	_, _ = db.DB.Exec(`DELETE FROM syslog WHERE action=?`, action)
	defer func() { _, _ = db.DB.Exec(`DELETE FROM syslog WHERE action=?`, action) }()
	malicious := []string{`=cmd|/c calc`, `+SUM(1+1)`, `-2+3`, `@evil`, "\t=1"}
	for _, detail := range malicious {
		db.SyslogWithID("auditor", action, detail, "203.0.113.60", 7)
	}
	rr := b1Call(t, AuditExport, map[string]any{"format": "csv", "action": action}, "203.0.113.60:1234")
	body := rr.Body.String()
	for _, want := range []string{"'=cmd", "'+SUM", "'-2+3", "'@evil", "'\t=1"} {
		if !strings.Contains(body, want) {
			t.Errorf("CSV 应把危险值加单引号前缀，缺少 %q；实际:\n%s", want, body)
		}
	}
	if strings.Contains(body, "\n=cmd") || strings.Contains(body, ",=cmd") {
		t.Error("CSV 不得出现以 = 开头的原始单元格")
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment;") {
		t.Error("导出响应应带下载头")
	}

	rr = b1Call(t, AuditExport, map[string]any{"format": "json", "action": action}, "203.0.113.60:1234")
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Error("JSON 导出 Content-Type 应为 application/json")
	}
	var rows []auditRow
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil || len(rows) != len(malicious) {
		t.Fatalf("JSON 导出应可解析且包含全部记录: err=%v rows=%d body=%s", err, len(rows), rr.Body.String())
	}
}

// 审计归因：从 token 取真实 subject/admin_id；无身份时记 unknown 而非 admin。
func TestSyslogFromRequestAttribution(t *testing.T) {
	middleware.InitSession("b1-attribution-secret")
	const username = "b1_audit_subject"
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, username)
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.DefaultCost)
	_, _ = db.DB.Exec(`INSERT INTO admin(username,password,status) VALUES(?,?,1)`, username, hash)
	var adminID int64
	_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, username).Scan(&adminID)
	defer func() {
		_, _ = db.DB.Exec(`DELETE FROM admin_session WHERE admin_id=?`, adminID)
		_, _ = db.DB.Exec(`DELETE FROM admin WHERE id=?`, adminID)
		_, _ = db.DB.Exec(`DELETE FROM syslog WHERE action='归因测试'`)
	}()

	token, _ := middleware.MakeSessionFull(username)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sslvpn_session", Value: token})
	r.RemoteAddr = "203.0.113.55:1234"
	syslogFromRequest(r, "归因测试", "带身份")
	var admin string
	var gotID int64
	var ip string
	if err := db.DB.QueryRow(`SELECT admin,admin_id,ip FROM syslog WHERE action='归因测试' ORDER BY id DESC LIMIT 1`).
		Scan(&admin, &gotID, &ip); err != nil {
		t.Fatal(err)
	}
	if admin != username || gotID != adminID || ip != "203.0.113.55" {
		t.Fatalf("审计应归因到真实主体: admin=%q id=%d ip=%q（期望 %q/%d）", admin, gotID, ip, username, adminID)
	}

	anon := httptest.NewRequest(http.MethodPost, "/", nil)
	anon.RemoteAddr = "203.0.113.56:1234"
	syslogFromRequest(anon, "归因测试", "无身份")
	var anonAdmin string
	var anonID int64
	_ = db.DB.QueryRow(`SELECT admin,admin_id FROM syslog WHERE action='归因测试' ORDER BY id DESC LIMIT 1`).
		Scan(&anonAdmin, &anonID)
	if anonAdmin != "unknown" || anonID != 0 {
		t.Fatalf("无身份请求应记 unknown/0，得到 %q/%d", anonAdmin, anonID)
	}
}
