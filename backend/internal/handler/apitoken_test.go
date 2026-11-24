package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/middleware"
)

const tokenTestAdmin = "apitoken_test_admin"

// setupTokenTest 准备一个带 session 的管理员请求环境（管理接口本身只允许 session 认证）。
func setupTokenTest(t *testing.T) string {
	t.Helper()
	middleware.InitSession("apitoken-test-secret")
	_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, tokenTestAdmin)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,status) VALUES(?,?,1)`, tokenTestAdmin, "x"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`DELETE FROM syslog WHERE admin=?`, tokenTestAdmin)
		_, _ = db.DB.Exec(`DELETE FROM admin WHERE username=?`, tokenTestAdmin)
	})
	return middleware.MakeSessionFor(tokenTestAdmin)
}

func tokenTestRequest(method, path, body, session string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if session != "" {
		r.AddCookie(&http.Cookie{Name: "sslvpn_session", Value: session})
	}
	return r
}

// seedAPIToken 直接落库，便于列表/吊销等测试使用固定明文与 hash。
func seedAPIToken(t *testing.T, name, scope string, expiresAt, revoked int64) (plain, hash string, id int64) {
	t.Helper()
	plain, hash, prefix, err := middleware.NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO api_token(name,token_hash,prefix,scope,created_by,created_at,expires_at,revoked)
		VALUES(?,?,?,?,?,?,?,?)`, name, hash, prefix, scope, tokenTestAdmin, time.Now().Unix(), expiresAt, revoked)
	if err != nil {
		t.Fatal(err)
	}
	id, _ = res.LastInsertId()
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, id) })
	return plain, hash, id
}

type createTokenResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Token     string `json:"token"`
		Prefix    string `json:"prefix"`
		Scope     string `json:"scope"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"data"`
}

func doCreateToken(t *testing.T, session, body string) (*httptest.ResponseRecorder, createTokenResp) {
	t.Helper()
	rr := httptest.NewRecorder()
	APITokenCreate(rr, tokenTestRequest(http.MethodPost, "/api/v1/apitoken/create", body, session))
	var resp createTokenResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析创建响应失败: %v, body=%s", err, rr.Body.String())
	}
	return rr, resp
}

// 创建接口：明文仅此一次返回、DB 只存 hash、prefix 规则、no-store、syslog 不泄露凭据。
func TestAPITokenCreateNoHashLeakAndSyslog(t *testing.T) {
	session := setupTokenTest(t)
	rr, resp := doCreateToken(t, session, `{"name":"AI Assistant","scope":"read","expires_days":30}`)
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, resp.Data.ID) })

	if resp.Code != 1 || resp.Data.Token == "" {
		t.Fatalf("创建应成功: %+v body=%s", resp, rr.Body.String())
	}
	plain := resp.Data.Token
	if !strings.HasPrefix(plain, middleware.APITokenPrefix) || len(plain) != 49 {
		t.Fatalf("明文格式错误: %q", plain)
	}
	if resp.Data.Prefix != plain[:12] || resp.Data.Scope != "read" || resp.Data.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("响应字段错误: %+v", resp.Data)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("创建接口必须设置 Cache-Control: no-store")
	}
	hash := middleware.HashAPIToken(plain)
	if strings.Contains(rr.Body.String(), hash) || strings.Contains(rr.Body.String(), "token_hash") {
		t.Fatal("响应不应包含 hash 或 token_hash 字段")
	}
	var dbHash, dbPrefix, dbName, dbScope, dbBy string
	if err := db.DB.QueryRow(`SELECT token_hash,prefix,name,scope,created_by FROM api_token WHERE id=?`, resp.Data.ID).
		Scan(&dbHash, &dbPrefix, &dbName, &dbScope, &dbBy); err != nil {
		t.Fatal(err)
	}
	if dbHash != hash || dbPrefix != resp.Data.Prefix || dbName != "AI Assistant" || dbScope != "read" || dbBy != tokenTestAdmin {
		t.Fatalf("落库数据错误: hash=%s prefix=%s name=%s scope=%s by=%s", dbHash, dbPrefix, dbName, dbScope, dbBy)
	}
	var detail string
	err := db.DB.QueryRow(`SELECT detail FROM syslog WHERE admin=? AND action='创建API Token' ORDER BY id DESC LIMIT 1`, tokenTestAdmin).Scan(&detail)
	if err != nil || !strings.Contains(detail, "AI Assistant") || strings.Contains(detail, hash) || strings.Contains(detail, plain) {
		t.Fatalf("syslog 应只记 name/id，不记明文/hash: detail=%q err=%v", detail, err)
	}
}

// 创建参数校验：name 1-64、scope 合法、expires_days 0 或 1-365。
func TestAPITokenCreateValidation(t *testing.T) {
	session := setupTokenTest(t)
	cases := []struct {
		name, body string
		wantOK     bool
	}{
		{"空名称", `{"name":"","scope":"read"}`, false},
		{"名称超长", `{"name":"` + strings.Repeat("x", 65) + `","scope":"read"}`, false},
		{"scope非法", `{"name":"ok","scope":"admin"}`, false},
		{"天数负数", `{"name":"ok","scope":"read","expires_days":-1}`, false},
		{"天数超限", `{"name":"ok","scope":"read","expires_days":366}`, false},
		{"永久token", `{"name":"permanent","scope":"read","expires_days":0}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, resp := doCreateToken(t, session, c.body)
			if c.wantOK && resp.Code != 1 {
				t.Fatalf("应创建成功，实际 %+v", resp)
			}
			if !c.wantOK && resp.Code == 1 {
				t.Fatalf("非法参数应被拒绝，实际 %+v", resp)
			}
			if resp.Data.ID != 0 {
				t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, resp.Data.ID) })
			}
			if c.name == "永久token" && resp.Data.ExpiresAt != 0 {
				t.Fatal("expires_days=0 应返回 expires_at=0（永久）")
			}
		})
	}
}

// 列表接口：只返回 prefix 等元数据，不泄露 hash/明文。
func TestAPITokenListNoHashLeak(t *testing.T) {
	session := setupTokenTest(t)
	plain, hash, _ := seedAPIToken(t, "list_visible", "read", 0, 0)

	rr := httptest.NewRecorder()
	APITokenList(rr, tokenTestRequest(http.MethodGet, "/api/v1/apitoken/list", "", session))
	body := rr.Body.String()
	if !strings.Contains(body, `"prefix"`) || !strings.Contains(body, "list_visible") {
		t.Fatalf("列表应包含 prefix 与 name: %s", body)
	}
	if strings.Contains(body, hash) || strings.Contains(body, plain) || strings.Contains(body, "token_hash") {
		t.Fatalf("列表绝不能泄露明文或 hash: %s", body)
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Total int `json:"total"`
			List  []struct {
				Name   string `json:"name"`
				Prefix string `json:"prefix"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != 1 || resp.Data.Total < 1 {
		t.Fatalf("列表响应异常: %s", body)
	}
	for _, it := range resp.Data.List {
		if strings.HasPrefix(it.Prefix, middleware.APITokenPrefix) && !strings.Contains(body, it.Name) {
			t.Fatalf("列表项缺失 name: %+v", it)
		}
	}
}

// 吊销：软删除 revoked=1、立即失效、syslog 留审计。
func TestAPITokenRevokeAndSyslog(t *testing.T) {
	session := setupTokenTest(t)
	_, resp := doCreateToken(t, session, `{"name":"revoke_me","scope":"read","expires_days":1}`)
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, resp.Data.ID) })
	plain := resp.Data.Token
	if _, ok := middleware.AuthenticateToken(plain); !ok {
		t.Fatal("吊销前 token 应有效")
	}

	rr := httptest.NewRecorder()
	APITokenRevoke(rr, tokenTestRequest(http.MethodPost, "/api/v1/apitoken/revoke", `{"id":`+strconv.FormatInt(resp.Data.ID, 10)+`}`, session))
	if !strings.Contains(rr.Body.String(), `"code":1`) {
		t.Fatalf("吊销应成功: %s", rr.Body.String())
	}
	var revoked int
	if err := db.DB.QueryRow(`SELECT revoked FROM api_token WHERE id=?`, resp.Data.ID).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatalf("应软吊销 revoked=1，实际 %d err=%v", revoked, err)
	}
	if _, ok := middleware.AuthenticateToken(plain); ok {
		t.Fatal("吊销后 token 必须立即失效")
	}
	var detail string
	err := db.DB.QueryRow(`SELECT detail FROM syslog WHERE admin=? AND action='吊销API Token' ORDER BY id DESC LIMIT 1`, tokenTestAdmin).Scan(&detail)
	hash := middleware.HashAPIToken(plain)
	if err != nil || !strings.Contains(detail, "revoke_me") || strings.Contains(detail, hash) || strings.Contains(detail, plain) {
		t.Fatalf("吊销 syslog 应只记 name/id: detail=%q err=%v", detail, err)
	}
}

// test 接口：验证有效性但不泄露 token；管理接口禁止被 API Token 自身调用。
func TestAPITokenTestAndNoSelfEscalation(t *testing.T) {
	session := setupTokenTest(t)
	_, resp := doCreateToken(t, session, `{"name":"test_token","scope":"read","expires_days":0}`)
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, resp.Data.ID) })
	plain := resp.Data.Token

	rr := httptest.NewRecorder()
	APITokenTest(rr, tokenTestRequest(http.MethodPost, "/api/v1/apitoken/test", `{"token":"`+plain+`"}`, session))
	var got struct {
		Code int `json:"code"`
		Data struct {
			Valid bool   `json:"valid"`
			Scope string `json:"scope"`
			Name  string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != 1 || !got.Data.Valid || got.Data.Scope != "read" || got.Data.Name != "test_token" {
		t.Fatalf("test 应返回有效信息: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), plain) {
		t.Fatal("test 接口不得回显 token 明文")
	}

	// 模拟主线集成：apiEntry 外层包了 TokenAuthDispatch。即使同时带 session cookie，
	// 只要带 Bearer ksvpn_ 就走 token 路径，管理接口应识别并拒绝自我提权。
	r := tokenTestRequest(http.MethodPost, "/api/v1/apitoken/create", `{"name":"escalate","scope":"write"}`, session)
	r.Header.Set("Authorization", "Bearer "+plain)
	rr2 := httptest.NewRecorder()
	dispatched := middleware.TokenAuthDispatch(func(w http.ResponseWriter, req *http.Request) {
		APITokenCreate(w, req)
	})
	dispatched(rr2, r)
	if !strings.Contains(rr2.Body.String(), `"code":401`) {
		t.Fatalf("API Token 不得调用管理接口: %s", rr2.Body.String())
	}
}

// 社区版硬约束：脚本直调创建接口也不能得到 write Token。
func TestAPITokenCreateWriteRejectedOnCommunity(t *testing.T) {
	session := setupTokenTest(t)
	rr, resp := doCreateToken(t, session, `{"name":"bad_write","scope":"write"}`)
	if resp.Code != 0 || !strings.Contains(rr.Body.String(), "需专业版及以上") {
		t.Fatalf("社区版应拒绝创建 write Token: %s", rr.Body.String())
	}
	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM api_token WHERE name='bad_write'`).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("被拒的 write Token 不应落库")
	}
}

// API Token 触发的操作必须写入可追溯主体（token:prefix#id），不能退化成 unknown。
func TestTokenAuditAttribution(t *testing.T) {
	setupTokenTest(t)
	plain, _, id := seedAPIToken(t, "audit_attr", "read", 0, 0)
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM syslog WHERE action='Token审计归因测试'`) })
	req := tokenTestRequest(http.MethodGet, "/api/v1/probe", "", "")
	req.Header.Set("Authorization", "Bearer "+plain)
	dispatched := middleware.TokenAuthDispatch(func(w http.ResponseWriter, r *http.Request) {
		syslogFromRequest(r, "Token审计归因测试", "probe")
		w.WriteHeader(http.StatusOK)
	})
	rr := httptest.NewRecorder()
	dispatched(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("probe 请求失败: %d %s", rr.Code, rr.Body.String())
	}
	var subject, detail string
	if err := db.DB.QueryRow(`SELECT admin,detail FROM syslog WHERE action='Token审计归因测试' ORDER BY id DESC LIMIT 1`).
		Scan(&subject, &detail); err != nil {
		t.Fatalf("未写入审计记录: %v", err)
	}
	want := "token:" + plain[:12] + "#" + strconv.FormatInt(id, 10)
	if !strings.HasPrefix(subject, want) || !strings.Contains(detail, "token_id=") {
		t.Fatalf("审计主体应可追溯到 Token，实际 subject=%q detail=%q", subject, detail)
	}
}

// 管理接口请求体上限 64KB，超限应直接拒绝且不落库。
func TestAPITokenBodyLimit(t *testing.T) {
	session := setupTokenTest(t)
	body := `{"name":"` + strings.Repeat("x", apitokenBodyLimit) + `","scope":"read"}`
	rr := httptest.NewRecorder()
	APITokenCreate(rr, tokenTestRequest(http.MethodPost, "/api/v1/apitoken/create", body, session))
	if !strings.Contains(rr.Body.String(), "参数错误") {
		t.Fatalf("超大请求体应被拒绝: %s", rr.Body.String())
	}
	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM api_token WHERE name LIKE 'xxxx%'`).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("超限请求不应落库")
	}
}

// 未撤销 token 数量上限 20。
func TestAPITokenMaxActive(t *testing.T) {
	session := setupTokenTest(t)
	for i := 0; i < apiTokenMaxActive; i++ {
		_, _, _ = seedAPIToken(t, "bulk_"+strconv.Itoa(i), "read", 0, 0)
	}
	_, resp := doCreateToken(t, session, `{"name":"over_limit","scope":"read"}`)
	if resp.Code == 1 {
		if resp.Data.ID != 0 {
			t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, resp.Data.ID) })
		}
		t.Fatal("达到 20 个未撤销 token 后应拒绝创建")
	}
}
