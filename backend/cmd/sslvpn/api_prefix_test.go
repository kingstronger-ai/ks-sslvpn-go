package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/handler"
	"sslvpn/internal/middleware"
	"time"
)

// 前缀 + 登录态 + 业务处理器的完整链路：带 Bearer token 访问 /api/v1/account/userlist 应返回 code=1
func TestAuthedEndpointViaAPIPrefix(t *testing.T) {
	if err := db.Open(t.TempDir()); err != nil {
		t.Skipf("无法初始化测试库，跳过：%v", err)
	}
	// Windows 上 SQLite 文件句柄不释放会导致 TempDir 清理失败，用完显式关闭
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
		}
	})
	middleware.InitSession("prefix-test-secret")

	mux := http.NewServeMux()
	registerAPIRoutes(mux, true)

	tok := middleware.MakeSession()
	req := httptest.NewRequest(http.MethodGet, handler.APIPath("/account/userlist"), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, body)
	}
	if strings.Contains(body, `"code":401`) {
		t.Fatalf("登录态未被识别：%s", body)
	}
	if strings.Contains(body, `"code":402`) {
		t.Fatalf("许可拦截误伤：%s", body)
	}
	if !strings.Contains(body, `"code":1`) {
		t.Fatalf("业务未正常返回：%s", body)
	}

	// ---- API Token 全链路：Bearer ksvpn_xxx 经 TokenAuthDispatch → Auth → 业务 handler ----
	makeToken := func(scope string) string {
		plain, hash, prefix, err := middleware.NewAPIToken()
		if err != nil {
			t.Fatalf("NewAPIToken: %v", err)
		}
		_, err = db.DB.Exec(`INSERT INTO api_token(name,token_hash,prefix,scope,created_by,created_at,expires_at,revoked)
			VALUES(?,?,?,?,?,?,0,0)`, "e2e-"+scope, hash, prefix, scope, "tester", time.Now().Unix())
		if err != nil {
			t.Fatalf("insert token: %v", err)
		}
		return plain
	}
	callToken := func(method, path, tok string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	readTok, writeTok := makeToken("read"), makeToken("write")
	// read token 可读
	if code, b := callToken(http.MethodGet, handler.APIPath("/account/userlist"), readTok); code != 200 || strings.Contains(b, `"code":401`) {
		t.Fatalf("read token GET 被拦截: %d %s", code, b)
	}
	// read token 不可写
	if code, b := callToken(http.MethodPost, handler.APIPath("/log/kick"), readTok); code != 401 {
		t.Fatalf("read token POST 应拒绝: %d %s", code, b)
	}
	// 社区版（测试环境无许可）硬约束：write Token 在鉴权层降级为 read，
	// 直连通用 API 的写接口同样被拒，不能绕过「社区版只读」。
	if code, b := callToken(http.MethodPost, handler.APIPath("/log/kick"), writeTok); code != 401 {
		t.Fatalf("社区版 write token POST 应被降级拒绝: %d %s", code, b)
	}
	if code, b := callToken(http.MethodGet, handler.APIPath("/account/userlist"), writeTok); code != 200 {
		t.Fatalf("社区版 write token GET 应可用: %d %s", code, b)
	}
	// 伪造 token 拒绝
	if code, _ := callToken(http.MethodGet, handler.APIPath("/account/userlist"), "ksvpn_fake000000"); code != 401 {
		t.Fatalf("伪造 token 应拒绝，实际 %d", code)
	}
}

// 同一接口用旧别名访问，结果应一致（默认开启别名）
func TestLegacyAliasSameHandler(t *testing.T) {
	if err := db.Open(t.TempDir()); err != nil {
		t.Skipf("无法初始化测试库，跳过：%v", err)
	}
	// Windows 上 SQLite 文件句柄不释放会导致 TempDir 清理失败，用完显式关闭
	t.Cleanup(func() {
		if db.DB != nil {
			_ = db.DB.Close()
		}
	})
	middleware.InitSession("prefix-test-secret")

	mux := http.NewServeMux()
	registerAPIRoutes(mux, true)
	tok := middleware.MakeSession()

	call := func(p string) string {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Body.String()
	}

	canonical := call(handler.APIPath("/account/userlist"))
	for _, legacy := range []string{"/account/userlist", "/api/account/userlist"} {
		if got := call(legacy); got != canonical {
			t.Errorf("旧别名 %s 与新前缀返回不一致\n新: %s\n旧: %s", legacy, canonical, got)
		}
	}
}
