package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/handler"
	"sslvpn/internal/middleware"
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
