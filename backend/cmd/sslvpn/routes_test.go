package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"sslvpn/internal/handler"
)

// ServeMux 对冲突模式会 panic，这里确保加了前缀后仍能正常注册
func TestRegisterAPIRoutesNoPanic(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		func() {
			defer func() {
				if e := recover(); e != nil {
					t.Fatalf("legacyAlias=%v 注册路由 panic: %v", legacy, e)
				}
			}()
			registerAPIRoutes(http.NewServeMux(), legacy)
		}()
	}
}

// 规范前缀必须命中路由（不能落到静态兜底），且带 X-API-Version 响应头
func TestCanonicalPrefixReachable(t *testing.T) {
	mux := http.NewServeMux()
	registerAPIRoutes(mux, true)
	// 模拟 main() 里的兜底处理器
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if handler.Routes[handler.BasePath(r.URL.Path)].H != nil {
			t.Errorf("接口 %s 落到了静态兜底", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// 用 GET 请求一个已知的 GET 公开接口：期望被路由接住（不是 404）
	req := httptest.NewRequest(http.MethodGet, handler.APIPath("/captcha"), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("%s 未被路由接住，返回 404", handler.APIPath("/captcha"))
	}
	if got := rec.Header().Get("X-API-Version"); got != "v1" {
		t.Errorf("X-API-Version = %q, want v1", got)
	}
}

// 关闭旧别名后，裸路径不应再命中接口
func TestLegacyAliasCanBeDisabled(t *testing.T) {
	mux := http.NewServeMux()
	registerAPIRoutes(mux, false)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// main() 里会在这里判定「已知接口但前缀不对」并返回 JSON；测试只关心没走到真实处理器
		w.WriteHeader(http.StatusNotFound)
	})
	for _, p := range []string{"/captcha", "/api/captcha"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("关闭别名后 %s 仍返回 %d（应为兜底的 404）", p, rec.Code)
		}
	}
}
