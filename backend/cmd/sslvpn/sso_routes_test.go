package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 飞书/钉钉/企微的浏览器落地页都挂在根路径下，Go 1.22 的 ServeMux 对重复/冲突模式会 panic，
// 这里用与 main() 相同的注册顺序做一次冒烟，确保不会在启动时崩掉。
func TestSSOLandingRoutesRegisterable(t *testing.T) {
	mux := http.NewServeMux()
	registerAPIRoutes(mux, true)

	mux.HandleFunc("/sso/auth/start", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/sso/callback", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/feishu-sso/auth/start", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/feishu-sso/callback", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/auth/start", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// 三个别名都要能命中，不能被 SPA 兜底吞掉
	for _, p := range []string{"/sso/callback", "/feishu-sso/callback", "/callback", "/healthz"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code == http.StatusNotFound {
			t.Errorf("%s 未注册成功", p)
		}
	}
}
