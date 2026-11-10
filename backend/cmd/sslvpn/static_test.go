package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/webfs"
)

// 静态资源处理器：响应必须与内嵌文件逐字节一致，且带 ETag/no-cache（防升级白屏）
func TestStaticFileHandler(t *testing.T) {
	dist, err := webfs.Dist()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(staticFileHandler(dist))
	defer srv.Close()

	embedIndex, _ := fs.ReadFile(dist, "index.html")
	embedJS, _ := fs.ReadFile(dist, "app.js")

	// 1. 首页 → HTML 且字节一致
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if string(body) != string(embedIndex) {
		t.Fatalf("index.html 响应与内嵌内容不一致: got %d bytes", len(body))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("index Content-Type = %q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("ETag") == "" {
		t.Fatalf("index 缺少 Cache-Control/ETag: %q / %q", resp.Header.Get("Cache-Control"), resp.Header.Get("ETag"))
	}

	// 2. app.js → 字节一致 + JS MIME
	resp2, _ := http.Get(srv.URL + "/app.js")
	body2 := readAll(t, resp2)
	if string(body2) != string(embedJS) {
		t.Fatalf("app.js 响应与内嵌内容不一致: got %d bytes want %d", len(body2), len(embedJS))
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.Contains(ct, "text/javascript") {
		t.Fatalf("app.js Content-Type = %q", ct)
	}

	// 3. ETag 条件请求 → 304
	req3, _ := http.NewRequest("GET", srv.URL+"/app.js", nil)
	req3.Header.Set("If-None-Match", resp2.Header.Get("ETag"))
	client := &http.Client{}
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match 应命中 304, got %d", resp3.StatusCode)
	}

	// 4. 未知路径 → SPA 回退 index.html
	resp4, _ := http.Get(srv.URL + "/some/spa/route")
	body4 := readAll(t, resp4)
	if string(body4) != string(embedIndex) {
		t.Fatalf("SPA 回退应返回 index.html, got %d bytes", len(body4))
	}

	// 5. logo.png → 图片 MIME
	resp5, _ := http.Get(srv.URL + "/logo.png")
	if ct := resp5.Header.Get("Content-Type"); !strings.Contains(ct, "image/png") {
		t.Fatalf("logo Content-Type = %q", ct)
	}
}

func readAll(t *testing.T, r *http.Response) []byte {
	t.Helper()
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf
}
