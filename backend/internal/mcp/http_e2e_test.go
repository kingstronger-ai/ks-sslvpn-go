package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
	"sslvpn/internal/middleware"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sslvpn-mcp-test")
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

func seedMCPToken(t *testing.T, name, scope string) string {
	t.Helper()
	plain, hash, prefix, err := middleware.NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO api_token(name,token_hash,prefix,scope,created_by,created_at,expires_at,revoked)
		VALUES(?,?,?,?,?,?,?,?)`, name, hash, prefix, scope, "mcp_test", time.Now().Unix(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, id) })
	return plain
}

func mcpRemote() string {
	n := time.Now().UnixNano()
	return fmt.Sprintf("10.%d.%d.%d:6000", (n/65536)%255, (n/256)%255, n%255)
}

type testRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func postMCP(mux http.Handler, token, payload string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = mcpRemote()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeRPC(t *testing.T, rr *httptest.ResponseRecorder) testRPCResponse {
	t.Helper()
	var resp testRPCResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON-RPC 响应解析失败: %v body=%s", err, rr.Body.String())
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc 字段错误: %s", rr.Body.String())
	}
	return resp
}

func toolText(t *testing.T, result json.RawMessage) (string, bool) {
	t.Helper()
	var obj struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &obj); err != nil || len(obj.Content) == 0 {
		t.Fatalf("tools/call 结果格式错误: %s err=%v", result, err)
	}
	return obj.Content[0].Text, obj.IsError
}

// 写工具双重闸门：Token scope + 授权档位。社区版持 write Token 也只能只读。
func TestMCPWriteTierGate(t *testing.T) {
	cases := []struct {
		scope      string
		tierAllows bool
		want       bool
	}{
		{middleware.TokenScopeRead, true, false},
		{middleware.TokenScopeRead, false, false},
		{middleware.TokenScopeWrite, false, false}, // 社区版 write Token 降级
		{middleware.TokenScopeWrite, true, true},   // 专业版+ write Token 放行
	}
	for _, c := range cases {
		if got := writeToolsAllowed(c.scope, c.tierAllows); got != c.want {
			t.Errorf("writeToolsAllowed(%q, %v) = %v, want %v", c.scope, c.tierAllows, got, c.want)
		}
	}

	// 档位映射：社区版不含 mcp_write，专业版/企业版含。
	for _, tc := range []struct {
		edition string
		want    bool
	}{
		{"", false}, {"community", false}, {"pro", true}, {"enterprise", true},
	} {
		p := license.Payload{Edition: tc.edition}
		if got := p.HasFeature(license.FeatMCPWrite); got != tc.want {
			t.Errorf("Edition=%q mcp_write = %v, want %v", tc.edition, got, tc.want)
		}
	}

	// 测试环境无许可（试用社区版），服务端硬判定应为关闭。
	if license.AllowFeature(license.FeatMCPWrite) {
		t.Error("社区版不应允许 mcp_write")
	}
}

// ②④ MCP HTTP 端点：scope + 档位共同决定工具可见范围；协议头/安全头/notification/405 正确；token 不泄露。
func TestServeHTTPScopeProtocolAndHeaders(t *testing.T) {
	readToken := seedMCPToken(t, "http_read", middleware.TokenScopeRead)
	writeToken := seedMCPToken(t, "http_write", middleware.TokenScopeWrite)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/mcp", middleware.MCPTokenAuth(http.HandlerFunc(ServeHTTP)).ServeHTTP)
	Bind(mux)

	// read token 的 tools/list = 21，且写工具调用被拒
	rr := postMCP(mux, readToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list HTTP 状态错误: %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type 错误: %q", ct)
	}
	if pv := rr.Header().Get("MCP-Protocol-Version"); pv != defaultProtocolVersion {
		t.Fatalf("MCP-Protocol-Version 默认值错误: %q", pv)
	}
	for k, want := range map[string]string{
		"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
	} {
		if got := rr.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	resp := decodeRPC(t, rr)
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &list); err != nil || len(list.Tools) != 21 {
		t.Fatalf("read scope tools/list 应有 21 个工具: n=%d err=%v", len(list.Tools), err)
	}
	for _, tool := range list.Tools {
		if tool.Name == "ksvpn_kick_user" || tool.Name == "ksvpn_stop_all_vpn" {
			t.Fatalf("read scope 泄露写工具: %s", tool.Name)
		}
	}
	if strings.Contains(rr.Body.String(), readToken) {
		t.Fatal("响应泄露 read token")
	}

	rr = postMCP(mux, readToken, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ksvpn_kick_user","arguments":{"username":"alice"}}}`)
	text, isErr := toolText(t, decodeRPC(t, rr).Result)
	if !isErr || !strings.Contains(text, "写操作") {
		t.Fatalf("read scope 调用写工具应被拒: isErr=%v text=%s", isErr, text)
	}

	// 社区版下 write token 也被档位闸门降级为 21 个只读工具。
	// （专业版/企业版才按 scope 放开全部 27 个，见 TestMCPWriteTierGate。）
	rr = postMCP(mux, writeToken, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	resp = decodeRPC(t, rr)
	if err := json.Unmarshal(resp.Result, &list); err != nil || len(list.Tools) != 21 {
		t.Fatalf("社区版 write scope tools/list 应降级为 21 个工具: n=%d err=%v", len(list.Tools), err)
	}
	for _, tool := range list.Tools {
		if tool.Name == "ksvpn_kick_user" || tool.Name == "ksvpn_stop_all_vpn" {
			t.Fatalf("社区版泄露写工具: %s", tool.Name)
		}
	}
	if strings.Contains(rr.Body.String(), writeToken) {
		t.Fatal("响应泄露 write token")
	}
	rr = postMCP(mux, writeToken, `{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"ksvpn_kick_user","arguments":{"username":"alice"}}}`)
	text, isErr = toolText(t, decodeRPC(t, rr).Result)
	if !isErr || !strings.Contains(text, "写操作") {
		t.Fatalf("社区版 write token 调用写工具应被拒: isErr=%v text=%s", isErr, text)
	}

	// 请求头里的协议版本回显
	rr2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	req.RemoteAddr = mcpRemote()
	mux.ServeHTTP(rr2, req)
	if got := rr2.Header().Get("MCP-Protocol-Version"); got != "2025-03-26" {
		t.Fatalf("协议版本未回显: %q", got)
	}

	// notification 返回 204 无 body
	rr2 = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Authorization", "Bearer "+readToken)
	req.RemoteAddr = mcpRemote()
	mux.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNoContent || rr2.Body.Len() != 0 {
		t.Fatalf("notification 应返回 204 空 body: code=%d body=%s", rr2.Code, rr2.Body.String())
	}

	// 非 POST 返回 405 + Allow
	rr2 = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	mux.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusMethodNotAllowed || rr2.Header().Get("Allow") != "POST" {
		t.Fatalf("GET 应返回 405 + Allow:POST: code=%d allow=%q", rr2.Code, rr2.Header().Get("Allow"))
	}
}

// 端到端：真实 ServeMux + TokenAuthDispatch 风格假业务路由 + MCP 端点；
// read token 走 initialize → tools/list → ksvpn_status → ksvpn_health，验证内部回环全链路。
func TestEndToEndReadTokenFullChain(t *testing.T) {
	readToken := seedMCPToken(t, "e2e_fullchain", middleware.TokenScopeRead)

	mux := http.NewServeMux()
	apiEntry := func(fn http.HandlerFunc) http.HandlerFunc {
		return middleware.TokenAuthDispatch(fn) // 与 main.go 的 apiEntry 外层一致
	}
	statusHits, healthHits, bareHealthHits := 0, 0, 0
	mux.HandleFunc("/api/v1/upgrade/version", apiEntry(func(w http.ResponseWriter, r *http.Request) {
		statusHits++
		if r.Method != http.MethodGet {
			t.Errorf("upgrade/version 应为 GET: %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"code":1,"data":{"version":"9.9.9","agent_online":true}}`))
	}))
	mux.HandleFunc("/api/v1/health", apiEntry(func(w http.ResponseWriter, r *http.Request) {
		healthHits++
		_, _ = w.Write([]byte(`{"code":1,"data":{"status":"canonical","uptime":"2d","instances":3,"online":7,"disk_percent":42,"cert_days":{"server":100}}}`))
	}))
	// 真实主程序里 /health 裸路径由 staticFileHandler 兜底；这里模拟同一行为。
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		bareHealthHits++
		_, _ = w.Write([]byte(`{"code":1,"data":{"status":"ok","uptime":"2d","instances":3,"online":7,"disk_percent":42,"cert_days":{"server":100}}}`))
	})
	mux.HandleFunc("/api/v1/mcp", middleware.MCPTokenAuth(http.HandlerFunc(ServeHTTP)).ServeHTTP)
	Bind(mux)

	var allBodies []string

	// 1) initialize
	rr := postMCP(mux, readToken, `{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	resp := decodeRPC(t, rr)
	initObj := map[string]any{}
	_ = json.Unmarshal(resp.Result, &initObj)
	if initObj["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize 协议版本错误: %s", resp.Result)
	}
	allBodies = append(allBodies, rr.Body.String())

	// 2) tools/list
	rr = postMCP(mux, readToken, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	resp = decodeRPC(t, rr)
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &list); err != nil || len(list.Tools) != 21 {
		t.Fatalf("tools/list 应有 21 个工具: n=%d err=%v", len(list.Tools), err)
	}
	foundStatus := false
	for _, tool := range list.Tools {
		if tool.Name == "ksvpn_status" {
			foundStatus = true
		}
	}
	if !foundStatus {
		t.Fatal("tools/list 缺少 ksvpn_status")
	}
	allBodies = append(allBodies, rr.Body.String())

	// 3) tools/call ksvpn_status —— 内部回环必须真实拿到业务 handler 数据
	rr = postMCP(mux, readToken, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ksvpn_status","arguments":{}}}`)
	resp = decodeRPC(t, rr)
	text, isErr := toolText(t, resp.Result)
	if isErr {
		t.Fatalf("ksvpn_status 不应报错: %s", text)
	}
	for _, want := range []string{"9.9.9", "canonical", "3", "7", "42%", "server=100天"} {
		if !strings.Contains(text, want) {
			t.Errorf("ksvpn_status 缺少 %q: %s", want, text)
		}
	}
	if statusHits == 0 || healthHits == 0 {
		t.Fatalf("内部回环未命中业务 handler: statusHits=%d healthHits=%d", statusHits, healthHits)
	}
	allBodies = append(allBodies, rr.Body.String())

	// 4) tools/call ksvpn_health —— 验证裸路径 /health 被实际使用
	rr = postMCP(mux, readToken, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ksvpn_health","arguments":{}}}`)
	resp = decodeRPC(t, rr)
	text, isErr = toolText(t, resp.Result)
	if isErr || !strings.Contains(text, `"status": "ok"`) || bareHealthHits == 0 {
		t.Fatalf("ksvpn_health 应通过裸路径 /health 拿到数据: isErr=%v hits=%d text=%s", isErr, bareHealthHits, text)
	}
	allBodies = append(allBodies, rr.Body.String())

	// token 绝不出现在任何响应里
	for _, body := range allBodies {
		if strings.Contains(body, readToken) {
			t.Fatal("端到端响应泄露 token 明文")
		}
	}
}
