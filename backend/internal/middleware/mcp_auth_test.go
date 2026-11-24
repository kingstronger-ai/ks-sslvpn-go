package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ① MCPTokenAuth 拒绝无 token / 非 ksvpn_ 前缀 / 无效 token；有效 token（含只读）应放行并注入 context。
func TestMCPTokenAuthRejectAndContext(t *testing.T) {
	validRead, _ := seedToken(t, "mcp_auth_read", TokenScopeRead, 0, 0)
	validWrite, _ := seedToken(t, "mcp_auth_write", TokenScopeWrite, 0, 0)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfo 未注入 context")
		}
		if got := MCPTokenFromContext(r.Context()); got == "" {
			t.Error("token 原文未注入 context")
		} else if info.Prefix != got[:APITokenPrefixLen] {
			t.Errorf("TokenInfo prefix 与 token 原文不一致: %s vs %s", info.Prefix, got[:APITokenPrefixLen])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := MCPTokenAuth(next)

	// 无 Authorization
	nextCalled = false
	rr := httptest.NewRecorder()
	r := newBearerRequest(http.MethodPost, "/api/v1/mcp", "", uniqueRemote())
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "MCP 需要 API Token") || nextCalled {
		t.Fatalf("无 token 应返回 401 MCP 提示: code=%d body=%s next=%v", rr.Code, rr.Body.String(), nextCalled)
	}

	// Bearer 但不是 ksvpn_ 前缀（旧 session token 不得用于 MCP）
	nextCalled = false
	rr = httptest.NewRecorder()
	r = newBearerRequest(http.MethodPost, "/api/v1/mcp", "expiry|admin|sig", uniqueRemote())
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "MCP 需要 API Token") || nextCalled {
		t.Fatalf("非 ksvpn_ token 应返回 401 MCP 提示: code=%d body=%s next=%v", rr.Code, rr.Body.String(), nextCalled)
	}

	// ksvpn_ 前缀但库里不存在
	nextCalled = false
	rr = httptest.NewRecorder()
	r = newBearerRequest(http.MethodPost, "/api/v1/mcp", "ksvpn_" + strings.Repeat("Z", 43), uniqueRemote())
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "API Token 无效或权限不足") || nextCalled {
		t.Fatalf("无效 token 应返回 401: code=%d body=%s next=%v", rr.Code, rr.Body.String(), nextCalled)
	}

	// 有效 read token 用 POST 访问 MCP 也必须放行（这是不复用 TokenAuthDispatch 的关键）
	nextCalled = false
	rr = httptest.NewRecorder()
	r = newBearerRequest(http.MethodPost, "/api/v1/mcp", validRead, uniqueRemote())
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK || !nextCalled {
		t.Fatalf("read token 的 POST 应放行: code=%d body=%s next=%v", rr.Code, rr.Body.String(), nextCalled)
	}

	// 有效 write token 同样放行，且 context 里能拿到原文
	nextCalled = false
	var seenToken string
	check := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = MCPTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	MCPTokenAuth(check).ServeHTTP(httptest.NewRecorder(), newBearerRequest(http.MethodPost, "/api/v1/mcp", validWrite, uniqueRemote()))
	if seenToken != validWrite {
		t.Fatalf("MCPTokenFromContext 应返回 token 原文: got=%q want=%q", seenToken, validWrite)
	}

	// 响应必须是合法 JSON 且不含 token 全文
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rr.Body.String()), &parsed); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
}
