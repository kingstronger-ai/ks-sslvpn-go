package middleware

import (
	"context"
	"net/http"
	"strings"
)

// mcpTokenKey 是 MCP 端点专用的 context key：存放 API Token 原文，
// 供 mcp.ServeHTTP 构造 per-request 的 InternalAPIClient（内部回环调用需要带上它）。
type mcpTokenKey struct{}

// MCPTokenFromContext 取出 MCP 端点鉴权成功后注入的 token 原文；不存在时返回空串。
func MCPTokenFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(mcpTokenKey{}).(string); ok {
		return s
	}
	return ""
}

func writeMCPUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"code":401,"msg":"MCP 需要 API Token"}`))
}

// MCPTokenAuth 是 /api/v1/mcp 端点的专用鉴权中间件。
//
// 不使用 TokenAuthDispatch：它会按 HTTP 方法判 scope，而 MCP 握手一律是 POST，
// 会把只读 token 的 initialize / tools/list 误判为需要 write scope。
// 这里只校验 token 有效性；scope 决定工具可见范围（read=21 个只读工具，write=全部 27 个），
// 具体的写操作仍由内部回环调用时的 TokenAuthDispatch 按方法约束。
func MCPTokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerAPIToken(r)
		if !strings.HasPrefix(token, APITokenPrefix) {
			writeMCPUnauthorized(w)
			return
		}
		ip := tokenClientIP(r)
		if tokenIPLocked(ip) {
			writeTokenUnauthorized(w)
			return
		}
		info, ok := AuthenticateToken(token)
		if !ok {
			recordTokenFail(ip)
			writeTokenUnauthorized(w)
			return
		}
		clearTokenFail(ip)
		// 与 TokenAuthDispatch 一致：社区版 write Token 在 context 中即为 read，
		// MCP 工具可见范围与通用 API 权限不会出现两套口径。
		info.Scope = EffectiveAPITokenScope(info)
		ctx := context.WithValue(r.Context(), tokenContextKey{}, info)
		ctx = context.WithValue(ctx, mcpTokenKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
