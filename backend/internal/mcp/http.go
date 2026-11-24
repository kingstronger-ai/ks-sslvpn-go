package mcp

import (
	"io"
	"net/http"
	"sync/atomic"

	"sslvpn/internal/license"
	"sslvpn/internal/middleware"
)

// writeToolsAllowed 判断写工具是否开放：Token 须为 write scope，且当前授权档位
// 开放 mcp_write（专业版起）。社区版持 write Token 也会被降级为只读。
func writeToolsAllowed(scope string, tierAllows bool) bool {
	return scope == middleware.TokenScopeWrite && tierAllows
}

// boundMux 在启动阶段由 Bind 一次性设置，之后只读，避免全局可变状态竞态。
var boundMux atomic.Value // 存储 http.Handler

// Bind 绑定主程序 mux（仅应在启动阶段调用一次）。
func Bind(mux http.Handler) {
	if mux != nil {
		boundMux.Store(mux)
	}
}

func currentMux() http.Handler {
	v := boundMux.Load()
	if v == nil {
		return nil
	}
	h, _ := v.(http.Handler)
	return h
}

// ServeHTTP 是内嵌 MCP 的 Streamable HTTP 端点。
// 鉴权由 middleware.MCPTokenAuth 在外层完成：TokenInfo 决定工具可见范围，
// token 原文用于构造 per-request 的 InternalAPIClient。
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"仅支持 POST /api/v1/mcp（Streamable HTTP）；SSE 未启用"}`))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":"请求体过大"}`))
		return
	}

	token := middleware.MCPTokenFromContext(r.Context())
	info, _ := middleware.TokenInfoFromContext(r.Context())
	// 写工具双重闸门：Token 须为 write scope，且当前授权档位开放 mcp_write（专业版起）。
	// 社区版禁止创建 write Token；存量 write Token 也按只读处理（鉴权层已降级）。
	// 硬拦截在服务端，不依赖前端隐藏。
	tierWrite := license.AllowFeature(license.FeatMCPWrite)
	enableWrite := writeToolsAllowed(info.Scope, tierWrite)

	// debug 日志只打 token 前缀，绝不打全文。
	defaultLogger().Debug("MCP 请求 token=%s scope=%s tier_write=%v enable_write=%v", tokenPrefix(token), info.Scope, tierWrite, enableWrite)

	mux := currentMux()
	if mux == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"MCP 内部回环未初始化"}`))
		return
	}

	client := NewInternalAPIClient(mux, token)
	srv := NewServer(client, enableWrite, tierWrite)

	meta := RequestMeta{
		Method:   r.Header.Get("Mcp-Method"),
		Name:     r.Header.Get("Mcp-Name"),
		Protocol: r.Header.Get("MCP-Protocol-Version"),
	}
	if meta.Protocol == "" {
		meta.Protocol = defaultProtocolVersion
	}

	w.Header().Set("MCP-Protocol-Version", meta.Protocol)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	resp, hasResponse := srv.HandleRPC(body, meta)
	if !hasResponse {
		// notification：无响应体。
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, _ = w.Write(resp)
}
