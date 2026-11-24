// Package mcp 把独立版 KSVPN MCP 服务内嵌进 VPN 主程序。
// 工具业务逻辑与独立版逐行一致；HTTP 调用改为内部回环传输（见 api.go）。
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// parseRPCRequest 只解析 MCP 关心的字段；_meta 等扩展字段由 encoding/json 自动忽略。
func parseRPCRequest(data []byte) (*rpcRequest, error) {
	var req rpcRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	if req.Method == "" {
		return nil, fmt.Errorf("缺少 method")
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return nil, fmt.Errorf("jsonrpc 必须为 2.0")
	}
	return &req, nil
}

func (r *rpcRequest) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func newRPCResult(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func newRPCError(id json.RawMessage, code int, msg string) *rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// RequestMeta 来自 HTTP 头的 MCP 协议元信息。
type RequestMeta struct {
	Method   string // Mcp-Method 头（HTTP 模式）
	Name     string // Mcp-Name 头（HTTP 模式）
	Protocol string // MCP-Protocol-Version 头
}

// Server 是 transports 与工具实现之间的协议层。
// 内嵌版每次 MCP HTTP 请求新建一个 Server：client 持有 per-request token，
// enableWrite 由 token scope 决定，避免全局可变状态导致的并发串扰。
type Server struct {
	client       *APIClient
	enableWrite  bool
	tierWrite    bool // 当前授权档位是否开放 mcp_write，仅用于给出准确错误提示
	log          *Logger
	tools        []Tool
	defaultProto string
}

// NewServer 构造一个协议层实例；client 必须已用 NewInternalAPIClient 绑定当前请求的 token。
// tierWrite 只影响提示文案：真正的权限闸门是 enableWrite（scope × 档位）。
func NewServer(client *APIClient, enableWrite bool, tierWrite bool) *Server {
	return &Server{
		client:       client,
		enableWrite:  enableWrite,
		tierWrite:    tierWrite,
		log:          defaultLogger(),
		tools:        BuildTools(),
		defaultProto: defaultProtocolVersion,
	}
}

// VisibleTools 返回当前 scope 下可见的工具列表（read 过滤掉全部写工具）。
func (s *Server) VisibleTools() []Tool {
	if s.enableWrite {
		return s.tools
	}
	out := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		if !t.Write {
			out = append(out, t)
		}
	}
	return out
}

// HandleRPC 处理一段 JSON-RPC 请求体，返回 (响应字节, 是否有响应)。
// notification（无 id）不产生任何输出，由调用方返回 204。
func (s *Server) HandleRPC(data []byte, meta RequestMeta) ([]byte, bool) {
	req, err := parseRPCRequest(data)
	if err != nil {
		resp := newRPCError(json.RawMessage("null"), -32700, err.Error())
		b, _ := json.Marshal(resp)
		return b, true
	}
	if meta.Method == "" {
		meta.Method = req.Method
	}
	s.log.Debug("收到方法 %s（Mcp-Name=%q, 协议=%q）", meta.Method, meta.Name, meta.Protocol)
	if req.isNotification() {
		// tools/call 不允许以 notification 形式提交：否则高危写工具会静默执行、
		// 客户端拿不到任何回执，事后也难以关联调用结果。这里直接拒绝且不执行。
		if req.Method == "tools/call" {
			b, _ := json.Marshal(newRPCError(json.RawMessage("null"), -32600,
				"tools/call 不支持 notification 形式，请携带 id 以获取执行结果"))
			return b, true
		}
		// 其它通知无需回复；未知通知按 MCP 惯例静默忽略（只记方法名，不记参数）。
		s.log.Debug("已处理 notification 方法 %s", req.Method)
		_, _ = s.dispatch(context.Background(), req, meta)
		return nil, false
	}
	result, rpcErr := s.dispatch(context.Background(), req, meta)
	if rpcErr != nil {
		resp := newRPCError(req.ID, rpcErr.Code, rpcErr.Message)
		b, _ := json.Marshal(resp)
		return b, true
	}
	resp := newRPCResult(req.ID, result)
	b, err := json.Marshal(resp)
	if err != nil {
		b, _ = json.Marshal(newRPCError(req.ID, -32603, "响应序列化失败"))
	}
	return b, true
}

func (s *Server) protocolVersion(req *rpcRequest, meta RequestMeta) string {
	if meta.Protocol != "" {
		return meta.Protocol
	}
	if len(req.Params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion != "" {
			return p.ProtocolVersion
		}
	}
	return s.defaultProto
}

func (s *Server) capabilities() map[string]any {
	return map[string]any{
		"tools": map[string]any{"listChanged": false},
	}
}

type toolsListResult struct {
	Tools      []Tool `json:"tools"`
	TTLMs      int    `json:"ttlMs"`
	CacheScope string `json:"cacheScope"`
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest, meta RequestMeta) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": s.protocolVersion(req, meta),
			"capabilities":    s.capabilities(),
			"serverInfo": map[string]any{
				"name":    "ksvpn-mcp",
				"version": "1.0.0",
			},
		}, nil
	case "notifications/initialized":
		return struct{}{}, nil
	case "ping":
		return struct{}{}, nil
	case "server/discover":
		return map[string]any{
			"protocolVersion": s.defaultProto,
			"capabilities":    s.capabilities(),
			"toolCount":       len(s.VisibleTools()),
			"serverInfo": map[string]any{
				"name":    "ksvpn-mcp",
				"version": "1.0.0",
			},
		}, nil
	case "tools/list":
		return toolsListResult{Tools: s.VisibleTools(), TTLMs: 60000, CacheScope: "server"}, nil
	case "tools/call":
		return s.callTool(ctx, req)
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "方法不存在: " + req.Method}
	}
}

func (s *Server) callTool(ctx context.Context, req *rpcRequest) (any, *rpcError) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &rpcError{Code: -32602, Message: "tools/call 参数解析失败: " + err.Error()}
		}
	}
	if params.Name == "" {
		return nil, &rpcError{Code: -32602, Message: "tools/call 缺少 name 参数"}
	}
	tool, found := FindTool(params.Name)
	if !found {
		return toolContent("未知工具 "+params.Name+"。请先调用 tools/list 获取可用工具名。", true), nil
	}
	if tool.Write && !s.enableWrite {
		if s.tierWrite {
			return toolContent("工具 "+tool.Name+" 是写操作，当前 Token 未启用 write scope。请改用 write Token。", true), nil
		}
		return toolContent("工具 "+tool.Name+" 是写操作，当前授权档位不支持（社区版 / 试用 / 未激活仅开放 21 个只读工具，需专业版及以上）。更换 Token 无法解决，请升级授权。", true), nil
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	text, isErr := tool.Run(ctx, s.client, params.Arguments)
	return toolContent(text, isErr), nil
}

func toolContent(text string, isError bool) map[string]any {
	result := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
	}
	if isError {
		result["isError"] = true
	}
	return result
}
