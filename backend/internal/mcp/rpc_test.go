package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ② read scope 只暴露 21 个只读工具；write scope 暴露全部 27 个。
func TestVisibleToolsAndToolsListByScope(t *testing.T) {
	readSrv := NewServer(nil, false, false)
	visible := readSrv.VisibleTools()
	if len(visible) != 21 {
		t.Fatalf("read scope 工具数应为 21，实际 %d", len(visible))
	}
	for _, tool := range visible {
		if tool.Write {
			t.Fatalf("read scope 泄露写工具: %s", tool.Name)
		}
	}
	writeSrv := NewServer(nil, true, true)
	if len(writeSrv.VisibleTools()) != 27 {
		t.Fatalf("write scope 工具数应为 27，实际 %d", len(writeSrv.VisibleTools()))
	}
	if len(BuildTools()) != 27 {
		t.Fatalf("工具总数应为 27，实际 %d", len(BuildTools()))
	}

	res, rpcErr := readSrv.dispatch(context.Background(), &rpcRequest{Method: "tools/list", ID: json.RawMessage(`1`)}, RequestMeta{})
	if rpcErr != nil {
		t.Fatalf("tools/list 失败: %+v", rpcErr)
	}
	list := res.(toolsListResult)
	if len(list.Tools) != 21 || list.TTLMs != 60000 || list.CacheScope != "server" {
		t.Fatalf("tools/list 响应异常: %+v", list)
	}
}

// ⑤ initialize / ping / 未知方法 -32601 / 非法 JSON -32700 / notification 无响应。
func TestProtocolMethods(t *testing.T) {
	srv := NewServer(nil, false, false)

	resp, has := srv.HandleRPC([]byte(`{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2024-11-05"}}`), RequestMeta{})
	if !has {
		t.Fatal("initialize 应有响应")
	}
	var initResp rpcResponse
	if err := json.Unmarshal(resp, &initResp); err != nil {
		t.Fatal(err)
	}
	initObj, ok := initResp.Result.(map[string]any)
	if !ok || initObj["protocolVersion"] != "2024-11-05" {
		t.Fatalf("initialize 应回显协议版本: %s", resp)
	}
	if caps, ok := initObj["capabilities"].(map[string]any); !ok || caps["tools"] == nil {
		t.Fatalf("initialize 缺少 tools 能力: %s", resp)
	}
	if si, ok := initObj["serverInfo"].(map[string]any); !ok || si["name"] != "ksvpn-mcp" {
		t.Fatalf("initialize 缺少 serverInfo: %s", resp)
	}

	resp, has = srv.HandleRPC([]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`), RequestMeta{})
	if !has || !strings.Contains(string(resp), `"result":{}`) {
		t.Fatalf("ping 响应异常: has=%v body=%s", has, resp)
	}

	resp, has = srv.HandleRPC([]byte(`{"jsonrpc":"2.0","id":3,"method":"does/not/exist"}`), RequestMeta{})
	if !has {
		t.Fatal("未知方法应有响应")
	}
	var errResp rpcResponse
	_ = json.Unmarshal(resp, &errResp)
	if errResp.Error == nil || errResp.Error.Code != -32601 {
		t.Fatalf("未知方法应返回 -32601: %s", resp)
	}

	resp, has = srv.HandleRPC([]byte(`{"jsonrpc":"2.0","id":4,`), RequestMeta{})
	var parseErr rpcResponse
	_ = json.Unmarshal(resp, &parseErr)
	if !has || parseErr.Error == nil || parseErr.Error.Code != -32700 {
		t.Fatalf("非法 JSON 应返回 -32700: has=%v body=%s", has, resp)
	}

	_, has = srv.HandleRPC([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), RequestMeta{})
	if has {
		t.Fatal("notification 不应产生响应")
	}
}

// healthRun 修复验证：优先裸路径 /health，失败才回退 /api/v1/health。
func TestHealthRunPrefersBarePath(t *testing.T) {
	const token = "ksvpn_HEALTHTEST1234567890abcdef"

	mux := http.NewServeMux()
	bareHits := 0
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		bareHits++
		_, _ = w.Write([]byte(`{"code":1,"data":{"status":"bare-ok","uptime":"1h"}}`))
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":1,"data":{"status":"fallback"}}`))
	})
	c := NewInternalAPIClient(mux, token)
	text, isErr := healthRun(context.Background(), c, map[string]any{})
	if isErr || !strings.Contains(text, "bare-ok") || strings.Contains(text, "fallback") || bareHits != 1 {
		t.Fatalf("应优先使用裸路径 /health: isErr=%v bareHits=%d text=%s", isErr, bareHits, text)
	}

	// 裸路径失败时回退
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux2.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":1,"data":{"status":"fallback-ok"}}`))
	})
	c2 := NewInternalAPIClient(mux2, token)
	text, isErr = healthRun(context.Background(), c2, map[string]any{})
	if isErr || !strings.Contains(text, "fallback-ok") {
		t.Fatalf("裸路径失败应回退 /api/v1/health: isErr=%v text=%s", isErr, text)
	}
}

// tools/call 不允许 notification 形式：必须返回错误且不执行写工具。
func TestToolsCallNotificationRejected(t *testing.T) {
	srv := NewServer(nil, true, true)
	resp, has := srv.HandleRPC([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ksvpn_stop_all_vpn","arguments":{"confirm":"I_KNOW"}}}`), RequestMeta{})
	if !has || len(resp) == 0 {
		t.Fatal("tools/call notification 应返回错误响应，不能静默执行")
	}
	var out rpcResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32600 || !strings.Contains(out.Error.Message, "notification") {
		t.Fatalf("应返回 -32600 notification 错误: %s", resp)
	}
}

// 批量踢下线 / 停实例属于高危操作，缺 confirm 时必须不发任何请求。
func TestDestructiveToolsRequireConfirm(t *testing.T) {
	mux := http.NewServeMux()
	calls := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	c := NewInternalAPIClient(mux, "ksvpn_testtoken000")

	text, isErr := kickUserRun(context.Background(), c, map[string]any{"all": true})
	if !isErr || !strings.Contains(text, "KICK_ALL") {
		t.Fatalf("批量踢下线缺 confirm 应被拒: isErr=%v text=%s", isErr, text)
	}
	text, isErr = serviceActionRun("/service/stop")(context.Background(), c, map[string]any{"id": json.Number("1")})
	if !isErr || !strings.Contains(text, "STOP") {
		t.Fatalf("停实例缺 confirm 应被拒: isErr=%v text=%s", isErr, text)
	}
	if calls != 0 {
		t.Fatalf("确认失败时不应发起任何 API 请求，实际 %d 次", calls)
	}
}
