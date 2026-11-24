package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ③ 内部回环调用能真实拿到业务 handler 数据；⑥ 注入的 Authorization 原样透传、path 不被修改。
func TestInternalAPILoopbackAuthAndPaths(t *testing.T) {
	const token = "ksvpn_LOOPBACKTEST1234567890abcdefghij"

	var gotPaths []string
	var gotAuths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/upgrade/version", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuths = append(gotAuths, r.Header.Get("Authorization"))
		if r.Method != http.MethodGet {
			t.Errorf("期望 GET，实际 %s", r.Method)
		}
		_, _ = io.WriteString(w, `{"code":1,"data":{"version":"9.8.7","agent_online":true}}`)
	})
	mux.HandleFunc("/api/v1/service/start", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuths = append(gotAuths, r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil || m["id"] != float64(3) {
			t.Errorf("POST body 未透传: %s err=%v", body, err)
		}
		_, _ = io.WriteString(w, `{"code":1,"msg":"started"}`)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuths = append(gotAuths, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"code":1,"data":{"status":"ok"}}`)
	})

	c := NewInternalAPIClient(mux, token)

	res, err := c.do(context.Background(), http.MethodGet, "/upgrade/version", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !strings.Contains(string(res.Body), `"version":"9.8.7"`) {
		t.Fatalf("回环调用未拿到业务数据: code=%d body=%s", res.StatusCode, res.Body)
	}
	if gotPaths[0] != "/api/v1/upgrade/version" {
		t.Errorf("path 被修改: %s", gotPaths[0])
	}
	if gotAuths[0] != "Bearer "+token {
		t.Errorf("Authorization 未透传: %q", gotAuths[0])
	}

	res, err = c.do(context.Background(), http.MethodPost, "/service/start", map[string]any{"id": 3}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || gotPaths[1] != "/api/v1/service/start" || gotAuths[1] != "Bearer "+token {
		t.Fatalf("POST 回环异常: code=%d paths=%v auths=%v", res.StatusCode, gotPaths, gotAuths)
	}

	res, err = c.do(context.Background(), http.MethodGet, "/health", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !strings.Contains(string(res.Body), `"status":"ok"`) {
		t.Fatalf("裸路径 /health 回环失败: code=%d body=%s", res.StatusCode, res.Body)
	}
	if gotPaths[2] != "/health" || gotAuths[2] != "Bearer "+token {
		t.Errorf("裸路径 path/auth 异常: %s / %q", gotPaths[2], gotAuths[2])
	}
}

// ④ token 不出现在任何响应文本、错误信息与 debug 日志中。
func TestTokenNeverLeaks(t *testing.T) {
	const token = "ksvpn_SUPERSECRET1234567890abcdefghijk"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/boom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"code":0,"msg":"bad token=%s password=secret123"}`, token))
	})
	mux.HandleFunc("/api/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain text contains "+token)
	})
	c := NewInternalAPIClient(mux, token)

	// 业务 msg 中的 token=... 被正则脱敏
	res, err := c.do(context.Background(), http.MethodGet, "/boom", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	text, isErr := c.resultText(res)
	if !isErr || strings.Contains(text, token) {
		t.Fatalf("业务错误信息泄露 token: %s", text)
	}

	// 非 JSON 文本中的 token 被 sanitizeText 替换
	res, err = c.do(context.Background(), http.MethodGet, "/echo", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	text, isErr = c.resultText(res)
	if isErr || strings.Contains(text, token) || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("文本响应泄露 token: isErr=%v text=%s", isErr, text)
	}

	// safeErr 也替换 token
	if got := c.safeErr(errors.New("failed for " + token)); strings.Contains(got, token) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("safeErr 泄露 token: %s", got)
	}

	// debug 日志只打 prefix
	var buf bytes.Buffer
	logger := newLoggerWithWriter(&buf, true)
	logger.Debug("GET /api/v1/x (token=%s)", tokenPrefix(token))
	if strings.Contains(buf.String(), token) || !strings.Contains(buf.String(), "***") {
		t.Fatalf("debug 日志泄露 token: %s", buf.String())
	}
}
