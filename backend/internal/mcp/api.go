package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// defaultProtocolVersion 是无状态核心下的默认回显版本。
	defaultProtocolVersion = "2025-06-18"
	// maxResponseBytes 单次 KSVPN API 响应体上限（8MB）。
	maxResponseBytes = 8 << 20
	// maxRequestBytes 单次 MCP JSON-RPC 请求体上限（1MB）。
	maxRequestBytes = 1 << 20
)

// Logger 日志固定写 stderr；任何 token 只以 prefix 形式出现。
type Logger struct {
	mu    sync.Mutex
	debug bool
	out   *log.Logger
}

func defaultLogger() *Logger {
	return &Logger{debug: false, out: log.New(os.Stderr, "[ksvpn-mcp] ", log.LstdFlags)}
}

func newLoggerWithWriter(w io.Writer, debug bool) *Logger {
	return &Logger{debug: debug, out: log.New(w, "[ksvpn-mcp] ", log.LstdFlags)}
}

func (l *Logger) Info(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Printf("INFO  "+format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Printf("WARN  "+format, args...)
}

func (l *Logger) Debug(format string, args ...any) {
	if !l.debug {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Printf("DEBUG "+format, args...)
}

// loopbackTransport 把 HTTP 请求直接交给主程序 mux，绝不发给真实网络。
// req.URL.Path 保持原样（/api/v1/xxx 走 API 路由，/health、/metrics 走裸路径），
// req.Header 里的 Authorization 原样透传，由 TokenAuthDispatch → Auth → 业务 handler 完成鉴权。
type loopbackTransport struct{ mux http.Handler }

func (t loopbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.mux == nil {
		return nil, fmt.Errorf("MCP 内部回环 mux 未绑定")
	}
	rec := httptest.NewRecorder()
	t.mux.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// APIClient 持有主程序 mux 与当前 AI 请求的 token；每次 MCP HTTP 请求新建一个实例。
type APIClient struct {
	base   string // http://ksvpn.internal/api/v1
	origin string // http://ksvpn.internal，用于 /health、/metrics 等裸路径
	token  string
	log    *Logger
	hc     *http.Client
}

// NewInternalAPIClient 构造内部回环客户端。token 为当前请求携带的 API Token 原文。
func NewInternalAPIClient(mux http.Handler, token string) *APIClient {
	return &APIClient{
		base:   "http://ksvpn.internal/api/v1",
		origin: "http://ksvpn.internal",
		token:  token,
		log:    defaultLogger(),
		hc: &http.Client{
			Transport: loopbackTransport{mux: mux},
			Timeout:   30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type apiResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

func (r *apiResponse) object() (map[string]any, bool) {
	if r == nil || len(bytes.TrimSpace(r.Body)) == 0 {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func (r *apiResponse) code() (int, bool) {
	m, ok := r.object()
	if !ok {
		return 0, false
	}
	v, exists := m["code"]
	if !exists {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, _ := n.Int64()
		return int(i), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func (r *apiResponse) msg() string {
	m, ok := r.object()
	if !ok {
		return ""
	}
	if s, ok := m["msg"].(string); ok {
		return s
	}
	return ""
}

// do 发起一次内部 KSVPN API 调用。bare=true 时拼到 origin 裸路径（/health、/metrics）。
func (c *APIClient) do(ctx context.Context, method, path string, body any, bare bool) (*apiResponse, error) {
	target := c.base + "/" + strings.TrimLeft(path, "/")
	if bare {
		target = c.origin + "/" + strings.TrimLeft(path, "/")
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("请求体序列化失败: %w", err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.log.Debug("%s %s (token=%s)", method, target, tokenPrefix(c.token))
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 KSVPN API 失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 KSVPN API 响应失败: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("KSVPN API 响应超过 %d 字节上限，已截断拒绝", maxResponseBytes)
	}
	return &apiResponse{StatusCode: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: data}, nil
}

// tokenPrefix 只输出 token 前缀；debug 日志绝不出现完整 token。
func tokenPrefix(token string) string {
	if token == "" {
		return "<empty>"
	}
	const show = 7
	if len(token) <= show {
		return token[:1] + "***"
	}
	return token[:show] + "***"
}

// safeErr 保证任何错误信息里都不会出现完整 token。
func (c *APIClient) safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if c.token != "" {
		s = strings.ReplaceAll(s, c.token, "[REDACTED]")
	}
	return s
}

// resultText 把 API 响应转成给 AI 的可读文本与 isError 标志。
func (c *APIClient) resultText(res *apiResponse) (string, bool) {
	if res == nil {
		return "KSVPN API 无响应", true
	}
	if res.StatusCode >= 400 {
		msg := redactString(res.msg())
		switch res.StatusCode {
		case 401:
			return "KSVPN API 返回 401：Token 无效、过期或权限不足（read/write scope）。" + suffixMsg(msg), true
		case 403:
			return "KSVPN API 返回 403：该接口未授权或当前授权版本不支持（专业版/企业版功能，或 Token scope 不足）。" + suffixMsg(msg), true
		default:
			return fmt.Sprintf("KSVPN API 返回 HTTP %d。%s", res.StatusCode, suffixMsg(msg)), true
		}
	}
	if obj, ok := res.object(); ok {
		if code, hasCode := res.code(); hasCode && code != 1 {
			return fmt.Sprintf("KSVPN API 业务失败（code=%d）：%s", code, redactString(res.msg())), true
		}
		return truncateText(prettyJSON(redactValue(obj)), 64<<10), false
	}
	text := strings.TrimSpace(string(res.Body))
	if text == "" {
		return "KSVPN API 返回空响应（操作可能已生效）", false
	}
	return truncateText(c.sanitizeText(text), 64<<10), false
}

func suffixMsg(msg string) string {
	if msg == "" {
		return ""
	}
	return "后端信息：" + msg
}

// sanitizeText 对非 JSON 文本（如 /metrics）做最后一道 token 脱敏。
func (c *APIClient) sanitizeText(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "[REDACTED]")
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func truncateText(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "\n...（输出已截断）"
}

var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "private", "privkey",
	"hash", "otpauth", "authorization", "cookie", "apikey", "api_key", "credential",
}

// redactValue 递归把口令/密钥/hash/TOTP 等敏感字段替换为 [REDACTED]。
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

var sensitiveInlineRE = regexp.MustCompile(`(?i)(password|passwd|secret|token|private_key|privkey|hash|otpauth|credential)\s*[=:]\s*([^\s,;]+)`)

// redactString 处理后端 msg 中夹杂的 key=value / key: value 敏感值。
func redactString(s string) string {
	return sensitiveInlineRE.ReplaceAllString(s, "$1=[REDACTED]")
}
