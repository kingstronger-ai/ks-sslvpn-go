// Package middleware 会话认证与 CORS
package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var sessionSecret []byte

// InitSession 设置会话签名密钥
func InitSession(secret string) { sessionSecret = []byte(secret) }

// signToken 生成 "expiry|hmac(expiry)"
func signToken(expiry int64) string {
	payload := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// MakeSession 签发会话 token（默认 12h）
func MakeSession() string { return signToken(time.Now().Add(12 * time.Hour).Unix()) }

// CheckSession 校验 token 是否有效
func CheckSession(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(parts[0]))
	expect := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expect), []byte(parts[1]))
}

// tokenFromRequest 从 cookie 或 Authorization 头取 token
func tokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie("sslvpn_session"); err == nil && c.Value != "" {
		return c.Value
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// CheckRequest 判断当前请求是否携带有效会话（cookie 或 Bearer token）。
// 供非 API 页面（如客户端下载页）复用与后台完全相同的会话校验规则。
func CheckRequest(r *http.Request) bool {
	return CheckSession(tokenFromRequest(r))
}

// Auth 登录校验中间件：未登录返回 code=401
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !CheckSession(tokenFromRequest(r)) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":401,"msg":"登录状态已失效，请重新登录"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CORS 跨域处理：管理面板为同源 SPA，仅对同源请求回显 CORS 头。
// 不再无条件反射任意 Origin + Allow-Credentials（会被恶意网页借管理员的
// 会话跨域调用 API）；非同源浏览器请求一律不给跨域许可，服务端到服务端
// 调用（curl/脚本）不受影响。
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && originIsSameHost(r, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originIsSameHost 判断 Origin 的 host:port 是否与请求目标一致（同源）
func originIsSameHost(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
