// Package middleware 会话认证与 CORS
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
)

var sessionSecret []byte

// InitSession 设置会话签名密钥
func InitSession(secret string) { sessionSecret = []byte(secret) }

const sessionTTL = 12 * time.Hour

// MakeSession 签发匿名会话 token（供测试/兼容调用，无身份信息）
func MakeSession() string { return MakeSessionFor("") }

// MakeSessionFor 签发带管理员身份但无 jti 的 token（expiry|subject|hmac）。
// 仅为兼容上一版格式与测试保留；正式登录请用 MakeSessionFull 获得可吊销能力。
// subject 为空时签发最旧的 expiry.hmac 格式。
func MakeSessionFor(subject string) string {
	return signToken(time.Now().Add(sessionTTL).Unix(), subject, "")
}

// MakeSessionFull 签发正式会话：expiry|subject|jti|hmac，并登记 admin_session（12h）。
// jti 为 16 字节随机 base64url（不含 '|'，可安全作为分段）。
// IP/UA 由登录 handler 随后用 SetSessionClient 补齐。
func MakeSessionFull(subject string) (string, string) {
	jti := randomJTI()
	now := time.Now()
	exp := now.Add(sessionTTL).Unix()
	token := signToken(exp, subject, jti)
	if db.DB != nil {
		var adminID int64
		_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, subject).Scan(&adminID)
		_, _ = db.DB.Exec(`INSERT INTO admin_session(jti,admin_id,username,created_at,expires_at,revoked,last_seen)
			VALUES(?,?,?,?,?,0,0)`, jti, adminID, subject, now.Unix(), exp)
	}
	return token, jti
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// signToken 生成 token：
//   - jti 非空：expiry|subject|jti|hmac（正式会话，可吊销）
//   - subject 非空：expiry|subject|hmac（上一版带身份格式，兼容）
//   - 否则：expiry.hmac（旧匿名格式，兼容）
func signToken(expiry int64, subject, jti string) string {
	payload := strconv.FormatInt(expiry, 10)
	if subject != "" {
		payload += "|" + subject
	}
	if jti != "" {
		payload += "|" + jti
	}
	sum := signPayload(payload)
	if subject != "" {
		return payload + "|" + sum
	}
	return payload + "." + sum
}

func signPayload(payload string) string {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// parseToken 验签并解析 (subject, jti)。兼容三种格式：
//   - expiry.hmac             旧匿名/升级前存量会话：无身份、无 jti
//   - expiry|subject|hmac     上一版带身份格式：无 jti，不查表
//   - expiry|subject|jti|hmac 本版正式会话：带 jti，需查表确认未吊销
func parseToken(token string) (subject, jti string, ok bool) {
	var payload, macHex string
	if strings.Contains(token, "|") {
		parts := strings.SplitN(token, "|", 4)
		switch len(parts) {
		case 4:
			payload, macHex = parts[0]+"|"+parts[1]+"|"+parts[2], parts[3]
			subject, jti = parts[1], parts[2]
		case 3:
			payload, macHex = parts[0]+"|"+parts[1], parts[2]
			subject = parts[1]
		default:
			return "", "", false
		}
	} else {
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		payload, macHex = parts[0], parts[1]
	}
	expPart := payload
	if i := strings.IndexByte(expPart, '|'); i >= 0 {
		expPart = expPart[:i]
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	if !hmac.Equal([]byte(signPayload(payload)), []byte(macHex)) {
		return "", "", false
	}
	return subject, jti, true
}

// CheckSession 校验 token 是否有效；带 jti 的会话同时确认服务端未吊销、未过期。
func CheckSession(token string) bool {
	_, jti, ok := parseToken(token)
	if !ok {
		return false
	}
	if jti != "" {
		return SessionActive(jti)
	}
	return true
}

// SessionUser 返回 token 中的管理员身份；旧格式/匿名 token 返回空串
func SessionUser(token string) string {
	sub, _, _ := parseToken(token)
	return sub
}

// SessionJTI 返回 token 中的会话 jti；旧格式 token 返回空串
func SessionJTI(token string) string {
	_, jti, _ := parseToken(token)
	return jti
}

// SetSessionClient 登录成功后补齐会话的 IP/UA 与 last_seen
func SetSessionClient(jti, ip, userAgent string) {
	if db.DB == nil || jti == "" {
		return
	}
	_, _ = db.DB.Exec(`UPDATE admin_session SET ip=?,user_agent=?,last_seen=? WHERE jti=?`,
		ip, userAgent, time.Now().Unix(), jti)
}

// IsRevoked jti 是否已被吊销；记录不存在也视为已吊销（无法证明有效即拒绝）
func IsRevoked(jti string) bool {
	if db.DB == nil || jti == "" {
		return true
	}
	var revoked int
	if err := db.DB.QueryRow(`SELECT revoked FROM admin_session WHERE jti=?`, jti).Scan(&revoked); err != nil {
		return true
	}
	return revoked != 0
}

// SessionActive jti 对应会话存在、未吊销且未过期
func SessionActive(jti string) bool {
	if db.DB == nil || jti == "" {
		return false
	}
	var revoked int
	var exp int64
	err := db.DB.QueryRow(`SELECT revoked,expires_at FROM admin_session WHERE jti=?`, jti).Scan(&revoked, &exp)
	return err == nil && revoked == 0 && time.Now().Unix() <= exp
}

// RevokeJTI 吊销单个会话（登出 / 管理端强制下线）
func RevokeJTI(jti string) {
	if db.DB == nil || jti == "" {
		return
	}
	_, _ = db.DB.Exec(`UPDATE admin_session SET revoked=1 WHERE jti=?`, jti)
}

// RevokeAdmin 吊销某管理员的全部未吊销会话（改密 / 禁用 / 删除 / revokeAll）
func RevokeAdmin(adminID int64) {
	if db.DB == nil || adminID <= 0 {
		return
	}
	_, _ = db.DB.Exec(`UPDATE admin_session SET revoked=1 WHERE admin_id=? AND revoked=0`, adminID)
}

// SessionInfo 会话列表项
type SessionInfo struct {
	JTI       string `json:"jti"`
	AdminID   int64  `json:"admin_id"`
	Username  string `json:"username"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   int    `json:"revoked"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	LastSeen  int64  `json:"last_seen"`
}

// ListSessions 列出全部管理员会话（管理端 /admin/sessions）
func ListSessions() ([]SessionInfo, error) {
	if db.DB == nil {
		return []SessionInfo{}, nil
	}
	rows, err := db.DB.Query(`SELECT jti,admin_id,username,created_at,expires_at,revoked,ip,user_agent,last_seen
		FROM admin_session ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []SessionInfo{}
	for rows.Next() {
		var s SessionInfo
		if rows.Scan(&s.JTI, &s.AdminID, &s.Username, &s.CreatedAt, &s.ExpiresAt,
			&s.Revoked, &s.IP, &s.UserAgent, &s.LastSeen) == nil {
			list = append(list, s)
		}
	}
	return list, rows.Err()
}

// DeleteExpiredSessions 清理过期会话（登录时顺带调用，不起新 goroutine）
func DeleteExpiredSessions() (int64, error) {
	if db.DB == nil {
		return 0, nil
	}
	res, err := db.DB.Exec(`DELETE FROM admin_session WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- 管理员 MFA 短期票据（5min 过期 + 单 IP 绑定 + HMAC 签名，不落库） ----------

const mfaTicketTTL = 5 * time.Minute

// MakeMFATicket 密码校验通过后签发的一次性二次验证票据
func MakeMFATicket(adminID int64, ip string) string {
	exp := time.Now().Add(mfaTicketTTL).Unix()
	ipEnc := base64.RawURLEncoding.EncodeToString([]byte(ip))
	payload := strconv.FormatInt(exp, 10) + "|" + strconv.FormatInt(adminID, 10) + "|" + ipEnc
	return payload + "|" + hmacSHA256Hex("mfa-ticket|"+payload)
}

// VerifyMFATicket 校验票据签名、有效期与 IP 绑定，成功返回管理员 id
func VerifyMFATicket(ticket, ip string) (int64, bool) {
	parts := strings.SplitN(ticket, "|", 4)
	if len(parts) != 4 {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	adminID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || adminID <= 0 {
		return 0, false
	}
	ipBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || string(ipBytes) != ip {
		return 0, false
	}
	payload := parts[0] + "|" + parts[1] + "|" + parts[2]
	if !hmac.Equal([]byte(hmacSHA256Hex("mfa-ticket|"+payload)), []byte(parts[3])) {
		return 0, false
	}
	return adminID, true
}

func hmacSHA256Hex(msg string) string {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// TokenFromRequest 从 cookie 或 Authorization 头取 token（导出供 handler 复用）
func TokenFromRequest(r *http.Request) string { return tokenFromRequest(r) }

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

// Auth 登录校验中间件：未登录或会话已被服务端吊销返回 code=401
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API Token 已在 TokenAuthDispatch 完成校验与 scope 检查，这里直接放行，
		// 否则 token 请求（无 session cookie）会被二次拦截返回 401。
		if _, tokenOK := TokenInfoFromContext(r.Context()); tokenOK {
			next.ServeHTTP(w, r)
			return
		}
		_, jti, ok := parseToken(tokenFromRequest(r))
		if !ok || (jti != "" && !SessionActive(jti)) {
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

// headerHost 判断 Referer 等 URL 字符串的 host 是否与请求目标一致；
// 解析失败或无 host 时返回 false（调用方决定如何处置）
func headerHostIsSame(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// SameOrigin 非幂等方法（POST/PUT/DELETE 等）的同源校验（CSRF 纵深防御）：
//   - 请求带 Origin/Referer 头时，必须与 Host 同源，否则 403；
//   - 缺失时放行，兼容 curl / 部署脚本 / 桌面客户端等非浏览器调用方。
//
// 配合“破坏性接口一律 POST”可阻断顶层导航型 CSRF（SameSite=Lax 下 GET 导航仍带 Cookie）。
func SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// 幂等方法不做校验
		default:
			if o := r.Header.Get("Origin"); o != "" && !originIsSameHost(r, o) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":403,"msg":"跨站请求已被拒绝（Origin 与站点不同源）"}`))
				return
			}
			if o := r.Header.Get("Origin"); o == "" {
				if ref := r.Header.Get("Referer"); ref != "" && !headerHostIsSame(r, ref) {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"code":403,"msg":"跨站请求已被拒绝（Referer 与站点不同源）"}`))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders 为所有响应加基础安全响应头（F-05）：
//   - X-Frame-Options: DENY            防点击劫持
//   - X-Content-Type-Options: nosniff  防 MIME 嗅探
//   - Referrer-Policy: no-referrer     不外泄管理端 URL
//   - Content-Security-Policy:         XSS 纵深（当前前端依赖内联 onclick 与内联样式，
//     script/style 暂保留 'unsafe-inline' 保底；后续把内联事件迁移为事件委托后收紧）
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// ---------- API Token 认证（与现有 session 认证并行，互不影响） ----------
//
// 集成提示：业务 handler 不需要区分认证方式，只需在 main.go 的 apiEntry 外层包一层
// handler.TokenAuthDispatch（确切代码片段见 KSVPN-API-Token-实现说明.md）。
// 带 Bearer ksvpn_ 的请求走本节校验；不带 token 的请求原样落到现有 session 认证。

const (
	APITokenPrefix    = "ksvpn_"
	APITokenPrefixLen = 12 // "ksvpn_" + 6 位随机串，如 ksvpn_A1b2C3
	TokenScopeRead    = "read"
	TokenScopeWrite   = "write"

	tokenMaxFails     = 10
	tokenLockDuration = 10 * time.Minute
)

// TokenInfo 通过 API Token 校验后得到的身份信息（不含明文/hash）
type TokenInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	CreatedBy string `json:"created_by"`
	Prefix    string `json:"prefix"`
}

type tokenContextKey struct{}

// TokenInfoFromContext 取出 TokenAuth / TokenAuthDispatch 注入的 TokenInfo
func TokenInfoFromContext(ctx context.Context) (TokenInfo, bool) {
	info, ok := ctx.Value(tokenContextKey{}).(TokenInfo)
	return info, ok
}

// HashAPIToken 返回明文 token 的 sha256 hex（库中只存这个值）
func HashAPIToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// NewAPIToken 生成明文 ksvpn_ + 32 字节 crypto/rand 的 base64url（无 padding，约 49 字符）。
// 返回 (明文, sha256, 前 12 位 prefix)；明文只在创建响应里出现一次。
func NewAPIToken() (plain, hash, prefix string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	plain = APITokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashAPIToken(plain), plain[:APITokenPrefixLen], nil
}

// AuthenticateToken 查库、hmac.Equal 常量时间比对 hash，检查 revoked/expires_at，
// 成功后容错更新 last_used_at（写失败不影响认证结果）。
func AuthenticateToken(token string) (TokenInfo, bool) {
	var zero TokenInfo
	if len(token) < APITokenPrefixLen || !strings.HasPrefix(token, APITokenPrefix) || db.DB == nil {
		return zero, false
	}
	hash := HashAPIToken(token)
	rows, err := db.DB.Query(`SELECT id,name,token_hash,scope,created_by,prefix,revoked,expires_at
		FROM api_token WHERE prefix=?`, token[:APITokenPrefixLen])
	if err != nil {
		return zero, false
	}
	var found TokenInfo
	matched := false
	now := time.Now().Unix()
	for rows.Next() {
		var info TokenInfo
		var storedHash string
		var revoked int
		var expiresAt int64
		if rows.Scan(&info.ID, &info.Name, &storedHash, &info.Scope, &info.CreatedBy,
			&info.Prefix, &revoked, &expiresAt) != nil {
			continue
		}
		// 常量时间比较防时序侧信道；prefix 只是索引预筛，真正凭据是 hash。
		if !hmac.Equal([]byte(storedHash), []byte(hash)) {
			continue
		}
		if revoked != 0 || (expiresAt != 0 && now > expiresAt) {
			break
		}
		if info.Scope != TokenScopeRead && info.Scope != TokenScopeWrite {
			break
		}
		found, matched = info, true
		break
	}
	rows.Close()
	if !matched {
		return zero, false
	}
	// 容错写：写失败绝不拒绝请求（如只读副本/短暂锁）。
	_, _ = db.DB.Exec(`UPDATE api_token SET last_used_at=? WHERE id=?`, now, found.ID)
	return found, true
}

// EffectiveAPITokenScope 返回 Token 在当前授权档位下的**实际** scope。
// 社区版 / 试用 / 未激活时 write Token 一律降级为 read：不仅 MCP 写工具不可用，
// 通用 /api/v1 写接口同样不可用，避免绕过「社区版只读」承诺。
func EffectiveAPITokenScope(info TokenInfo) string {
	if info.Scope == TokenScopeWrite && !license.AllowFeature(license.FeatMCPWrite) {
		return TokenScopeRead
	}
	return info.Scope
}

// scopeSatisfies：required="" 或 "read" 时 read/write 均可；"write" 仅 write 可通过。
func scopeSatisfies(actual, required string) bool {
	if required == "" || required == TokenScopeRead {
		return actual == TokenScopeRead || actual == TokenScopeWrite
	}
	return actual == TokenScopeWrite
}

func writeTokenUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"code":401,"msg":"API Token 无效或权限不足"}`))
}

// tokenFailures 是独立的按 IP 失败计数器：loginFailState 在 handler 包内且未导出，
// middleware 无法复用；这里用等价的 10 次/10min 策略 + 独立 map（带锁，惰性清理）。
var tokenFailures = struct {
	sync.Mutex
	m map[string]*tokenFailState
}{m: map[string]*tokenFailState{}}

type tokenFailState struct {
	fails       int
	lockedUntil time.Time
}

// tokenClientIP 只认远端地址，默认不采信 X-Forwarded-For/X-Real-IP（与 login.go 的 clientIP 策略一致）。
func tokenClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func tokenIPLocked(ip string) bool {
	tokenFailures.Lock()
	defer tokenFailures.Unlock()
	st := tokenFailures.m[ip]
	if st == nil {
		return false
	}
	if !st.lockedUntil.IsZero() && time.Now().After(st.lockedUntil) {
		delete(tokenFailures.m, ip)
		return false
	}
	return st.fails >= tokenMaxFails
}

func recordTokenFail(ip string) {
	tokenFailures.Lock()
	defer tokenFailures.Unlock()
	st := tokenFailures.m[ip]
	if st == nil {
		st = &tokenFailState{}
		tokenFailures.m[ip] = st
	}
	st.fails++
	if st.fails >= tokenMaxFails && st.lockedUntil.IsZero() {
		st.lockedUntil = time.Now().Add(tokenLockDuration)
	}
}

func clearTokenFail(ip string) {
	tokenFailures.Lock()
	delete(tokenFailures.m, ip)
	tokenFailures.Unlock()
}

// bearerAPIToken 只从 Authorization: Bearer 取 token（API Token 不接受 cookie，避免与 session 混用）。
func bearerAPIToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// TokenAuth 中间件：从 Bearer 取 token 校验；requiredScope="write" 时强制 write 权限。
// 失败返回 HTTP 401 + {"code":401,"msg":"API Token 无效或权限不足"}；成功把 TokenInfo 放入 context。
func TokenAuth(next http.Handler, requiredScope string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := tokenClientIP(r)
		if tokenIPLocked(ip) {
			writeTokenUnauthorized(w)
			return
		}
		info, ok := AuthenticateToken(bearerAPIToken(r))
		if ok {
			// 与 TokenAuthDispatch / MCPTokenAuth 同一口径：任何 Token 鉴权入口
			// 都不得让社区版 write Token 获得通用 API 的写权限。
			info.Scope = EffectiveAPITokenScope(info)
		}
		if !ok || !scopeSatisfies(info.Scope, requiredScope) {
			recordTokenFail(ip)
			writeTokenUnauthorized(w)
			return
		}
		clearTokenFail(ip)
		ctx := context.WithValue(r.Context(), tokenContextKey{}, info)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenAuthDispatch 供 main.go 的 apiEntry 外层包裹：
//   - 带 Bearer ksvpn_ token：按 method 判 scope（GET/HEAD=read，其它=write）校验，通过后调 fallback；
//   - 不带 token（或 Bearer 非 ksvpn_ 的旧 session token）：原样走 fallback，继续用现有 session 认证。
//
// 业务 handler 无需区分认证方式；需要身份时用 TokenInfoFromContext(r.Context())。
func TokenAuthDispatch(fallback http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerAPIToken(r)
		if token == "" || !strings.HasPrefix(token, APITokenPrefix) {
			fallback(w, r)
			return
		}
		required := TokenScopeRead
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			required = TokenScopeWrite
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
		// 档位降级在鉴权层生效：社区版 write Token 只能以 read 身份进入业务 handler，
		// 也杜绝 AI 客户端绕过 MCP 直接 POST /api/v1 写接口。
		info.Scope = EffectiveAPITokenScope(info)
		if !scopeSatisfies(info.Scope, required) {
			recordTokenFail(ip)
			writeTokenUnauthorized(w)
			return
		}
		clearTokenFail(ip)
		ctx := context.WithValue(r.Context(), tokenContextKey{}, info)
		fallback(w, r.WithContext(ctx))
	}
}
