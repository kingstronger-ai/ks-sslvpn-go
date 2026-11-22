// Package middleware 会话认证与 CORS
package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sslvpn/internal/db"
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
func MakeSessionFor(subject string) string { return signToken(time.Now().Add(sessionTTL).Unix(), subject, "") }

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
