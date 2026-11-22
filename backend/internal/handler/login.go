// login / captcha / 找回密码 / 注册 / 轮询
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
	"sslvpn/internal/mail"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// ---------- 登录 ----------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Captcha  string `json:"captcha"`
	CodeID   string `json:"code_id"`
}

// 登录失败锁定采用双维度：真实 IP 与用户名。
// 仅按 IP 锁定时，攻击者可用伪造代理头或轮换出口 IP 绕过；加上 username 维度后，
// 即使 IP 不断变化，针对同一个账号（如 admin）的爆破仍会在阈值处被锁定。
// 带到期时间，避免失败计数只增不减导致合法用户被永久锁死（DoS）。
const (
	loginMaxFails     = 10
	loginLockDuration = 10 * time.Minute
)

type loginFailState struct {
	fails       int
	lockedUntil time.Time
}

var loginAttempts = struct {
	sync.Mutex
	m map[string]*loginFailState
}{m: map[string]*loginFailState{}}

// loginLocked 检查某键是否处于锁定期；过期条目在此惰性清理。
func loginLocked(key string) bool {
	st := loginAttempts.m[key]
	if st == nil {
		return false
	}
	if !st.lockedUntil.IsZero() && time.Now().After(st.lockedUntil) {
		delete(loginAttempts.m, key)
		return false
	}
	return st.fails >= loginMaxFails
}

func LoginCheck(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	ip := clientIP(r)
	user := strings.ToLower(strings.TrimSpace(req.Username))
	ipKey := "ip:" + ip
	userKey := "u:" + user

	// 登录失败次数限制（真实 IP + 用户名双维度，任一锁定即拒绝）
	loginAttempts.Lock()
	ipLocked, userLocked := loginLocked(ipKey), loginLocked(userKey)
	loginAttempts.Unlock()
	if ipLocked || userLocked {
		util.Fail(w, "失败次数过多，请 10 分钟后再试")
		return
	}

	// 图形验证码
	if !checkCaptcha(req.CodeID, req.Captcha) {
		util.Fail(w, "验证码错误")
		return
	}

	var hash string
	var status, super, totpEnabled int
	var adminID int64
	err := db.DB.QueryRow(`SELECT id,password,status,COALESCE(super,0),COALESCE(totp_enabled,0) FROM admin WHERE username=?`, req.Username).
		Scan(&adminID, &hash, &status, &super, &totpEnabled)
	if err != nil || status != 1 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		recordLoginFail(ipKey, userKey)
		db.Syslog(req.Username, "登录失败", "用户名或密码错误", ip)
		util.Fail(w, "用户名或密码错误")
		return
	}

	loginAttempts.Lock()
	delete(loginAttempts.m, ipKey)
	delete(loginAttempts.m, userKey)
	loginAttempts.Unlock()

	// B1-2：开启管理员 MFA 时，密码正确只发短期票据，不签发会话
	if totpEnabled == 1 {
		mfaTicket := middleware.MakeMFATicket(adminID, ip)
		db.SyslogWithID(req.Username, "需要二次验证", "", ip, adminID)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 10, "msg": "需要二次验证", "mfa_token": mfaTicket,
		})
		return
	}

	// B1-1：正式会话带 jti 并落库，服务端可随时吊销；顺带清理过期会话
	middleware.DeleteExpiredSessions()
	token, jti := middleware.MakeSessionFull(req.Username)
	middleware.SetSessionClient(jti, ip, r.UserAgent())
	http.SetCookie(w, &http.Cookie{
		Name: "sslvpn_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: requestIsHTTPS(r),
	})
	db.SyslogWithID(req.Username, "登录成功", "", ip, adminID)
	incrLoginCount()
	util.OKMsg(w, "登录成功", map[string]string{"token": token, "username": req.Username, "super": superFlag(super)})
}

// recordLoginFail 对给定维度（IP / 用户名）累加失败次数，达阈值后锁定 10 分钟。
func recordLoginFail(keys ...string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	for _, k := range keys {
		st := loginAttempts.m[k]
		if st == nil {
			st = &loginFailState{}
			loginAttempts.m[k] = st
		}
		st.fails++
		if st.fails >= loginMaxFails && st.lockedUntil.IsZero() {
			st.lockedUntil = time.Now().Add(loginLockDuration)
		}
	}
}

// incrLoginCount 登录成功计数
func incrLoginCount() {
	if n, err := strconv.Atoi(db.GetSetting("login_count")); err == nil {
		db.SetSetting("login_count", strconv.Itoa(n+1))
	} else {
		db.SetSetting("login_count", "1")
	}
}

// superFlag 管理员 super 标记序列化为 "1"/"0"（前端据此显隐管理员管理入口）
func superFlag(super int) string {
	if super == 1 {
		return "1"
	}
	return "0"
}

// LoginMFA 管理员二次验证：/logincheck 密码通过后发的 mfa_token + TOTP（或恢复码）换正式会话。
// 未开 MFA 的管理员不会走到这里；失败同样计入 loginFailState 防爆破。
func LoginMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfa_token"`
		OTP      string `json:"otp"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.MFAToken == "" || strings.TrimSpace(req.OTP) == "" {
		util.Fail(w, "参数错误")
		return
	}
	ip := clientIP(r)
	ipKey := "ip:" + ip
	loginAttempts.Lock()
	ipLocked := loginLocked(ipKey)
	loginAttempts.Unlock()
	if ipLocked {
		util.Fail(w, "失败次数过多，请 10 分钟后再试")
		return
	}

	adminID, ok := middleware.VerifyMFATicket(req.MFAToken, ip)
	if !ok || adminID <= 0 {
		recordLoginFail(ipKey)
		db.Syslog("unknown", "MFA 票据无效", "签名/有效期/IP 绑定校验失败", ip)
		util.Fail(w, "二次验证票据无效或已过期，请重新登录")
		return
	}

	var username, secret, recovery string
	var status, super, totpEnabled int
	err := db.DB.QueryRow(`SELECT username,status,COALESCE(super,0),COALESCE(totp_enabled,0),
		COALESCE(totp_secret,''),COALESCE(totp_recovery,'') FROM admin WHERE id=?`, adminID).
		Scan(&username, &status, &super, &totpEnabled, &secret, &recovery)
	if err != nil || status != 1 || totpEnabled != 1 {
		recordLoginFail(ipKey)
		util.Fail(w, "二次验证票据已失效，请重新登录")
		return
	}
	userKey := "u:" + strings.ToLower(strings.TrimSpace(username))
	loginAttempts.Lock()
	userLocked := loginLocked(userKey)
	loginAttempts.Unlock()
	if userLocked {
		util.Fail(w, "失败次数过多，请 10 分钟后再试")
		return
	}

	otp := strings.TrimSpace(req.OTP)
	verified := (secret != "" && util.VerifyTOTP(secret, otp)) || consumeRecoveryCode(adminID, recovery, otp)
	if !verified {
		recordLoginFail(ipKey, userKey)
		db.SyslogWithID(username, "MFA 验证失败", "", ip, adminID)
		util.Fail(w, "动态码或恢复码错误；连续错误将被临时锁定")
		return
	}

	loginAttempts.Lock()
	delete(loginAttempts.m, ipKey)
	delete(loginAttempts.m, userKey)
	loginAttempts.Unlock()

	middleware.DeleteExpiredSessions()
	token, jti := middleware.MakeSessionFull(username)
	middleware.SetSessionClient(jti, ip, r.UserAgent())
	http.SetCookie(w, &http.Cookie{
		Name: "sslvpn_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r),
	})
	db.SyslogWithID(username, "登录成功（MFA）", "", ip, adminID)
	incrLoginCount()
	util.OKMsg(w, "登录成功", map[string]string{"token": token, "username": username, "super": superFlag(super)})
}

// consumeRecoveryCode 校验并消费单个 MFA 恢复码（单次使用），成功后从库中移除该码
func consumeRecoveryCode(adminID int64, recoveryJSON, code string) bool {
	if code == "" || recoveryJSON == "" {
		return false
	}
	var hashes []string
	if err := json.Unmarshal([]byte(recoveryJSON), &hashes); err != nil {
		return false
	}
	digest := sha256s(code)
	kept := make([]string, 0, len(hashes))
	used := false
	for _, h := range hashes {
		if !used && h == digest {
			used = true
			continue
		}
		kept = append(kept, h)
	}
	if !used {
		return false
	}
	b, _ := json.Marshal(kept)
	_, _ = db.DB.Exec(`UPDATE admin SET totp_recovery=? WHERE id=?`, string(b), adminID)
	return true
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// B1-1：登出即吊销服务端会话，避免仅删 cookie 导致的会话继续有效
	if jti := middleware.SessionJTI(middleware.TokenFromRequest(r)); jti != "" {
		middleware.RevokeJTI(jti)
	}
	syslogFromRequest(r, "退出登录", "")
	http.SetCookie(w, &http.Cookie{Name: "sslvpn_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r)})
	util.OKMsg(w, "已退出", nil)
}

// requestIsHTTPS 判断当前请求是否经 HTTPS 到达：TLS 直连，或可信反代传入
// X-Forwarded-Proto: https。仅 https 会话才给 Cookie 加 Secure 属性，
// 避免纯 http 内网部署（如 SSLVPN_API_BIND 明文口）登录态失效。
func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// trustProxyHeaders 仅在显式开启 SSLVPN_TRUST_PROXY=1 时才采信 X-Real-IP / X-Forwarded-For。
// 默认关闭：服务由 ListenAndServeTLS 直接对外，没有可信反代强制覆写这些头，
// 任意客户端都能伪造它们来绕过按 IP 的登录/限流锁定（CWE-290）。
func trustProxyHeaders() bool {
	return os.Getenv("SSLVPN_TRUST_PROXY") == "1"
}

func clientIP(r *http.Request) string {
	if trustProxyHeaders() {
		if v := r.Header.Get("X-Real-IP"); v != "" {
			return strings.TrimSpace(v)
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host := r.RemoteAddr
	// 优先用标准库解析，兼容 IPv6（如 "[::1]:58443"）；失败再退回按最后一个冒号切分
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// ---------- 图形验证码（算术式，SVG 输出） ----------

var captchaStore = struct {
	sync.Mutex
	m       map[string]string
	expired map[string]time.Time
}{m: map[string]string{}, expired: map[string]time.Time{}}

func Captcha(w http.ResponseWriter, r *http.Request) {
	a, b := time.Now().Unix()%9+1, time.Now().UnixNano()%9+1
	ans := fmt.Sprint(a + b)
	id := util.RandomHex(8)
	captchaStore.Lock()
	// 清理过期项
	for k := range captchaStore.m {
		if len(k) > 0 && captchaStore.expired[k].Before(time.Now()) {
			delete(captchaStore.m, k)
			delete(captchaStore.expired, k)
		}
	}
	captchaStore.m[id] = ans
	captchaStore.expired[id] = time.Now().Add(5 * time.Minute)
	captchaStore.Unlock()

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40">
<rect width="120" height="40" fill="#f0f2f5"/>
<text x="60" y="27" font-size="22" text-anchor="middle" fill="#333">%d + %d = ?</text></svg>`, a, b)
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("X-Captcha-Id", id)
	util.OK(w, map[string]string{"code_id": id, "svg": svg})
}

func checkCaptcha(id, input string) bool {
	// 管理登录始终需要验证码：留空、缺 code_id 一律拒绝，防止脚本不带 captcha 字段绕过
	if strings.TrimSpace(id) == "" || strings.TrimSpace(input) == "" {
		return false
	}
	captchaStore.Lock()
	defer captchaStore.Unlock()
	ans, ok := captchaStore.m[id]
	if !ok {
		return false
	}
	delete(captchaStore.m, id)
	return ans == strings.TrimSpace(input)
}

// ---------- 安全码：HMAC 入库 + 失败锁定 + 单码 ----------

const (
	secureCodeLen    = 8
	codeMaxFails     = 5
	codeLockDuration = 10 * time.Minute
	codeSendInterval = 60 * time.Second
)

type codeFailState struct {
	fails    int
	until    time.Time // 锁定到期时间；零值表示未锁定
	lastSent time.Time // 上次发码时间（key 前缀 send:）
}

// codeAttempts 失败计数/锁定状态：进程内维护。
// key 形如 "ip:<ip>"、"t:<target>"、"send:<target>"，三个维度互不冲突。
var codeAttempts = struct {
	sync.Mutex
	m map[string]*codeFailState
}{m: map[string]*codeFailState{}}

func secureCodeKey() string {
	if k := db.GetSetting("session_secret"); k != "" {
		return k
	}
	return "ks-sslvpn-secure-code" // 兜底：正常启动 runInit 已生成 session_secret
}

// codeLocked 任一维度处于锁定期即返回 true。
func codeLocked(keys ...string) bool {
	now := time.Now()
	codeAttempts.Lock()
	defer codeAttempts.Unlock()
	for _, k := range keys {
		if st := codeAttempts.m[k]; st != nil && st.until.After(now) {
			return true
		}
	}
	return false
}

func codeFail(keys ...string) {
	codeAttempts.Lock()
	defer codeAttempts.Unlock()
	for _, k := range keys {
		st := codeAttempts.m[k]
		if st == nil {
			st = &codeFailState{}
			codeAttempts.m[k] = st
		}
		st.fails++
		if st.fails >= codeMaxFails {
			st.until = time.Now().Add(codeLockDuration)
			st.fails = 0
		}
	}
}

func codeClear(keys ...string) {
	codeAttempts.Lock()
	defer codeAttempts.Unlock()
	for _, k := range keys {
		delete(codeAttempts.m, k)
	}
}

// canSendCode 同一 target 冷却期内不允许重复发码（防邮件轰炸 / 撞库探测）。
func canSendCode(target string) bool {
	key := "send:" + target
	codeAttempts.Lock()
	defer codeAttempts.Unlock()
	st := codeAttempts.m[key]
	if st != nil && time.Since(st.lastSent) < codeSendInterval {
		return false
	}
	if st == nil {
		st = &codeFailState{}
		codeAttempts.m[key] = st
	}
	st.lastSent = time.Now()
	return true
}

// issueSecureCode 发码：单 target 仅保留一张未消费码，库中只存 HMAC 摘要。
func issueSecureCode(target, email, subject, what string) (string, error) {
	code := util.RandomAlnumCode(secureCodeLen)
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE target=?`, target) // 新码作废旧码
	digest := util.HMACSHA256Hex(secureCodeKey(), code)
	_, _ = db.DB.Exec(`INSERT INTO secure_code(target,code,expire_at) VALUES(?,?,?)`,
		target, digest, time.Now().Add(10*time.Minute).Format("2006-01-02 15:04:05"))
	if err := mail.Send(loadSMTP(), email, subject,
		"<p>您的"+what+"是：<b>"+code+"</b>，10 分钟内有效。如非本人操作请忽略。</p>"); err != nil {
		return "", err
	}
	return code, nil
}

// verifySecureCode 校验并消费安全码，成功返回该码 id；keys 为失败计数维度。
func verifySecureCode(target, code string, keys ...string) (int64, bool) {
	if strings.TrimSpace(code) == "" || codeLocked(keys...) {
		return 0, false
	}
	digest := util.HMACSHA256Hex(secureCodeKey(), code)
	var id int64
	err := db.DB.QueryRow(`SELECT id FROM secure_code WHERE target=? AND code=? AND expire_at>datetime('now','localtime')`,
		target, digest).Scan(&id)
	if err != nil {
		codeFail(keys...)
		return 0, false
	}
	codeClear(keys...)
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE id=?`, id)
	return id, true
}

// codeDims 返回某次校验的 IP + target 两个失败计数维度。
func codeDims(r *http.Request, target string) []string {
	return []string{"ip:" + clientIP(r), "t:" + target}
}

// ---------- VPN 用户自助注册 / 找回 ----------

func smtpCfg() *mail.Config { return loadSMTP() }

func GetFlag(w http.ResponseWriter, r *http.Request) {
	// 返回系统标识信息（原系统用于前端初始化判断）
	util.OK(w, map[string]any{
		"flag":          "ks-sslvpn-go",
		"register":      db.GetSetting("register_user_status") == "1",
		"sys_name":      db.GetSetting("sys_name"),
		"download_url":  db.GetSetting("download_url"),
		"copyright":     db.GetSetting("copyright"),
		"copyright_url": db.GetSetting("copyright_url"),
	})
}

func GetSafeCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Email == "" {
		util.Fail(w, "请输入管理员邮箱")
		return
	}
	var username string
	err := db.DB.QueryRow(`SELECT username FROM admin WHERE email=?`, req.Email).Scan(&username)
	if err != nil {
		util.Fail(w, "邮箱未绑定任何管理员")
		return
	}
	if !canSendCode(req.Email) {
		util.Fail(w, "发送过于频繁，请 60 秒后再试")
		return
	}
	if _, err := issueSecureCode(req.Email, req.Email, "SSLVPN 管理密码找回", "安全验证码"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "安全码已发送至邮箱", nil)
}

func CheckCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
		Pass  string `json:"password"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if _, ok := verifySecureCode(req.Email, req.Code, codeDims(r, req.Email)...); !ok {
		util.Fail(w, "安全码无效或已过期；连续错误将被临时锁定")
		return
	}
	if len(req.Pass) < 8 {
		util.Fail(w, "新密码长度至少 8 位")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Pass), bcrypt.DefaultCost)
	if _, err := db.DB.Exec(`UPDATE admin SET password=?, updated_at=datetime('now','localtime') WHERE email=?`, hash, req.Email); err != nil {
		util.Fail(w, "重置失败")
		return
	}
	// 邮箱找回改密同样吊销该管理员全部会话
	var resetID int64
	if db.DB.QueryRow(`SELECT id FROM admin WHERE email=?`, req.Email).Scan(&resetID) == nil {
		middleware.RevokeAdmin(resetID)
	}
	util.OKMsg(w, "密码已重置，请使用新密码登录", nil)
}

func GetCodeByVpnUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "请输入 VPN 用户名")
		return
	}
	var email string
	err := db.DB.QueryRow(`SELECT email FROM account WHERE username=? AND status=1`, req.Username).Scan(&email)
	if err != nil || email == "" {
		util.Fail(w, "用户不存在或未绑定邮箱")
		return
	}
	if !canSendCode(req.Username) {
		util.Fail(w, "发送过于频繁，请 60 秒后再试")
		return
	}
	if _, err := issueSecureCode(req.Username, email, "VPN 密码找回", "安全验证码"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "安全码已发送至绑定邮箱", nil)
}

func FindVpnUserPasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Code     string `json:"code"`
		Pass     string `json:"password"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if _, ok := verifySecureCode(req.Username, req.Code, codeDims(r, req.Username)...); !ok {
		util.Fail(w, "安全码无效或已过期；连续错误将被临时锁定")
		return
	}
	if len(req.Pass) < 6 {
		util.Fail(w, "新密码长度至少 6 位")
		return
	}
	if _, err := db.DB.Exec(`UPDATE account SET password=?, updated_at=datetime('now','localtime') WHERE username=?`,
		req.Pass, req.Username); err != nil {
		util.Fail(w, "重置失败")
		return
	}
	syncAuthFiles()
	util.OKMsg(w, "VPN 密码已重置", nil)
}

func GetRegisterVpnUserCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Email == "" {
		util.Fail(w, "请输入邮箱")
		return
	}
	if db.GetSetting("register_user_status") != "1" {
		util.Fail(w, "系统未开放 VPN 用户自助注册")
		return
	}
	if !canSendCode(req.Email) {
		util.Fail(w, "发送过于频繁，请 60 秒后再试")
		return
	}
	if _, err := issueSecureCode(req.Email, req.Email, "VPN 注册验证码", "注册验证码"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "验证码已发送", nil)
}

func RegisterVpnUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Code     string `json:"code"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if db.GetSetting("register_user_status") != "1" {
		util.Fail(w, "系统未开放注册")
		return
	}
	if _, ok := verifySecureCode(req.Email, req.Code, codeDims(r, req.Email)...); !ok {
		util.Fail(w, "验证码无效或已过期；连续错误将被临时锁定")
		return
	}
	if !validName(req.Username) || len(req.Password) < 6 {
		util.Fail(w, "用户名或密码不符合要求（用户名：字母数字下划线；密码≥6位）")
		return
	}
	var exists int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, req.Username).Scan(&exists)
	if exists > 0 {
		util.Fail(w, "用户名已存在")
		return
	}
	// 自助注册同样受许可用户数上限约束，避免绕过后台限制
	if err := license.CanAddUsers(1); err != nil {
		util.FailCode(w, 403, err.Error())
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,email,status,created_at) VALUES(?,?,?,1,datetime('now','localtime'))`,
		req.Username, req.Password, req.Email); err != nil {
		util.Fail(w, "注册失败")
		return
	}
	license.Invalidate()
	if err := vpn.IssueUserCert(req.Username); err != nil {
		util.OKMsg(w, "注册成功（证书签发失败，请联系管理员重建配置）", nil)
		return
	}
	syncAuthFiles()
	util.OKMsg(w, "注册成功，请使用账号密码连接 VPN", nil)
}

func GetRegisterCode(w http.ResponseWriter, r *http.Request) {
	// 管理员注册码（与 VPN 用户注册同一机制）
	GetRegisterVpnUserCode(w, r)
}

func RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Code     string `json:"code"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if db.GetSetting("register_admin_status") != "1" {
		util.Fail(w, "系统未开放管理员注册")
		return
	}
	if _, ok := verifySecureCode(req.Email, req.Code, codeDims(r, req.Email)...); !ok {
		util.Fail(w, "验证码无效或已过期；连续错误将被临时锁定")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,email,status,created_at) VALUES(?,?,?,1,datetime('now','localtime'))`,
		req.Username, hash, req.Email); err != nil {
		util.Fail(w, "注册失败（用户名可能已存在）")
		return
	}
	util.OKMsg(w, "管理员注册成功", nil)
}

// 允许 '@'：LDAP/AD 支持邮箱形态账号（filter 配成 (mail=%s) 或 (userPrincipalName=%s)）。
// 其余特殊字符仍禁止，避免进入 LDAP filter、证书 CN 与 .ovpn 文件名。
func validName(s string) bool {
	if s == "" || len(s) > 64 { // 上限 64：与 X.509 CN 长度上限一致（证书/SQL 均安全）
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '@') {
			return false
		}
	}
	return true
}

// ---------- 轮询与在线状态 ----------

func PollingTask(w http.ResponseWriter, r *http.Request) {
	// 检查过期用户并禁用
	res, err := db.DB.Exec(`UPDATE account SET status=0 WHERE status=1 AND expire_date != ''
		AND date(expire_date, '+1 day') < date('now')`)
	affected := int64(0)
	if err == nil {
		affected, _ = res.RowsAffected()
	}
	// 同步认证文件与在线状态
	syncAuthFiles()
	util.OK(w, map[string]any{"disabled": affected, "time": db.Now()})
}

func CheckOnlineStatus(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	online := false
	for _, u := range vpn.AllOnlineUsers() {
		if u.Username == username {
			online = true
			break
		}
	}
	util.OK(w, map[string]bool{"online": online})
}

func DownloadCA(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(vpn.PKIDir, "ca.crt"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
	_, _ = w.Write(data)
}

func sha256s(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
