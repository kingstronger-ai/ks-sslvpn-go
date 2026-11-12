// 飞书扫码登录（SSO）：设备码流程 + 一次性 VPN 口令
//
// 整体链路（与既有客户端 KSVPN.ps1 完全兼容，字段名保持一致）：
//
//	POST /api/v1/device/start   客户端发起 → 返回 device_code / device_verifier / auth_url
//	GET  <base>/auth/start      浏览器打开 → 302 到飞书授权页
//	GET  <base>/callback        飞书回跳 → 换 token、取用户信息、映射 LDAP 账号、签发一次性口令
//	POST /api/v1/device/poll    客户端轮询 → 拿到 username + vpn_token
//	POST /api/v1/profile/feishu 客户端凭 device_verifier 下载个人配置（免密）
//	POST /api/v1/profile/account 传统账号密码下载个人配置
//	POST /api/v1/token/verify   旧网关脚本的服务间校验入口（Bearer 共享密钥）
//
// vpn_token 形如 FS1.<base64url>，直接填进 OpenVPN 的「密码」位，
// 由 sslvpn auth-verify 子进程本地核销（见 vpn.ConsumeFeishuToken）。
package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// ---------- 配置 ----------

const (
	defFeishuAuthURL     = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	defFeishuTokenURL    = "https://accounts.feishu.cn/oauth/v3/token"
	defFeishuAppTokenURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
	defFeishuUserInfoURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
	defFeishuScope       = "contact:user.email:readonly"
)

type feishuConfig struct {
	Enabled      bool
	AppID        string
	AppSecret    string
	BaseURL      string // 对外基地址，留空按请求 Host 推导为 https://<host>/feishu-sso
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	AppTokenURL  string
	TokenMode    string // v3 | legacy-v1
	Scope        string
	TenantKey    string
	EmailDomain  string // 允许的邮箱域名，多个用逗号分隔
	VerifySecret string
	MatchAttr    string // 飞书 ID 映射的 LDAP 属性，默认 carLicense
	DeviceTTLSec int
	TokenTTLSec  int
	Mock         bool
}

func feishuCfg() feishuConfig {
	get := func(k, def string) string {
		if v := strings.TrimSpace(db.GetSetting(k)); v != "" {
			return v
		}
		return def
	}
	atoi := func(k string, def int) int {
		if n, err := strconv.Atoi(db.GetSetting(k)); err == nil && n > 0 && n <= 86400 {
			return n
		}
		return def
	}
	return feishuConfig{
		Enabled:      db.GetSetting("feishu_enabled") == "1",
		AppID:        get("feishu_app_id", ""),
		AppSecret:    get("feishu_app_secret", ""),
		BaseURL:      strings.TrimRight(get("feishu_base_url", ""), "/"),
		AuthURL:      get("feishu_auth_url", defFeishuAuthURL),
		TokenURL:     get("feishu_token_url", defFeishuTokenURL),
		UserInfoURL:  get("feishu_userinfo_url", defFeishuUserInfoURL),
		AppTokenURL:  get("feishu_app_token_url", defFeishuAppTokenURL),
		TokenMode:    get("feishu_token_mode", "v3"),
		Scope:        get("feishu_scope", defFeishuScope),
		TenantKey:    get("feishu_tenant_key", ""),
		EmailDomain:  get("feishu_email_domain", ""),
		VerifySecret: get("feishu_verify_secret", ""),
		MatchAttr:    get("feishu_match_attr", "carLicense"),
		DeviceTTLSec: atoi("feishu_device_ttl", 300),
		TokenTTLSec:  atoi("feishu_token_ttl", 60),
		Mock:         db.GetSetting("feishu_mock_mode") == "1",
	}
}

// baseURL 旧版飞书配置入口，统一委托给 ssoDerivedBaseURL，
// 保证「扫码登录」页与 /api/v1/device/start 下发的地址口径一致。
// 「服务器公网地址」允许带端口（如 1.2.3.4:58443），回调会原样保留端口。
func (c feishuConfig) baseURL(r *http.Request) string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return ssoDerivedBaseURL(r)
}

// ---------- 响应 ----------

func ssoJSON(w http.ResponseWriter, status int, body map[string]any) {
	b, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func ssoHTML(w http.ResponseWriter, status int, title, message string, autoClose bool) {
	esc := htmlEscape
	closeJS := ""
	if autoClose {
		closeJS = `<script>setTimeout(function(){window.open("","_self");window.close()},1200)</script>`
	}
	body := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>` + esc(title) + `</title>
<style>
body{font-family:system-ui,"Microsoft YaHei",sans-serif;background:#f2f5fa;color:#2f3542;margin:0;
display:grid;place-items:center;min-height:100vh}
.card{background:#fff;border-radius:16px;padding:38px 40px;max-width:560px;
box-shadow:0 14px 40px rgba(20,30,60,.10)}
h1{color:#2f6bff;font-size:22px;margin:0 0 14px}
p{line-height:1.75;margin:8px 0;color:#4a5261}
.brand{font-size:12px;color:#98a2b3;margin-top:22px}
</style></head><body><main class="card"><h1>` + esc(title) + `</h1><p>` + esc(message) + `</p>
<p>页面将尝试自动关闭；如未关闭，可直接关闭并返回 VPN 客户端。</p>
<div class="brand">` + esc(brandName()) + `</div></main>` + closeJS + `</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// ---------- 限流（进程内按 IP+桶计数）----------

type rateItem struct {
	count   int
	resetAt time.Time
}

var ssoRate = struct {
	sync.Mutex
	m map[string]*rateItem
}{m: map[string]*rateItem{}}

func ssoRateAllow(bucket string, r *http.Request, max int, window time.Duration) bool {
	key := bucket + "|" + ssoClientIP(r)
	now := time.Now()
	l := &ssoRate
	l.Lock()
	defer l.Unlock()
	if len(l.m) > 4096 { // 防内存膨胀
		for k, v := range l.m {
			if now.After(v.resetAt) {
				delete(l.m, k)
			}
		}
	}
	it := l.m[key]
	if it == nil || now.After(it.resetAt) {
		l.m[key] = &rateItem{count: 1, resetAt: now.Add(window)}
		return true
	}
	it.count++
	return it.count <= max
}

func ssoClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return clientIP(r)
}

// ---------- 工具 ----------

// ssoRand 生成 n 字节随机数的 base64url 串（无填充，字符集 A-Za-z0-9-_）
func ssoRand(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// readSSOJSON 读取小体积 JSON（上限 16KB），空体视为 {}
func readSSOJSON(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 16 << 10
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	if err := dec.Decode(dst); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// ssoAccountByUsername 取账号关键字段（不存在返回 nil）
func ssoAccountByUsername(username string) *Account {
	a := &Account{}
	err := db.DB.QueryRow(`SELECT id,username,auth_type,COALESCE(email,''),
		COALESCE(expire_date,''),COALESCE(group_id,0),COALESCE(status,0) FROM account WHERE username=?`, username).
		Scan(&a.ID, &a.Username, &a.AuthType, &a.Email, &a.ExpireDate, &a.GroupID, &a.Status)
	if err != nil {
		return nil
	}
	return a
}

// accountUsable 账号可用于登录（启用且未过期）
func accountUsable(a *Account) (bool, string) {
	if a == nil {
		return false, "该飞书身份未在 VPN 系统中开通账号，请联系管理员"
	}
	if a.Status != 1 {
		return false, "该 VPN 账号已被禁用，请联系管理员"
	}
	if a.ExpireDate != "" {
		if t, err := time.Parse("2006-01-02", a.ExpireDate); err == nil && time.Now().After(t.Add(24*time.Hour)) {
			return false, "该 VPN 账号已过期，请联系管理员续期"
		}
	}
	switch strings.ToLower(strings.TrimSpace(a.AuthType)) {
	case "ldap", "feishu", "sso", "dingtalk", "wecom":
	default:
		return false, "该 VPN 账号未启用扫码登录（需为 LDAP / 扫码类型），请联系管理员"
	}
	return true, ""
}

// ---------- 设备码：发起 ----------

// SSODeviceStart POST /api/v1/device/start
// 请求可用 provider 指定渠道（feishu/dingtalk/wecom），留空则用「默认渠道」。
func SSODeviceStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider         string `json:"provider"`
		ExpectedUsername string `json:"expected_username"`
	}
	_ = readSSOJSON(r, &req, 4096)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = ssoDefaultProvider()
	}
	if provider == "" {
		ssoJSON(w, 403, map[string]any{"ok": false, "error": "扫码登录未启用，请联系管理员"})
		return
	}
	if _, known := ssoProviderNames[provider]; !known || !ssoProviderEnabled(provider) {
		ssoJSON(w, 403, map[string]any{"ok": false, "error": ssoProviderLabel(provider) + "登录未启用，请联系管理员"})
		return
	}
	if !ssoRateAllow("device-start", r, 10, time.Minute) {
		ssoJSON(w, 429, map[string]any{"ok": false, "error": "请求过于频繁，请稍后重试"})
		return
	}
	expected := strings.TrimSpace(req.ExpectedUsername)
	if expected != "" && !validName(expected) {
		ssoJSON(w, 400, map[string]any{"ok": false, "error": "VPN 用户名格式不正确"})
		return
	}

	cfg := feishuCfg()
	deviceCode := ssoRand(24)
	verifier := ssoRand(32)
	state := ssoRand(24)
	if deviceCode == "" || verifier == "" || state == "" {
		ssoJSON(w, 500, map[string]any{"ok": false, "error": "随机数生成失败"})
		return
	}
	now := time.Now()
	expires := now.Add(time.Duration(cfg.DeviceTTLSec) * time.Second)
	if _, err := db.DB.Exec(`INSERT INTO sso_device
		(device_code,provider,verifier_hash,state,status,expected_username,created_ip,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		deviceCode, provider, vpn.TokenDigest(verifier), state, "pending", expected,
		ssoClientIP(r), now.Unix(), expires.Unix()); err != nil {
		ssoJSON(w, 500, map[string]any{"ok": false, "error": "登录请求创建失败"})
		return
	}

	// 授权页是服务端的绝对路径，必须用纯 origin 拼接；回调基地址可能带 /feishu-sso 前缀，
	// 直接拼会变成 /feishu-sso/sso/auth/start（404）。
	authURL := ssoOrigin(r) + "/sso/auth/start?device_code=" + url.QueryEscape(deviceCode)
	resp := map[string]any{
		"ok":                        true,
		"provider":                  provider,
		"device_code":               deviceCode,
		"deviceCode":                deviceCode,
		"user_code":                 strings.ToUpper(deviceCode[:8]),
		"device_verifier":           verifier,
		"deviceVerifier":            verifier,
		"verifier":                  verifier,
		"auth_url":                  authURL,
		"authUrl":                   authURL,
		"verification_uri":          authURL,
		"verification_uri_complete": authURL,
		"expires_in":                cfg.DeviceTTLSec,
		"expiresIn":                 cfg.DeviceTTLSec,
		"interval":                  2,
		"provider_name":             ssoProviderLabel(provider),
	}
	if ssoMockEnabled(provider) {
		resp["test_callback_url"] = ssoOrigin(r) + "/sso/callback?state=" + url.QueryEscape(state)
	}
	ssoJSON(w, 201, resp)
}

// ---------- 设备码：浏览器授权 ----------

// SSOAuthStart GET /sso/auth/start（兼容 /feishu-sso/auth/start、/auth/start）
func SSOAuthStart(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.URL.Query().Get("device_code")
	var provider, state string
	var expires int64
	err := db.DB.QueryRow(`SELECT COALESCE(provider,'feishu'),state,expires_at FROM sso_device WHERE device_code=?`, deviceCode).
		Scan(&provider, &state, &expires)
	if err != nil || time.Now().Unix() > expires || state == "" {
		ssoHTML(w, 400, "登录请求已失效", "请返回 VPN 客户端重新发起扫码登录。", false)
		return
	}
	label := ssoProviderLabel(provider)
	if !ssoProviderEnabled(provider) {
		ssoHTML(w, 403, label+"登录未启用", "请联系管理员在管理后台启用该渠道。", false)
		return
	}
	if ssoMockEnabled(provider) {
		ssoHTML(w, 200, "模拟登录模式", "当前为联调模式，请由测试脚本调用回调接口完成授权。", false)
		return
	}
	callback := ssoBaseURL(r) + "/callback"
	_, _ = db.DB.Exec(`UPDATE sso_device SET callback_url=? WHERE device_code=?`, callback, deviceCode)

	target, err := ssoAuthURL(provider, state, callback)
	if err != nil {
		ssoHTML(w, 500, label+"应用未配置完整", err.Error(), false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// SSOCallback GET /sso/callback（兼容 /feishu-sso/callback、/callback）
func SSOCallback(w http.ResponseWriter, r *http.Request) {
	if !ssoRateAllow("callback", r, 20, time.Minute) {
		ssoHTML(w, 429, "请求过于频繁", "请稍后再试。", false)
		return
	}
	state := r.URL.Query().Get("state")
	var deviceCode, provider, expected, callbackURL, status string
	var expires int64
	err := db.DB.QueryRow(`SELECT device_code,COALESCE(provider,'feishu'),expected_username,callback_url,status,expires_at
		FROM sso_device WHERE state=?`, state).Scan(&deviceCode, &provider, &expected, &callbackURL, &status, &expires)
	if err != nil || time.Now().Unix() > expires || state == "" {
		ssoHTML(w, 400, "登录请求无效", "登录状态校验失败或请求已经过期，请返回客户端重试。", false)
		return
	}
	if status != "pending" {
		ssoHTML(w, 400, "登录请求已处理", "该登录请求已被使用，请返回客户端重新发起。", false)
		return
	}
	label := ssoProviderLabel(provider)

	deny := func(msg string) {
		_, _ = db.DB.Exec(`UPDATE sso_device SET status='denied',error=? WHERE device_code=?`, msg, deviceCode)
		ssoAccessLog(provider+"_denied", "", "", msg, ssoClientIP(r))
		ssoHTML(w, 403, label+"身份验证失败", msg, false)
	}

	ident, ferr := func() (*ssoIdentity, error) {
		if ssoMockEnabled(provider) {
			return ssoMockIdentity(provider, r), nil
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			return nil, fmt.Errorf("%s未返回授权码，可能已取消授权", label)
		}
		return ssoExchange(provider, code, callbackURL)
	}()
	if ferr != nil {
		deny(ferr.Error())
		return
	}
	if ident.Email == "" && ident.Login == "" && ident.UnionID == "" {
		deny("未获取到可用的" + label + "身份信息，请检查应用权限")
		return
	}
	if ident.Email != "" && !emailDomainAllowed(ssoEmailDomain(provider), ident.Email) {
		deny("邮箱域名不在允许范围内（" + ssoEmailDomain(provider) + "）")
		return
	}
	if provider == SSOFeishu {
		if tk := ssoSetting("feishu_tenant_key", ""); tk != "" && ident.TenantKey != "" && ident.TenantKey != tk {
			deny("飞书租户不匹配，请联系管理员")
			return
		}
	}

	username, method, rerr := resolveSSOUsername(provider, ident, expected)
	if rerr != nil {
		deny(rerr.Error())
		return
	}

	cfg := feishuCfg()
	raw := vpn.FeishuTokenPrefix + ssoRand(32)
	now := time.Now()
	if _, err := db.DB.Exec(`INSERT INTO sso_token(token_hash,token_id,username,email,method,consumed,created_at,expires_at)
		VALUES(?,?,?,?,?,0,?,?)`,
		vpn.TokenDigest(raw), vpn.TokenDigest(raw)[:12], username, ident.Email, provider,
		now.Unix(), now.Add(time.Duration(cfg.TokenTTLSec)*time.Second).Unix()); err != nil {
		ssoHTML(w, 500, "签发登录凭证失败", "服务端写入失败，请稍后重试。", false)
		return
	}
	if _, err := db.DB.Exec(`UPDATE sso_device SET status='authorized',username=?,email=?,match_method=?,vpn_plain=?
		WHERE device_code=?`, username, ident.Email, method, raw, deviceCode); err != nil {
		ssoHTML(w, 500, "签发登录凭证失败", "服务端写入失败，请稍后重试。", false)
		return
	}
	ssoAccessLog(provider+"_authorized", username, ident.Email, "match="+method, ssoClientIP(r))
	ssoHTML(w, 200, label+"身份验证成功", "账号 "+username+" 已通过验证，请回到 VPN 客户端继续。", true)
}

// feishuExchangeCode 用授权码换取 user_access_token（兼容 v3 与 legacy-v1 两种模式）
func feishuExchangeCode(cfg feishuConfig, code, redirectURI string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.TokenMode == "legacy-v1" {
		body, _ := json.Marshal(map[string]string{"app_id": cfg.AppID, "app_secret": cfg.AppSecret})
		resp, err := client.Post(cfg.AppTokenURL, "application/json; charset=utf-8", strings.NewReader(string(body)))
		if err != nil {
			return "", fmt.Errorf("飞书应用凭证获取失败：%v", err)
		}
		defer resp.Body.Close()
		var appRes struct {
			Code           int    `json:"code"`
			Msg            string `json:"msg"`
			AppAccessToken string `json:"app_access_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&appRes)
		if resp.StatusCode != 200 || appRes.AppAccessToken == "" {
			return "", fmt.Errorf("飞书应用凭证获取失败：%s", fallbackStr(appRes.Msg, resp.Status))
		}
		payload, _ := json.Marshal(map[string]string{"grant_type": "authorization_code", "code": code})
		req, _ := http.NewRequest(http.MethodPost, cfg.TokenURL, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+appRes.AppAccessToken)
		r2, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("飞书换取登录凭证失败：%v", err)
		}
		defer r2.Body.Close()
		var tok struct {
			Code        int    `json:"code"`
			Msg         string `json:"msg"`
			AccessToken string `json:"access_token"`
			Data        struct {
				AccessToken string `json:"access_token"`
			} `json:"data"`
		}
		_ = json.NewDecoder(r2.Body).Decode(&tok)
		t := fallbackStr(tok.Data.AccessToken, tok.AccessToken)
		if r2.StatusCode != 200 || t == "" {
			return "", fmt.Errorf("飞书换取登录凭证失败：%s", fallbackStr(tok.Msg, r2.Status))
		}
		return t, nil
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	req, _ := http.NewRequest(http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	cred := base64.StdEncoding.EncodeToString([]byte(cfg.AppID + ":" + cfg.AppSecret))
	req.Header.Set("Authorization", "Basic "+cred)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("飞书换取登录凭证失败：%v", err)
	}
	defer resp.Body.Close()
	var tok struct {
		Code             int    `json:"code"`
		Msg              string `json:"msg"`
		ErrorDescription string `json:"error_description"`
		AccessToken      string `json:"access_token"`
		Data             struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	t := fallbackStr(tok.Data.AccessToken, tok.AccessToken)
	if resp.StatusCode != 200 || t == "" {
		return "", fmt.Errorf("飞书换取登录凭证失败：%s", fallbackStr(tok.ErrorDescription, fallbackStr(tok.Msg, resp.Status)))
	}
	return t, nil
}

// feishuUserInfo 拉取用户信息
func feishuUserInfo(cfg feishuConfig, accessToken string) (map[string]any, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, cfg.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("飞书用户信息获取失败：%v", err)
	}
	defer resp.Body.Close()
	var raw struct {
		Code int            `json:"code"`
		Msg  string         `json:"msg"`
		Data map[string]any `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	if resp.StatusCode != 200 || (raw.Code != 0 && raw.Code != 200) || raw.Data == nil {
		return nil, fmt.Errorf("飞书用户信息获取失败：%s", fallbackStr(raw.Msg, resp.Status))
	}
	return raw.Data, nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func fallbackStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// resolveSSOUsername 渠道身份 → VPN 账号
//
// 匹配顺序（命中即返回）：
//  1. 渠道直接给出的账号名（企业微信 userid、联调 mock_login）
//  2. 本地扫码类账号按邮箱直配（auth_type=feishu/sso/dingtalk/wecom/ldap）
//  3. LDAP：按渠道 ID（unionId/openId/userid，兼容 feishu_ 等前缀）匹配 carLicense 等属性
//  4. LDAP：按 mail 匹配
//
// 命中后统一校验：用户名合法、账号存在、启用、未过期、认证类型允许扫码、与 expected_username 一致。
func resolveSSOUsername(provider string, ident *ssoIdentity, expected string) (string, string, error) {
	label := ssoProviderLabel(provider)

	accept := func(username, method string) (string, string, error) {
		if !validName(username) {
			return "", "", fmt.Errorf("%s账号名格式不受支持（%s）", label, username)
		}
		if expected != "" && !strings.EqualFold(expected, username) {
			return "", "", fmt.Errorf("%s身份与 VPN 配置的用户名不一致", label)
		}
		if ok, reason := accountUsable(ssoAccountByUsername(username)); !ok {
			return "", "", fmt.Errorf("%s", reason)
		}
		return username, method, nil
	}

	// 1) 渠道直给账号名
	if login := strings.TrimSpace(ident.Login); login != "" && validName(login) {
		if a := ssoAccountByUsername(login); a != nil {
			return accept(login, "login")
		}
	}
	// 2) 本地账号按邮箱直配
	if ident.Email != "" {
		if u := ssoAccountByEmail(ident.Email); u != "" {
			return accept(u, "email_local")
		}
	}

	// 3) / 4) LDAP 反查
	client, err := ldapConnect()
	if err != nil {
		return "", "", fmt.Errorf("%s身份未绑定 VPN 账号，且系统未配置 LDAP，请联系管理员", label)
	}
	defer client.Close()

	attr := strings.TrimSpace(ssoMatchAttr(provider))
	values := ident.identityValues()
	if attr != "" && len(values) > 0 {
		clauses := make([]string, 0, len(values))
		for _, v := range values {
			clauses = append(clauses, "("+attr+"="+ldapEscape(v)+")")
		}
		recs, serr := client.SearchFilter("(|"+strings.Join(clauses, "")+")", "uid", "cn")
		if serr == nil && len(recs) > 1 {
			return "", "", fmt.Errorf("%s身份关联到多个 LDAP 账号，已拒绝登录", label)
		}
		if serr == nil && len(recs) == 1 {
			return accept(ldapRecordName(recs[0]), provider+"_id")
		}
	}
	if ident.Email != "" {
		recs, serr := client.SearchFilter("(mail="+ldapEscape(ident.Email)+")", "uid", "cn")
		if serr != nil {
			return "", "", fmt.Errorf("LDAP 查询失败：%v", serr)
		}
		if len(recs) > 1 {
			return "", "", fmt.Errorf("邮箱匹配到多个 LDAP 账号，已拒绝登录")
		}
		if len(recs) == 1 {
			return accept(ldapRecordName(recs[0]), "email")
		}
	}
	return "", "", fmt.Errorf("LDAP 中找不到与该%s身份绑定的账号，请联系管理员", label)
}

func ldapRecordName(rec LdapRecord) string {
	if v := rec.Attrs["uid"]; v != "" {
		return v
	}
	return rec.Attrs["cn"]
}

// ssoAccountByEmail 按邮箱找可用于扫码登录的本地账号
func ssoAccountByEmail(email string) string {
	var name string
	err := db.DB.QueryRow(`SELECT username FROM account
		WHERE lower(email)=? AND lower(auth_type) IN ('feishu','sso','dingtalk','wecom','ldap') AND status=1
		ORDER BY id LIMIT 1`, strings.ToLower(strings.TrimSpace(email))).Scan(&name)
	if err != nil {
		return ""
	}
	return name
}

// ldapEscape 按 RFC4515 转义过滤器中的特殊字符
func ldapEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0:
			b.WriteString(`\00`)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ---------- 设备码：轮询 ----------

// SSODevicePoll POST /api/v1/device/poll
func SSODevicePoll(w http.ResponseWriter, r *http.Request) {
	if !ssoRateAllow("device-poll", r, 120, time.Minute) {
		ssoJSON(w, 429, map[string]any{"ok": false, "error": "请求过于频繁，请稍后重试"})
		return
	}
	var req struct {
		DeviceCode     string `json:"device_code"`
		DeviceVerifier string `json:"device_verifier"`
	}
	if err := readSSOJSON(r, &req, 4096); err != nil {
		ssoJSON(w, 400, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	var verifierHash, status, username, errMsg, plain string
	var expires int64
	err := db.DB.QueryRow(`SELECT verifier_hash,status,username,error,COALESCE(vpn_plain,''),expires_at
		FROM sso_device WHERE device_code=?`, req.DeviceCode).
		Scan(&verifierHash, &status, &username, &errMsg, &plain, &expires)
	if err == sql.ErrNoRows || (err == nil && time.Now().Unix() > expires && status == "pending") {
		ssoJSON(w, 410, map[string]any{"ok": false, "status": "expired", "state": "expired", "error": "登录请求已过期"})
		return
	}
	if err != nil {
		ssoJSON(w, 410, map[string]any{"ok": false, "status": "expired", "error": "登录请求无效"})
		return
	}
	if !vpn.SafeEqual(verifierHash, vpn.TokenDigest(req.DeviceVerifier)) {
		ssoJSON(w, 403, map[string]any{"ok": false, "error": "设备校验失败"})
		return
	}
	switch status {
	case "pending":
		ssoJSON(w, 202, map[string]any{"ok": true, "status": "pending", "state": "pending"})
		return
	case "denied":
		ssoJSON(w, 403, map[string]any{"ok": false, "status": "denied", "state": "denied", "error": fallbackStr(errMsg, "飞书身份验证被拒绝")})
		return
	case "delivered":
		ssoJSON(w, 410, map[string]any{"ok": false, "status": "consumed", "state": "consumed", "error": "登录凭证已经领取"})
		return
	}
	// authorized：一次性交出用户名与口令，随后立即清空明文
	if _, err := db.DB.Exec(`UPDATE sso_device SET status='delivered',vpn_plain='' WHERE device_code=? AND status='authorized'`,
		req.DeviceCode); err != nil {
		ssoJSON(w, 500, map[string]any{"ok": false, "error": "服务内部错误"})
		return
	}
	cfg := feishuCfg()
	ssoJSON(w, 200, map[string]any{
		"ok":           true,
		"status":       "authorized",
		"state":        "authorized",
		"username":     username,
		"user":         username,
		"account":      username,
		"vpn_token":    plain,
		"token":        plain,
		"access_token": plain,
		"password":     plain,
		"expires_in":   cfg.TokenTTLSec,
	})
}

// ---------- 个人配置下载 ----------

// SSOProfile POST /api/v1/profile/feishu（凭 device_verifier 免密下载）
func SSOProfile(w http.ResponseWriter, r *http.Request) {
	if !ssoRateAllow("profile-feishu", r, 10, time.Minute) {
		ssoJSON(w, 429, map[string]any{"ok": false, "error": "请求过于频繁，请稍后重试"})
		return
	}
	var req struct {
		DeviceCode     string `json:"device_code"`
		DeviceVerifier string `json:"device_verifier"`
	}
	if err := readSSOJSON(r, &req, 4096); err != nil {
		ssoJSON(w, 400, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	var verifierHash, status, username string
	var profileSent int
	var expires int64
	err := db.DB.QueryRow(`SELECT verifier_hash,status,username,profile_sent,expires_at
		FROM sso_device WHERE device_code=?`, req.DeviceCode).
		Scan(&verifierHash, &status, &username, &profileSent, &expires)
	if err != nil || time.Now().Unix() > expires {
		ssoJSON(w, 410, map[string]any{"ok": false, "error": "登录请求已过期"})
		return
	}
	if !vpn.SafeEqual(verifierHash, vpn.TokenDigest(req.DeviceVerifier)) {
		ssoJSON(w, 403, map[string]any{"ok": false, "error": "设备校验失败"})
		return
	}
	if (status != "authorized" && status != "delivered") || username == "" {
		ssoJSON(w, 403, map[string]any{"ok": false, "error": "飞书身份尚未验证"})
		return
	}
	if profileSent == 1 {
		ssoJSON(w, 410, map[string]any{"ok": false, "error": "个人配置已经领取"})
		return
	}
	_, _ = db.DB.Exec(`UPDATE sso_device SET profile_sent=1 WHERE device_code=?`, req.DeviceCode)
	writeProfileArchive(w, username)
}

// LDAPProfile POST /api/v1/profile/account（账号密码下载，兼容原网关行为）
//
// 兼容两代客户端的请求字段：旧客户端（Windows v0.4.3 / macOS 源码版）发送
// {"username","password"}；v0.4.6 起 macOS 客户端发送 {"username","secret"}。
// TOTP 账号支持 "password,动态码" 逗号追加格式（与 OpenVPN auth-verify 一致）。
func LDAPProfile(w http.ResponseWriter, r *http.Request) {
	if !ssoRateAllow("profile-account", r, 5, time.Minute) {
		ssoJSON(w, 429, map[string]any{"ok": false, "error": "请求过于频繁，请稍后重试"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Secret   string `json:"secret"` // v0.4.6+ macOS 客户端字段名
	}
	if err := readSSOJSON(r, &req, 4096); err != nil {
		ssoJSON(w, 400, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	pass := req.Password
	if pass == "" {
		pass = req.Secret
	}
	loginName := strings.TrimSpace(req.Username)
	if !validName(loginName) || pass == "" {
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
		return
	}
	// 默认只允许短账号；管理员开启后，邮箱 / UPN(DN) 别名解析成真实 VPN 用户名。
	// 解析后用真实用户名查账号、绑定 LDAP、签发配置，保证与 auth-verify 一致，
	// LDAP 搜索过滤器也无需改动（仍用 (uid=%s)）。
	username, ok := vpn.ResolveLoginName(db.DB, loginName)
	if !ok {
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
		return
	}
	a := ssoAccountByUsername(username)
	if a == nil || a.Status != 1 {
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
		return
	}
	switch strings.ToLower(a.AuthType) {
	case "ldap":
		client, err := ldapConnect()
		if err != nil {
			ssoJSON(w, 404, map[string]any{"ok": false, "error": "LDAP 未配置"})
			return
		}
		err = client.BindCheck(username, pass)
		client.Close()
		if err != nil {
			ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
			return
		}
	case "local", "totp":
		// ssoAccountByUsername 不查密码列（避免密码扩散到各调用方），
		// 这里单独取真实密码 / TOTP 密钥后再比对。
		var hash, totpSecret string
		if err := db.DB.QueryRow(`SELECT COALESCE(password,''),COALESCE(totp_secret,'')
			FROM account WHERE username=?`, username).Scan(&hash, &totpSecret); err != nil || hash == "" || hash == "-" {
			ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
			return
		}
		if strings.ToLower(a.AuthType) == "totp" {
			// 密码格式：password 或 password,TOTP
			passPart, otp := pass, ""
			if i := strings.LastIndex(pass, ","); i > 0 {
				passPart, otp = pass[:i], pass[i+1:]
			}
			if hash != passPart || !util.VerifyTOTP(totpSecret, otp) {
				ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或动态码错误"})
				return
			}
		} else if hash != pass {
			ssoJSON(w, 401, map[string]any{"ok": false, "error": "VPN 账号或密码错误"})
			return
		}
	default:
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "该账号不支持密码登录"})
		return
	}
	writeProfileArchive(w, username)
}

// writeProfileArchive 输出 <用户名>_<实例>.tgz（内含 .ovpn）
func writeProfileArchive(w http.ResponseWriter, username string) {
	a := ssoAccountByUsername(username)
	if a == nil {
		ssoJSON(w, 404, map[string]any{"ok": false, "error": "个人 VPN 配置不存在"})
		return
	}
	name, data := buildUserCfgTgz(a)
	if len(data) == 0 {
		ssoJSON(w, 404, map[string]any{"ok": false, "error": "个人 VPN 配置生成失败，请联系管理员"})
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

// ---------- 服务间校验（兼容旧网关脚本）----------

// SSOTokenVerify POST /api/v1/token/verify
// 需要 Authorization: Bearer <feishu_verify_secret>，密钥至少 32 字节。
func SSOTokenVerify(w http.ResponseWriter, r *http.Request) {
	cfg := feishuCfg()
	auth := r.Header.Get("Authorization")
	if len(cfg.VerifySecret) < 32 || !strings.HasPrefix(auth, "Bearer ") ||
		!vpn.SafeEqual(strings.TrimPrefix(auth, "Bearer "), cfg.VerifySecret) {
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "服务认证失败"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Token    string `json:"token"`
		ClientIP string `json:"client_ip"`
	}
	if err := readSSOJSON(r, &req, 4096); err != nil {
		ssoJSON(w, 400, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	if ok, reason := vpn.ConsumeFeishuToken(db.DB, req.Username, req.Token); !ok {
		ssoAccessLog("vpn_token_rejected", req.Username, "", reason+" ip="+req.ClientIP, ssoClientIP(r))
		ssoJSON(w, 401, map[string]any{"ok": false, "error": "一次性令牌无效或已过期"})
		return
	}
	ssoAccessLog("vpn_token_accepted", req.Username, "", "via=http ip="+req.ClientIP, ssoClientIP(r))
	ssoJSON(w, 200, map[string]any{"ok": true, "username": req.Username})
}

// SSOHealthz GET /healthz
func SSOHealthz(w http.ResponseWriter, r *http.Request) {
	cfg := feishuCfg()
	ssoJSON(w, 200, map[string]any{
		"ok": true, "service": "ks-sslvpn-go", "version": "1.0.0",
		"providers": ssoEnabledProviders(), "default_provider": ssoDefaultProvider(),
		"feishu_enabled": cfg.Enabled, "mock": len(ssoEnabledProviders()) > 0 && ssoMockEnabled(ssoDefaultProvider()),
	})
}

// ssoAccessLog 写入认证日志（与 OpenVPN 认证日志同一目录，便于统一审计）
func ssoAccessLog(event, username, email, detail, ip string) {
	msg := event
	if username != "" {
		msg += " 用户名=" + username
	}
	if email != "" {
		msg += " 邮箱=" + email
	}
	if detail != "" {
		msg += " " + detail
	}
	vpn.AppendAccessLog("扫码登录", msg, ip)
}

// ---------- 管理接口 ----------

// ssoProviderReq 管理页提交的单个渠道配置
type ssoProviderReq struct {
	Key         string `json:"key"`
	Enabled     int    `json:"enabled"`
	Mock        int    `json:"mock"`
	EmailDomain string `json:"email_domain"`
	MatchAttr   string `json:"match_attr"`
	AppID       string `json:"app_id"`     // 飞书 AppID / 钉钉 AppKey / 企微 CorpID
	AgentID     string `json:"agent_id"`   // 企微 AgentId
	Secret      string `json:"secret"`     // 留空表示不修改
	TenantKey   string `json:"tenant_key"` // 飞书
	Scope       string `json:"scope"`      // 飞书
	TokenMode   string `json:"token_mode"` // 飞书 v3 / legacy-v1
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	UserInfoURL string `json:"userinfo_url"`
	AppTokenURL string `json:"app_token_url"`
	APIBase     string `json:"api_base"` // 企微 API 根地址
}

// SSOCfgGet GET /api/v1/system/getFeishu　（一次返回全部扫码渠道）
func SSOCfgGet(w http.ResponseWriter, r *http.Request) {
	cfg := feishuCfg()
	providers := []map[string]any{
		{
			"key": SSOFeishu, "name": "飞书",
			"enabled": boolInt(ssoProviderEnabled(SSOFeishu)), "mock": boolInt(ssoMockEnabled(SSOFeishu)),
			"app_id": cfg.AppID, "secret_set": cfg.AppSecret != "",
			"tenant_key": cfg.TenantKey, "scope": cfg.Scope, "token_mode": cfg.TokenMode,
			"auth_url": cfg.AuthURL, "token_url": cfg.TokenURL,
			"userinfo_url": cfg.UserInfoURL, "app_token_url": cfg.AppTokenURL,
			"email_domain": ssoEmailDomain(SSOFeishu), "match_attr": ssoMatchAttr(SSOFeishu),
		},
		{
			"key": SSODingTalk, "name": "钉钉",
			"enabled": boolInt(ssoProviderEnabled(SSODingTalk)), "mock": boolInt(ssoMockEnabled(SSODingTalk)),
			"app_id": db.GetSetting("dingtalk_client_id"), "secret_set": db.GetSetting("dingtalk_client_secret") != "",
			"scope":        ssoSetting("dingtalk_scope", "openid"),
			"auth_url":     ssoSetting("dingtalk_auth_url", "https://login.dingtalk.com/oauth2/auth"),
			"token_url":    ssoSetting("dingtalk_token_url", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"),
			"userinfo_url": ssoSetting("dingtalk_userinfo_url", "https://api.dingtalk.com/v1.0/contact/users/me"),
			"email_domain": ssoEmailDomain(SSODingTalk), "match_attr": ssoMatchAttr(SSODingTalk),
		},
		{
			"key": SSOWeCom, "name": "企业微信",
			"enabled": boolInt(ssoProviderEnabled(SSOWeCom)), "mock": boolInt(ssoMockEnabled(SSOWeCom)),
			"app_id": db.GetSetting("wecom_corp_id"), "agent_id": db.GetSetting("wecom_agent_id"),
			"secret_set":   db.GetSetting("wecom_corp_secret") != "",
			"auth_url":     ssoSetting("wecom_auth_url", "https://login.work.weixin.qq.com/wwlogin/sso/login"),
			"api_base":     ssoSetting("wecom_api_base", "https://qyapi.weixin.qq.com"),
			"email_domain": ssoEmailDomain(SSOWeCom), "match_attr": ssoMatchAttr(SSOWeCom),
		},
	}
	util.OK(w, map[string]any{
		"base_url":            ssoBaseURL(r),
		"base_url_configured": ssoConfiguredBase(),
		"base_url_derived":    ssoDerivedBaseURL(r),
		"origin":              ssoOrigin(r),
		"public_host":         strings.TrimSpace(db.GetSetting("public_host")),
		"default_provider":    ssoDefaultProvider(),
		"device_ttl":          cfg.DeviceTTLSec,
		"token_ttl":           cfg.TokenTTLSec,
		"match_attr":          cfg.MatchAttr,
		"verify_secret_set":   len(cfg.VerifySecret) >= 32,
		"mock_all":            db.GetSetting("sso_mock_mode") == "1",
		"enabled_count":       len(ssoEnabledProviders()),
		"providers":           providers,
	})
}

// SSOCfgSave POST /api/v1/system/updateFeishu
func SSOCfgSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL      string           `json:"base_url"`
		DefaultProv  string           `json:"default_provider"`
		DeviceTTL    int              `json:"device_ttl"`
		TokenTTL     int              `json:"token_ttl"`
		VerifySecret string           `json:"verify_secret"`
		MockAll      int              `json:"mock_all"`
		Providers    []ssoProviderReq `json:"providers"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if req.DeviceTTL <= 0 || req.DeviceTTL > 1800 {
		req.DeviceTTL = 300
	}
	if req.TokenTTL <= 0 || req.TokenTTL > 600 {
		req.TokenTTL = 60
	}
	set := func(k, v string) { db.SetSetting(k, strings.TrimSpace(v)) }
	// 回调基地址留空 = 跟随「全局设置 → 服务器公网地址」（域名、端口一起联动）。
	// 旧版本会把自动推导值回填进输入框，用户一点「保存全部」就被写死；这里把
	// 「与当前推导值相同」视为未修改，避免再次固化，让历史配置自动恢复联动。
	base := strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if base != "" && !strings.Contains(base, "://") {
		base = "https://" + base
	}
	if strings.EqualFold(base, ssoDerivedBaseURL(r)) {
		base = ""
	}
	set("sso_base_url", base)
	if base == "" {
		set("feishu_base_url", "") // 兼容字段一并清掉，否则仍会盖住联动值
	}
	if _, ok := ssoProviderNames[req.DefaultProv]; ok {
		set("sso_default_provider", req.DefaultProv)
	}
	set("feishu_device_ttl", strconv.Itoa(req.DeviceTTL))
	set("feishu_token_ttl", strconv.Itoa(req.TokenTTL))
	db.SetSetting("sso_mock_mode", strconv.Itoa(boolInt(req.MockAll == 1)))
	if strings.TrimSpace(req.VerifySecret) != "" {
		if len(req.VerifySecret) < 32 {
			util.Fail(w, "服务校验密钥至少 32 位字符")
			return
		}
		set("feishu_verify_secret", req.VerifySecret)
	}

	for _, p := range req.Providers {
		if _, ok := ssoProviderNames[p.Key]; !ok {
			continue
		}
		db.SetSetting(p.Key+"_enabled", strconv.Itoa(boolInt(p.Enabled == 1)))
		db.SetSetting(p.Key+"_mock_mode", strconv.Itoa(boolInt(p.Mock == 1)))
		set(p.Key+"_email_domain", strings.Trim(strings.ToLower(p.EmailDomain), ", "))
		attr := strings.TrimSpace(p.MatchAttr)
		if attr == "" {
			attr = "carLicense"
		}
		set(p.Key+"_match_attr", attr)

		switch p.Key {
		case SSOFeishu:
			set("feishu_app_id", p.AppID)
			if strings.TrimSpace(p.Secret) != "" {
				set("feishu_app_secret", p.Secret)
			}
			set("feishu_tenant_key", p.TenantKey)
			set("feishu_scope", p.Scope)
			if p.TokenMode == "legacy-v1" {
				set("feishu_token_mode", "legacy-v1")
			} else {
				set("feishu_token_mode", "v3")
			}
			set("feishu_auth_url", fallbackStr(strings.TrimSpace(p.AuthURL), defFeishuAuthURL))
			set("feishu_token_url", fallbackStr(strings.TrimSpace(p.TokenURL), defFeishuTokenURL))
			set("feishu_userinfo_url", fallbackStr(strings.TrimSpace(p.UserInfoURL), defFeishuUserInfoURL))
			set("feishu_app_token_url", fallbackStr(strings.TrimSpace(p.AppTokenURL), defFeishuAppTokenURL))
		case SSODingTalk:
			set("dingtalk_client_id", p.AppID)
			if strings.TrimSpace(p.Secret) != "" {
				set("dingtalk_client_secret", p.Secret)
			}
			set("dingtalk_scope", fallbackStr(strings.TrimSpace(p.Scope), "openid"))
			if v := strings.TrimSpace(p.AuthURL); v != "" {
				set("dingtalk_auth_url", v)
			}
			if v := strings.TrimSpace(p.TokenURL); v != "" {
				set("dingtalk_token_url", v)
			}
			if v := strings.TrimSpace(p.UserInfoURL); v != "" {
				set("dingtalk_userinfo_url", v)
			}
		case SSOWeCom:
			set("wecom_corp_id", p.AppID)
			set("wecom_agent_id", p.AgentID)
			if strings.TrimSpace(p.Secret) != "" {
				set("wecom_corp_secret", p.Secret)
			}
			if v := strings.TrimSpace(p.AuthURL); v != "" {
				set("wecom_auth_url", v)
			}
			if v := strings.TrimSpace(p.APIBase); v != "" {
				set("wecom_api_base", strings.TrimRight(v, "/"))
			}
			wecomCache.Lock()
			wecomCache.token, wecomCache.expire = "", time.Time{}
			wecomCache.Unlock()
		}
	}
	db.Syslog("admin", "更新扫码登录配置", "default="+ssoDefaultProvider()+" enabled="+fmt.Sprint(ssoEnabledProviders()), clientIP(r))
	util.OKMsg(w, "扫码登录配置已保存，立即生效", map[string]any{"enabled": ssoEnabledProviders()})
}

// SSOTest POST /api/v1/system/testFeishu　（body 可带 provider，默认飞书）
func SSOTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
	}
	_ = readSSOJSON(r, &req, 1024)
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		provider = SSOFeishu
	}
	if _, ok := ssoProviderNames[provider]; !ok {
		util.Fail(w, "未知的登录渠道")
		return
	}
	if ssoMockEnabled(provider) {
		util.OKMsg(w, "当前为联调模式，未调用"+ssoProviderLabel(provider)+"接口", map[string]any{"mock": true})
		return
	}
	msg, err := ssoTestProvider(provider)
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	util.OKMsg(w, msg+"，可以开始扫码登录", nil)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
