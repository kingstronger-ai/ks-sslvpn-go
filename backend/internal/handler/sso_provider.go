// 扫码登录渠道抽象：飞书 / 钉钉 / 企业微信
//
// 三种渠道的差别只在两件事——「授权页 URL」与「用 code 换身份」，
// 设备码、一次性口令、账号映射、配置下发全部共用（见 sso_feishu.go）。
package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
)

// SSO 渠道标识
const (
	SSOFeishu   = "feishu"
	SSODingTalk = "dingtalk"
	SSOWeCom    = "wecom"
)

var ssoProviderNames = map[string]string{
	SSOFeishu:   "飞书",
	SSODingTalk: "钉钉",
	SSOWeCom:    "企业微信",
}

func ssoProviderLabel(key string) string {
	if n, ok := ssoProviderNames[key]; ok {
		return n
	}
	return "扫码"
}

// ssoSetting 读取渠道配置（空值回落默认）
func ssoSetting(key, def string) string {
	if v := strings.TrimSpace(db.GetSetting(key)); v != "" {
		return v
	}
	return def
}

// ssoEnabledProviders 已启用的渠道（按固定顺序）
func ssoEnabledProviders() []string {
	var out []string
	for _, k := range []string{SSOFeishu, SSODingTalk, SSOWeCom} {
		if db.GetSetting(k+"_enabled") == "1" {
			out = append(out, k)
		}
	}
	return out
}

// ssoProviderEnabled 渠道是否启用
func ssoProviderEnabled(key string) bool {
	return db.GetSetting(key+"_enabled") == "1"
}

// ssoDefaultProvider 客户端未指定渠道时用哪个：
// 优先「默认渠道」设置，其次第一个已启用的渠道。
func ssoDefaultProvider() string {
	if p := db.GetSetting("sso_default_provider"); ssoProviderEnabled(p) {
		return p
	}
	if list := ssoEnabledProviders(); len(list) > 0 {
		return list[0]
	}
	return ""
}

// ssoEmailDomain 渠道的邮箱域名白名单（未单独设置时用全局 sso_email_domain）
func ssoEmailDomain(provider string) string {
	if v := db.GetSetting(provider + "_email_domain"); v != "" {
		return v
	}
	return db.GetSetting("sso_email_domain")
}

// ssoMatchAttr 渠道的飞书/钉钉 ID 映射属性（默认 carLicense）
func ssoMatchAttr(provider string) string {
	if v := db.GetSetting(provider + "_match_attr"); v != "" {
		return v
	}
	return ssoSetting("sso_match_attr", "carLicense")
}

func emailDomainAllowed(domainList, email string) bool {
	if strings.TrimSpace(domainList) == "" {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range strings.Split(domainList, ",") {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
		if d != "" && d == domain {
			return true
		}
	}
	return false
}

// ssoMockEnabled 联调模式：不调用任何第三方接口，用回调 query 里的 mock_* 伪造身份
func ssoMockEnabled(provider string) bool {
	if db.GetSetting("sso_mock_mode") == "1" {
		return true
	}
	if provider == SSOFeishu && db.GetSetting("feishu_mock_mode") == "1" {
		return true
	}
	return db.GetSetting(provider+"_mock_mode") == "1"
}

// ---------- 回调基地址 ----------
//
// 飞书 / 钉钉 / 企业微信共用同一份基地址，优先级：
//   1. 管理员在「扫码登录 → 回调基地址」显式填写的 sso_base_url（兼容旧 feishu_base_url）
//   2. 全局设置 → 服务器公网地址 public_host
//   3. 当前访问管理页的 Host
// 未显式填写时，改全局公网地址（含端口）后，页面显示的回调地址、下发的授权地址
// 会自动跟着变，不需要重新保存扫码登录页。

// ssoConfiguredBase 管理员显式保存的基地址；空 = 跟随全局公网地址。
func ssoConfiguredBase() string {
	for _, k := range []string{"sso_base_url", "feishu_base_url"} {
		v := strings.TrimRight(strings.TrimSpace(db.GetSetting(k)), "/")
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "https://" + v
		}
		return v
	}
	return ""
}

// ssoHostPart 取 URL / host 里的主机名（不含端口、路径）
func ssoHostPart(h string) string {
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ":") {
		return h[:i]
	}
	return h
}

// ssoPortPart 取 host:port 里的端口（无端口返回空）
func ssoPortPart(h string) string {
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		i := strings.Index(h, "]")
		if i > 0 && i+1 < len(h) && h[i+1] == ':' {
			return h[i+2:]
		}
		return ""
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ":") {
		return h[i+1:]
	}
	return ""
}

// ssoOriginOf 把任意基地址归一化为纯 origin（scheme://host[:port]）
func ssoOriginOf(v string) string {
	scheme, rest := "https", v
	if i := strings.Index(v, "://"); i >= 0 {
		if v[:i] == "http" {
			scheme = "http"
		}
		rest = v[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		rest = "localhost"
	}
	return scheme + "://" + rest
}

// ssoDerivedOrigin 忽略显式配置，只按「全局公网地址 / 当前访问 Host」推导 origin。
// 公网地址没写端口、而管理页又是通过同一主机名的带端口地址访问时，自动补上该端口，
// 避免回调地址丢端口后第三方平台回调到 443。
func ssoDerivedOrigin(r *http.Request) string {
	fallback := func() string {
		if r != nil && r.Host != "" {
			return "https://" + r.Host
		}
		return "https://localhost"
	}
	ph := strings.TrimSpace(db.GetSetting("public_host"))
	if ph == "" {
		return fallback()
	}
	if i := strings.Index(ph, "://"); i >= 0 {
		ph = ph[i+3:]
	}
	if i := strings.IndexAny(ph, "/?#"); i >= 0 {
		ph = ph[:i]
	}
	ph = strings.TrimRight(ph, "/")
	if ph == "" {
		return fallback()
	}
	if ssoPortPart(ph) == "" && r != nil && r.Host != "" &&
		strings.EqualFold(ssoHostPart(ph), ssoHostPart(r.Host)) {
		if p := ssoPortPart(r.Host); p != "" {
			ph += ":" + p
		}
	}
	return "https://" + ph
}

// ssoDerivedBaseURL 跟随全局时的默认回调基地址。保留 /feishu-sso 前缀以兼容
// 已经在飞书 / 钉钉 / 企业微信后台登记过的 redirect_uri（该路径是 /callback 的别名）。
func ssoDerivedBaseURL(r *http.Request) string {
	return ssoDerivedOrigin(r) + "/feishu-sso"
}

// ssoOrigin 实际生效的 origin，用于拼接 /sso/auth/start、/sso/callback
func ssoOrigin(r *http.Request) string {
	if v := ssoConfiguredBase(); v != "" {
		return ssoOriginOf(v)
	}
	return ssoDerivedOrigin(r)
}

// ssoBaseURL 回调基地址：显式配置优先，否则跟随全局公网地址（含端口）
func ssoBaseURL(r *http.Request) string {
	if v := ssoConfiguredBase(); v != "" {
		return v
	}
	return ssoDerivedBaseURL(r)
}

// ssoIdentity 各渠道归一化后的身份信息
type ssoIdentity struct {
	Provider  string
	UnionID   string // 飞书 union_id / 钉钉 unionId / 企微 userid
	OpenID    string // 飞书 open_id / 钉钉 openId
	UserID    string // 飞书 user_id / 企微 userid
	Email     string
	Mobile    string
	Name      string
	TenantKey string // 飞书 tenant_key / 钉钉 corpId
	Login     string // 可直接当作 VPN 账号名的候选（企微 userid）
}

// identityValues 用于在 LDAP 中按属性反查的 ID 集合（含 feishu_ 前缀的历史写法）
func (id *ssoIdentity) identityValues() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range []string{id.UnionID, id.OpenID, id.UserID} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		for _, cand := range []string{v, "feishu_" + v, "dingtalk_" + v, "wecom_" + v} {
			if !seen[cand] {
				seen[cand] = true
				out = append(out, cand)
			}
		}
	}
	return out
}

// ---------- 授权地址 ----------

// ssoAuthURL 生成渠道授权页地址
func ssoAuthURL(provider, state, callback string) (string, error) {
	switch provider {
	case SSOFeishu:
		appID := ssoSetting("feishu_app_id", "")
		if appID == "" {
			return "", fmt.Errorf("飞书 App ID 未配置")
		}
		raw := ssoSetting("feishu_auth_url", defFeishuAuthURL)
		target, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("飞书授权地址配置错误")
		}
		q := target.Query()
		q.Set("app_id", appID)
		q.Set("redirect_uri", callback)
		q.Set("state", state)
		q.Set("response_type", "code")
		if scope := ssoSetting("feishu_scope", defFeishuScope); scope != "" {
			q.Set("scope", scope)
		}
		target.RawQuery = q.Encode()
		return target.String(), nil

	case SSODingTalk:
		clientID := ssoSetting("dingtalk_client_id", "")
		if clientID == "" {
			return "", fmt.Errorf("钉钉 AppKey（Client ID）未配置")
		}
		raw := ssoSetting("dingtalk_auth_url", "https://login.dingtalk.com/oauth2/auth")
		target, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("钉钉授权地址配置错误")
		}
		q := target.Query()
		q.Set("redirect_uri", callback)
		q.Set("response_type", "code")
		q.Set("client_id", clientID)
		q.Set("scope", ssoSetting("dingtalk_scope", "openid"))
		q.Set("state", state)
		q.Set("prompt", "consent")
		target.RawQuery = q.Encode()
		return target.String(), nil

	case SSOWeCom:
		corpID := ssoSetting("wecom_corp_id", "")
		agentID := ssoSetting("wecom_agent_id", "")
		if corpID == "" || agentID == "" {
			return "", fmt.Errorf("企业微信 CorpID 或 AgentId 未配置")
		}
		raw := ssoSetting("wecom_auth_url", "https://login.work.weixin.qq.com/wwlogin/sso/login")
		target, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("企业微信授权地址配置错误")
		}
		q := target.Query()
		q.Set("login_type", "CorpApp")
		q.Set("appid", corpID)
		q.Set("agentid", agentID)
		q.Set("redirect_uri", callback)
		q.Set("state", state)
		target.RawQuery = q.Encode()
		return target.String(), nil
	}
	return "", fmt.Errorf("未知的登录渠道")
}

// ---------- code 换身份 ----------

// ssoExchange 用授权码换回归一化身份
func ssoExchange(provider, code, callback string) (*ssoIdentity, error) {
	switch provider {
	case SSOFeishu:
		token, err := feishuExchangeCode(feishuCfg(), code, callback)
		if err != nil {
			return nil, err
		}
		u, err := feishuUserInfo(feishuCfg(), token)
		if err != nil {
			return nil, err
		}
		return &ssoIdentity{
			Provider:  SSOFeishu,
			UnionID:   firstString(u, "union_id"),
			OpenID:    firstString(u, "open_id"),
			UserID:    firstString(u, "user_id"),
			Email:     strings.ToLower(firstString(u, "enterprise_email", "email")),
			Mobile:    firstString(u, "mobile"),
			Name:      firstString(u, "name", "en_name"),
			TenantKey: firstString(u, "tenant_key"),
		}, nil

	case SSODingTalk:
		return dingtalkExchange(code, callback)

	case SSOWeCom:
		return wecomExchange(code)
	}
	return nil, fmt.Errorf("未知的登录渠道")
}

// dingtalkExchange 钉钉：code → userAccessToken → contact/users/me
func dingtalkExchange(code, callback string) (*ssoIdentity, error) {
	clientID := ssoSetting("dingtalk_client_id", "")
	clientSecret := ssoSetting("dingtalk_client_secret", "")
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("钉钉 AppKey / AppSecret 未配置")
	}
	tokenURL := ssoSetting("dingtalk_token_url", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
	payload, _ := json.Marshal(map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"code":         code,
		"grantType":    "authorization_code",
	})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(tokenURL, "application/json; charset=utf-8", strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("钉钉换取登录凭证失败：%v", err)
	}
	defer resp.Body.Close()
	var tok struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		AccessToken string `json:"accessToken"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		return nil, fmt.Errorf("钉钉换取登录凭证失败：%s", fallbackStr(tok.Message, fallbackStr(tok.Code, resp.Status)))
	}

	infoURL := ssoSetting("dingtalk_userinfo_url", "https://api.dingtalk.com/v1.0/contact/users/me")
	req, _ := http.NewRequest(http.MethodGet, infoURL, nil)
	req.Header.Set("x-acs-dingtalk-access-token", tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp2, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("钉钉用户信息获取失败：%v", err)
	}
	defer resp2.Body.Close()
	var me struct {
		Nick      string `json:"nick"`
		UnionID   string `json:"unionId"`
		OpenID    string `json:"openId"`
		Email     string `json:"email"`
		Mobile    string `json:"mobile"`
		StateCode string `json:"stateCode"`
		Message   string `json:"message"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&me)
	if resp2.StatusCode != 200 || (me.UnionID == "" && me.OpenID == "") {
		return nil, fmt.Errorf("钉钉用户信息获取失败：%s", fallbackStr(me.Message, resp2.Status))
	}
	return &ssoIdentity{
		Provider: SSODingTalk,
		UnionID:  me.UnionID,
		OpenID:   me.OpenID,
		Email:    strings.ToLower(strings.TrimSpace(me.Email)),
		Mobile:   me.Mobile,
		Name:     me.Nick,
	}, nil
}

// wecomAccessToken 企业微信 access_token（带内存缓存，官方有效期 7200s）
var wecomCache struct {
	sync.Mutex
	token  string
	expire time.Time
}

func wecomAccessToken() (string, error) {
	corpID := ssoSetting("wecom_corp_id", "")
	secret := ssoSetting("wecom_corp_secret", "")
	if corpID == "" || secret == "" {
		return "", fmt.Errorf("企业微信 CorpID / Secret 未配置")
	}
	wecomCache.Lock()
	defer wecomCache.Unlock()
	if wecomCache.token != "" && time.Now().Before(wecomCache.expire) {
		return wecomCache.token, nil
	}
	api := strings.TrimRight(ssoSetting("wecom_api_base", "https://qyapi.weixin.qq.com"), "/")
	u := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", api, url.QueryEscape(corpID), url.QueryEscape(secret))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return "", fmt.Errorf("企业微信获取 access_token 失败：%v", err)
	}
	defer resp.Body.Close()
	var res struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res.ErrCode != 0 || res.AccessToken == "" {
		return "", fmt.Errorf("企业微信获取 access_token 失败：%s(%d)", res.ErrMsg, res.ErrCode)
	}
	ttl := res.ExpiresIn
	if ttl <= 60 {
		ttl = 7200
	}
	wecomCache.token = res.AccessToken
	wecomCache.expire = time.Now().Add(time.Duration(ttl-120) * time.Second)
	return wecomCache.token, nil
}

// wecomExchange 企业微信：code → userid（+ user_ticket 取详情）
func wecomExchange(code string) (*ssoIdentity, error) {
	token, err := wecomAccessToken()
	if err != nil {
		return nil, err
	}
	api := strings.TrimRight(ssoSetting("wecom_api_base", "https://qyapi.weixin.qq.com"), "/")
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(fmt.Sprintf("%s/cgi-bin/auth/getuserinfo?access_token=%s&code=%s",
		api, url.QueryEscape(token), url.QueryEscape(code)))
	if err != nil {
		return nil, fmt.Errorf("企业微信换取身份失败：%v", err)
	}
	defer resp.Body.Close()
	var res struct {
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
		UserID     string `json:"userid"`
		OpenID     string `json:"openid"`
		UserTicket string `json:"user_ticket"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res.ErrCode != 0 || (res.UserID == "" && res.OpenID == "") {
		return nil, fmt.Errorf("企业微信换取身份失败：%s(%d)", res.ErrMsg, res.ErrCode)
	}
	if res.UserID == "" {
		return nil, fmt.Errorf("该企业微信账号不属于本企业，无法登录（请从企业微信工作台进入）")
	}
	id := &ssoIdentity{Provider: SSOWeCom, UnionID: res.UserID, UserID: res.UserID, Login: res.UserID}

	// 有 user_ticket 时补全邮箱/手机号（需「通讯录」读取权限，失败不影响登录）
	if res.UserTicket != "" {
		body, _ := json.Marshal(map[string]string{"user_ticket": res.UserTicket})
		dresp, derr := client.Post(fmt.Sprintf("%s/cgi-bin/auth/getuserdetail?access_token=%s", api, url.QueryEscape(token)),
			"application/json; charset=utf-8", strings.NewReader(string(body)))
		if derr == nil {
			defer dresp.Body.Close()
			var d struct {
				ErrCode int    `json:"errcode"`
				UserID  string `json:"userid"`
				Mobile  string `json:"mobile"`
				Email   string `json:"email"`
				BizMail string `json:"biz_mail"`
			}
			if json.NewDecoder(dresp.Body).Decode(&d) == nil && d.ErrCode == 0 {
				id.Email = strings.ToLower(fallbackStr(d.BizMail, d.Email))
				id.Mobile = d.Mobile
			}
		}
	}
	return id, nil
}

// ssoMockIdentity 联调模式下的身份（不调用任何第三方接口）
func ssoMockIdentity(provider string, r *http.Request) *ssoIdentity {
	return &ssoIdentity{
		Provider:  provider,
		UnionID:   r.URL.Query().Get("mock_union_id"),
		OpenID:    r.URL.Query().Get("mock_open_id"),
		UserID:    r.URL.Query().Get("mock_user_id"),
		Email:     strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mock_email"))),
		Mobile:    r.URL.Query().Get("mock_mobile"),
		TenantKey: r.URL.Query().Get("mock_tenant"),
		Login:     r.URL.Query().Get("mock_login"),
	}
}

// ---------- 管理接口辅助 ----------

// ssoTestProvider 校验渠道凭证是否可用（管理页「测试」按钮）
func ssoTestProvider(provider string) (string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	switch provider {
	case SSOFeishu:
		appID, secret := db.GetSetting("feishu_app_id"), db.GetSetting("feishu_app_secret")
		if appID == "" || secret == "" {
			return "", fmt.Errorf("请先填写并保存 App ID / App Secret")
		}
		body, _ := json.Marshal(map[string]string{"app_id": appID, "app_secret": secret})
		resp, err := client.Post(ssoSetting("feishu_app_token_url", defFeishuAppTokenURL),
			"application/json; charset=utf-8", strings.NewReader(string(body)))
		if err != nil {
			return "", fmt.Errorf("连接飞书失败：%v", err)
		}
		defer resp.Body.Close()
		var res struct {
			Code           int    `json:"code"`
			Msg            string `json:"msg"`
			AppAccessToken string `json:"app_access_token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if resp.StatusCode != 200 || res.AppAccessToken == "" {
			return "", fmt.Errorf("飞书应用凭证校验失败：%s", fallbackStr(res.Msg, resp.Status))
		}
		return "飞书应用凭证有效", nil

	case SSODingTalk:
		clientID := db.GetSetting("dingtalk_client_id")
		if clientID == "" || db.GetSetting("dingtalk_client_secret") == "" {
			return "", fmt.Errorf("请先填写并保存 AppKey / AppSecret")
		}
		// 用 client_credentials 之外最轻量的方式：取企业 accessToken 校验凭证
		body, _ := json.Marshal(map[string]string{"appKey": clientID, "appSecret": db.GetSetting("dingtalk_client_secret")})
		resp, err := client.Post("https://api.dingtalk.com/v1.0/oauth2/accessToken",
			"application/json; charset=utf-8", strings.NewReader(string(body)))
		if err != nil {
			return "", fmt.Errorf("连接钉钉失败：%v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var res struct {
			Code        int    `json:"code"`
			Message     string `json:"message"`
			AccessToken string `json:"accessToken"`
		}
		_ = json.Unmarshal(raw, &res)
		if resp.StatusCode != 200 || res.AccessToken == "" {
			return "", fmt.Errorf("钉钉应用凭证校验失败：%s", fallbackStr(res.Message, resp.Status))
		}
		return "钉钉应用凭证有效", nil

	case SSOWeCom:
		if _, err := wecomAccessToken(); err != nil {
			return "", err
		}
		return "企业微信 access_token 获取成功", nil
	}
	return "", fmt.Errorf("未知的登录渠道")
}

// ssoProviderSummary 管理页展示用：各渠道启用状态
func ssoProviderSummary() []map[string]any {
	var out []map[string]any
	for _, k := range []string{SSOFeishu, SSODingTalk, SSOWeCom} {
		out = append(out, map[string]any{
			"key":     k,
			"name":    ssoProviderLabel(k),
			"enabled": ssoProviderEnabled(k),
			"domain":  ssoEmailDomain(k),
		})
	}
	return out
}
