package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"sslvpn/internal/db"
	"sslvpn/internal/vpn"
)

// TestMain 统一建库：db.Open 是进程级单例，测试结束再关库删目录
// （Windows 上数据库句柄未关闭会导致 TempDir 清理失败）
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sslvpn-handler-test")
	if err != nil {
		panic(err)
	}
	if err := db.Open(dir); err != nil {
		panic(err)
	}
	code := m.Run()
	if db.DB != nil {
		_ = db.DB.Close()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// setupSSO 准备一个启用「联调模式」的飞书环境（不真的调用飞书接口）
func setupSSO(t *testing.T) {
	t.Helper()
	db.SetSetting("feishu_enabled", "1")
	db.SetSetting("feishu_mock_mode", "1")
	db.SetSetting("feishu_email_domain", "example.com")
	db.SetSetting("feishu_verify_secret", strings.Repeat("k", 40))
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO account(username,password,auth_type,email,group_id,status)
		VALUES('zhangsan','-','feishu','zs@example.com',0,1)`); err != nil {
		t.Fatal(err)
	}
}

func doJSON(t *testing.T, h http.HandlerFunc, method, target string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, strings.NewReader(string(b)))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	h(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// 完整走一遍：发起 → 飞书回调（模拟）→ 轮询取口令 → 口令一次性核销
func TestFeishuDeviceFlowAndToken(t *testing.T) {
	setupSSO(t)

	w, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{})
	if w.Code != 201 || start["ok"] != true {
		t.Fatalf("device/start 失败: %d %s", w.Code, w.Body.String())
	}
	deviceCode, _ := start["device_code"].(string)
	verifier, _ := start["device_verifier"].(string)
	authURL, _ := start["auth_url"].(string)
	if deviceCode == "" || verifier == "" || !strings.Contains(authURL, "/auth/start?device_code=") {
		t.Fatalf("返回字段不完整: %v", start)
	}
	// 别名兼容（客户端可能读驼峰）
	if start["deviceCode"] != deviceCode || start["authUrl"] != authURL {
		t.Errorf("驼峰别名缺失: %v", start)
	}

	// 待授权时轮询应返回 202 pending
	w, poll := doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": verifier})
	if w.Code != 202 || poll["status"] != "pending" {
		t.Fatalf("轮询应为 pending: %d %s", w.Code, w.Body.String())
	}

	// 取 state 并模拟飞书回调
	var state string
	if err := db.DB.QueryRow(`SELECT state FROM sso_device WHERE device_code=?`, deviceCode).Scan(&state); err != nil {
		t.Fatal(err)
	}
	cb := "/sso/callback?state=" + url.QueryEscape(state) + "&mock_email=zs%40example.com"
	wc, _ := doJSON(t, SSOCallback, "GET", cb, nil)
	if wc.Code != 200 {
		t.Fatalf("回调应成功: %d %s", wc.Code, wc.Body.String())
	}

	// 轮询取口令
	w, poll = doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": verifier})
	if w.Code != 200 || poll["status"] != "authorized" {
		t.Fatalf("轮询应 authorized: %d %s", w.Code, w.Body.String())
	}
	username, _ := poll["username"].(string)
	token, _ := poll["vpn_token"].(string)
	if username != "zhangsan" || !strings.HasPrefix(token, vpn.FeishuTokenPrefix) {
		t.Fatalf("账号或口令异常: %v", poll)
	}

	// 口令只能消费一次
	if ok, reason := vpn.ConsumeFeishuToken(db.DB, "zhangsan", token); !ok {
		t.Fatalf("首次核销应通过，实际: %s", reason)
	}
	if ok, _ := vpn.ConsumeFeishuToken(db.DB, "zhangsan", token); ok {
		t.Fatal("重放同一口令必须被拒绝")
	}

	// 已领取后再次轮询 → 410 consumed
	w, poll = doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": verifier})
	if w.Code != 410 || poll["status"] != "consumed" {
		t.Fatalf("应返回 consumed: %d %s", w.Code, w.Body.String())
	}
}

// 设备校验值错误必须拒绝，且不能泄露口令
func TestFeishuPollRejectsWrongVerifier(t *testing.T) {
	setupSSO(t)
	_, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{})
	deviceCode, _ := start["device_code"].(string)
	w, out := doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": "wrong-verifier"})
	if w.Code != 403 {
		t.Fatalf("错误 verifier 应 403，实际 %d %s", w.Code, w.Body.String())
	}
	if _, has := out["vpn_token"]; has {
		t.Fatal("拒绝时不应返回口令")
	}
}

// 未启用飞书登录时直接 403
func TestSSODeviceStartDisabled(t *testing.T) {
	setupSSO(t)
	db.SetSetting("feishu_enabled", "0")
	defer db.SetSetting("feishu_enabled", "1")
	w, out := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{})
	if w.Code != 403 || out["ok"] != false {
		t.Fatalf("未启用应 403: %d %s", w.Code, w.Body.String())
	}
}

// 服务间校验接口：Bearer 密钥 + 一次性口令
func TestSSOTokenVerifyAPI(t *testing.T) {
	setupSSO(t)
	_, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{})
	deviceCode, _ := start["device_code"].(string)
	verifier, _ := start["device_verifier"].(string)
	var state string
	_ = db.DB.QueryRow(`SELECT state FROM sso_device WHERE device_code=?`, deviceCode).Scan(&state)
	doJSON(t, SSOCallback, "GET", "/sso/callback?state="+url.QueryEscape(state)+"&mock_email=zs%40example.com", nil)
	_, poll := doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": verifier})
	token, _ := poll["vpn_token"].(string)

	call := func(secret string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/v1/token/verify", strings.NewReader(string(b)))
		if secret != "" {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		w := httptest.NewRecorder()
		SSOTokenVerify(w, r)
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}

	if w, _ := call("", map[string]any{"username": "zhangsan", "token": token}); w.Code != 401 {
		t.Errorf("无密钥应 401，实际 %d", w.Code)
	}
	if w, _ := call(strings.Repeat("k", 40), map[string]any{"username": "zhangsan", "token": token}); w.Code != 200 {
		t.Errorf("正确密钥应 200，实际 %d %s", w.Code, w.Body.String())
	}
	if w, _ := call(strings.Repeat("k", 40), map[string]any{"username": "zhangsan", "token": token}); w.Code != 401 {
		t.Errorf("口令重放应 401，实际 %d", w.Code)
	}
}

// 邮箱域名白名单与账号状态都要拦截
func TestSSOCallbackDomainAndAccountChecks(t *testing.T) {
	setupSSO(t)
	run := func(mail string) int {
		_, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{})
		deviceCode, _ := start["device_code"].(string)
		var state string
		_ = db.DB.QueryRow(`SELECT state FROM sso_device WHERE device_code=?`, deviceCode).Scan(&state)
		w, _ := doJSON(t, SSOCallback, "GET",
			"/sso/callback?state="+url.QueryEscape(state)+"&mock_email="+url.QueryEscape(mail), nil)
		return w.Code
	}
	if code := run("zs@other.com"); code != 403 {
		t.Errorf("域名不在白名单应 403，实际 %d", code)
	}
	if code := run("nobody@example.com"); code != 403 {
		t.Errorf("无对应账号应 403，实际 %d", code)
	}
	_, _ = db.DB.Exec(`UPDATE account SET status=0 WHERE username='zhangsan'`)
	if code := run("zs@example.com"); code != 403 {
		t.Errorf("账号禁用应 403，实际 %d", code)
	}
	_, _ = db.DB.Exec(`UPDATE account SET status=1 WHERE username='zhangsan'`)
	if code := run("zs@example.com"); code != 200 {
		t.Errorf("正常账号应 200，实际 %d", code)
	}
}

// 多渠道：provider 选择、未启用渠道拒绝、企业微信 userid 直配账号
func TestSSOProviderRouting(t *testing.T) {
	setupSSO(t)
	db.SetSetting("dingtalk_enabled", "1")
	db.SetSetting("dingtalk_mock_mode", "1")
	db.SetSetting("wecom_enabled", "0")
	defer func() {
		db.SetSetting("dingtalk_enabled", "0")
		db.SetSetting("dingtalk_mock_mode", "0")
	}()

	// 未启用的渠道必须 403
	w, out := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{"provider": "wecom"})
	if w.Code != 403 {
		t.Fatalf("未启用渠道应 403，实际 %d %s", w.Code, w.Body.String())
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "企业微信") {
		t.Errorf("错误信息应指明渠道，实际 %q", msg)
	}

	// 钉钉渠道：发起 → 回调（mock_login 直配账号）→ 轮询
	w, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{"provider": "dingtalk"})
	if w.Code != 201 || start["provider"] != "dingtalk" {
		t.Fatalf("钉钉 device/start 失败: %d %s", w.Code, w.Body.String())
	}
	if u, _ := start["auth_url"].(string); !strings.Contains(u, "/sso/auth/start") {
		t.Errorf("auth_url 应指向通用落地页，实际 %q", u)
	}
	deviceCode, _ := start["device_code"].(string)
	verifier, _ := start["device_verifier"].(string)
	var state string
	if err := db.DB.QueryRow(`SELECT state FROM sso_device WHERE device_code=?`, deviceCode).Scan(&state); err != nil {
		t.Fatal(err)
	}
	// 渠道里没有邮箱，靠 userid 直配：走 mock_login
	wc, body := doJSON(t, SSOCallback, "GET",
		"/sso/callback?state="+url.QueryEscape(state)+"&mock_login=zhangsan", nil)
	if wc.Code != 200 {
		t.Fatalf("钉钉回调应成功: %d %s", wc.Code, body)
	}
	_, poll := doJSON(t, SSODevicePoll, "POST", "/api/v1/device/poll",
		map[string]any{"device_code": deviceCode, "device_verifier": verifier})
	if poll["status"] != "authorized" || poll["username"] != "zhangsan" {
		t.Fatalf("钉钉轮询结果异常: %v", poll)
	}
	if tok, _ := poll["vpn_token"].(string); !strings.HasPrefix(tok, vpn.FeishuTokenPrefix) {
		t.Errorf("一次性口令格式异常: %q", tok)
	}
	// 令牌 method 应记录渠道
	var method string
	_ = db.DB.QueryRow(`SELECT method FROM sso_token WHERE username='zhangsan' ORDER BY rowid DESC LIMIT 1`).Scan(&method)
	if method != "dingtalk" {
		t.Errorf("token method 应为 dingtalk，实际 %q", method)
	}
}

// 全局联调开关对所有渠道生效
func TestSSOMockAllProviders(t *testing.T) {
	setupSSO(t)
	db.SetSetting("sso_mock_mode", "1")
	defer db.SetSetting("sso_mock_mode", "0")
	db.SetSetting("feishu_mock_mode", "0")
	db.SetSetting("wecom_enabled", "1")
	db.SetSetting("wecom_mock_mode", "0")
	defer db.SetSetting("wecom_enabled", "0")

	w, start := doJSON(t, SSODeviceStart, "POST", "/api/v1/device/start", map[string]any{"provider": "wecom"})
	if w.Code != 201 {
		t.Fatalf("企业微信应可发起: %d %s", w.Code, w.Body.String())
	}
	deviceCode, _ := start["device_code"].(string)
	var state string
	_ = db.DB.QueryRow(`SELECT state FROM sso_device WHERE device_code=?`, deviceCode).Scan(&state)
	if wc, _ := doJSON(t, SSOCallback, "GET", "/sso/callback?state="+url.QueryEscape(state)+"&mock_login=zhangsan", nil); wc.Code != 200 {
		t.Fatalf("全局联调模式应跳过第三方调用: %d", wc.Code)
	}
}
