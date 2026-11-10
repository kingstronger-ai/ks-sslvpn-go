package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

func ssoBaseReq(host, method string, body any) *http.Request {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, "/api/v1/system/getFeishu", strings.NewReader(string(b)))
	} else {
		r = httptest.NewRequest(method, "/api/v1/system/getFeishu", nil)
	}
	r.Host = host
	return r
}

func resetSSOBase(t *testing.T) {
	t.Helper()
	keys := []string{"public_host", "sso_base_url", "feishu_base_url"}
	old := map[string]string{}
	for _, k := range keys {
		old[k] = db.GetSetting(k)
		db.SetSetting(k, "")
	}
	t.Cleanup(func() {
		for _, k := range keys {
			db.SetSetting(k, old[k])
		}
	})
}

func ssoCfgDoc(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	SSOCfgGet(w, r)
	out := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v / %s", err, w.Body.String())
	}
	d, _ := out["data"].(map[string]any)
	if d == nil {
		t.Fatalf("响应缺少 data: %s", w.Body.String())
	}
	return d
}

// 全局公网地址（含端口）变更后，回调基地址 / origin 立即联动；
// 未写端口且访问的是同一主机名时自动补当前端口；不同主机名不擅自补端口。
func TestSSOBaseURLFollowsPublicHostWithPort(t *testing.T) {
	resetSSOBase(t)
	r := ssoBaseReq("vpn.example.com:58443", "GET", nil)

	db.SetSetting("public_host", "https://vpn.example.com")
	if got, want := ssoOrigin(r), "https://vpn.example.com:58443"; got != want {
		t.Fatalf("origin 未自动补端口: got %q want %q", got, want)
	}
	if got, want := ssoBaseURL(r), "https://vpn.example.com:58443/feishu-sso"; got != want {
		t.Fatalf("回调基地址: got %q want %q", got, want)
	}
	if got := ssoOrigin(r) + "/sso/auth/start"; strings.Contains(got, "/feishu-sso/") {
		t.Fatalf("授权地址不应重复拼接 /feishu-sso: %s", got)
	}

	db.SetSetting("public_host", "https://vpn2.example.cn:6443")
	if got, want := ssoBaseURL(r), "https://vpn2.example.cn:6443/feishu-sso"; got != want {
		t.Fatalf("改域名+端口后未联动: got %q want %q", got, want)
	}
	if got, want := ssoOrigin(r), "https://vpn2.example.cn:6443"; got != want {
		t.Fatalf("改域名+端口后 origin 未联动: got %q want %q", got, want)
	}

	db.SetSetting("public_host", "https://other.example.cn")
	if got, want := ssoBaseURL(r), "https://other.example.cn/feishu-sso"; got != want {
		t.Fatalf("不同主机名不应补访问端口: got %q want %q", got, want)
	}
}

// 显式填写回调基地址时，以管理员填写的为准，不再随全局变化
func TestSSOBaseURLExplicitOverride(t *testing.T) {
	resetSSOBase(t)
	db.SetSetting("public_host", "https://vpn.example.com")
	db.SetSetting("sso_base_url", "https://sso.example.com/feishu-sso")
	r := ssoBaseReq("vpn.example.com:58443", "GET", nil)

	if got, want := ssoBaseURL(r), "https://sso.example.com/feishu-sso"; got != want {
		t.Fatalf("显式基地址: got %q want %q", got, want)
	}
	if got, want := ssoOrigin(r), "https://sso.example.com"; got != want {
		t.Fatalf("显式基地址的 origin 应去掉路径: got %q want %q", got, want)
	}
	db.SetSetting("public_host", "https://changed.example.cn:9443")
	if got, want := ssoBaseURL(r), "https://sso.example.com/feishu-sso"; got != want {
		t.Fatalf("显式基地址不应随全局变化: got %q want %q", got, want)
	}
}

// getFeishu 同时返回「生效值 / 显式配置值 / 推导值」，前端才能把输入框留空
func TestSSOCfgGetReportsConfiguredAndDerived(t *testing.T) {
	resetSSOBase(t)
	db.SetSetting("public_host", "https://vpn.example.com")
	r := ssoBaseReq("vpn.example.com:58443", "GET", nil)
	d := ssoCfgDoc(t, r)

	if d["base_url_configured"] != "" {
		t.Fatalf("未显式配置时 base_url_configured 应为空: %v", d["base_url_configured"])
	}
	if got, want := d["base_url"], "https://vpn.example.com:58443/feishu-sso"; got != want {
		t.Fatalf("base_url: got %v want %q", got, want)
	}
	if d["base_url_derived"] != d["base_url"] {
		t.Fatalf("跟随全局时 derived 应等于生效值: %v vs %v", d["base_url_derived"], d["base_url"])
	}
	if d["origin"] != "https://vpn.example.com:58443" {
		t.Fatalf("origin: %v", d["origin"])
	}
}

// 历史版本会把自动推导值回填进输入框，用户一点保存就被固化。
// 保存与推导值相同的地址应视为「留空跟随」，并清掉兼容字段。
func TestSSOCfgSaveKeepsFollowMode(t *testing.T) {
	resetSSOBase(t)
	db.SetSetting("public_host", "https://vpn.example.com")
	r := ssoBaseReq("vpn.example.com:58443", "GET", nil)
	derived := ssoDerivedBaseURL(r)
	db.SetSetting("sso_base_url", derived)
	db.SetSetting("feishu_base_url", derived)

	body := map[string]any{
		"base_url": derived, "default_provider": "feishu",
		"device_ttl": 300, "token_ttl": 60, "verify_secret": "",
		"mock_all": 0, "providers": []any{},
	}
	w := httptest.NewRecorder()
	SSOCfgSave(w, ssoBaseReq("vpn.example.com:58443", "POST", body))
	if got := db.GetSetting("sso_base_url"); got != "" {
		t.Fatalf("与推导值相同不应固化: %q", got)
	}
	if got := db.GetSetting("feishu_base_url"); got != "" {
		t.Fatalf("兼容字段应一并清除: %q", got)
	}

	// 改全局公网地址，飞书 / 钉钉 / 企业微信共用的回调地址随之变化
	db.SetSetting("public_host", "https://new.example.cn:7443")
	d := ssoCfgDoc(t, r)
	if got, want := d["base_url"], "https://new.example.cn:7443/feishu-sso"; got != want {
		t.Fatalf("保存后应恢复联动: got %v want %q", got, want)
	}
}
