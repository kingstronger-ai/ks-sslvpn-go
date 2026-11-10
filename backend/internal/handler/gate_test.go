package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/license"
)

// TestGateFeatureBlockedInCommunity 无正式许可（试用 / 社区档）时，
// 专业版与企业版功能必须被拦截，返回 {code:403} + 升级提示。
// 注：本项目 API 约定为 HTTP 200 + 应用层 {code,msg}，code!=1 即失败。
func TestGateFeatureBlockedInCommunity(t *testing.T) {
	license.Invalidate() // 清缓存，确保读取当前（无许可）状态
	for _, key := range []string{
		license.FeatDomainRoute, license.FeatSSO, license.FeatCCD,
		license.FeatLDAP, license.FeatClientDownload,
		license.FeatMultiInstance, license.FeatACMERenew,
	} {
		w := httptest.NewRecorder()
		if gateFeature(w, key) {
			t.Fatalf("%s: 社区档不应放行", key)
		}
		var resp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: 响应不是合法 JSON: %v", key, err)
		}
		if resp.Code == 1 {
			t.Fatalf("%s: 社区档不应返回成功码", key)
		}
		if !strings.Contains(resp.Msg, "授权") {
			t.Fatalf("%s: 提示应包含授权升级说明，实际: %s", key, resp.Msg)
		}
	}
}

// TestGateFeatureUnregisteredAllowed 未登记的功能键（全档位可用）必须放行。
func TestGateFeatureUnregisteredAllowed(t *testing.T) {
	license.Invalidate()
	w := httptest.NewRecorder()
	if !gateFeature(w, "not_a_registered_feature") {
		t.Fatalf("未登记功能应放行，实际被拦截: %s", w.Body.String())
	}
}
