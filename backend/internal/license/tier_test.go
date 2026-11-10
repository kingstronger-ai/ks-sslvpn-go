package license

import (
	"testing"
)

// TestTierDerivation 校验版本标识 → 档位推导（含历史值 standard 的兼容处理）。
func TestTierDerivation(t *testing.T) {
	cases := []struct {
		edition string
		want    string
	}{
		{"", TierCommunity},
		{"community", TierCommunity},
		{"standard", TierCommunity}, // 旧默认版式，按社区版处理
		{"unknown", TierCommunity},
		{"pro", TierPro},
		{"PRO", TierPro},
		{"p", TierPro},
		{"enterprise", TierEnterprise},
		{"ent", TierEnterprise},
		{" Enterprise ", TierEnterprise},
	}
	for _, c := range cases {
		got := Payload{Edition: c.edition}.Tier()
		if got != c.want {
			t.Errorf("Edition=%q Tier()=%q, want %q", c.edition, got, c.want)
		}
	}
}

// TestTierFeatures 校验三档默认功能开闭：社区版不含高级功能，
// 专业版含 Pro 组但不含企业组，企业版全开。
func TestTierFeatures(t *testing.T) {
	proOnly := []string{FeatDomainRoute, FeatSSO, FeatCCD, FeatLDAP, FeatClientDownload}
	entOnly := []string{FeatMultiInstance, FeatPrivateIssuance, FeatACMERenew}
	all := append(append([]string{}, proOnly...), entOnly...)

	community := Payload{Edition: "community"}
	for _, k := range all {
		if community.HasFeature(k) {
			t.Errorf("community 不应包含 %s", k)
		}
	}

	pro := Payload{Edition: "pro"}
	for _, k := range proOnly {
		if !pro.HasFeature(k) {
			t.Errorf("pro 应包含 %s", k)
		}
	}
	for _, k := range entOnly {
		if pro.HasFeature(k) {
			t.Errorf("pro 不应包含 %s", k)
		}
	}

	ent := Payload{Edition: "enterprise"}
	for _, k := range all {
		if !ent.HasFeature(k) {
			t.Errorf("enterprise 应包含 %s", k)
		}
	}
	if len(ent.EnabledFeatures()) != len(featureTier) {
		t.Errorf("enterprise 开启功能数=%d, want %d", len(ent.EnabledFeatures()), len(featureTier))
	}
	if len(community.EnabledFeatures()) != 0 {
		t.Errorf("community 开启功能应为空, got %v", community.EnabledFeatures())
	}
}

// TestExplicitFeatures 校验显式功能清单优先级：给出 ft 后按清单精确开闭，
// 即使档位较高也不会自动放开未列出的功能。
func TestExplicitFeatures(t *testing.T) {
	p := Payload{Edition: "enterprise", Features: []string{FeatDomainRoute, "ACME_AUTO_RENEW"}}
	if !p.HasFeature(FeatDomainRoute) {
		t.Error("显式清单应开启 domain_route")
	}
	if !p.HasFeature(FeatACMERenew) { // 大小写不敏感
		t.Error("显式清单应大小写不敏感地开启 acme_auto_renew")
	}
	if p.HasFeature(FeatSSO) {
		t.Error("显式清单未列出的功能不应自动开启")
	}
	if p.HasFeature(FeatMultiInstance) {
		t.Error("显式清单未列出的企业功能不应自动开启")
	}
	// 未登记的功能键在任何档位都默认可用
	if !p.HasFeature("some_core_feature") || !(Payload{}).HasFeature("some_core_feature") {
		t.Error("未登记功能应默认全档位可用")
	}
}

// TestRequiredTier 校验功能 → 最低档位映射，供 gateFeature 生成升级提示。
func TestRequiredTier(t *testing.T) {
	for _, k := range []string{FeatDomainRoute, FeatSSO, FeatCCD, FeatLDAP, FeatClientDownload} {
		if RequiredTier(k) != TierPro {
			t.Errorf("%s 应归属 pro, got %q", k, RequiredTier(k))
		}
	}
	for _, k := range []string{FeatMultiInstance, FeatPrivateIssuance, FeatACMERenew} {
		if RequiredTier(k) != TierEnterprise {
			t.Errorf("%s 应归属 enterprise, got %q", k, RequiredTier(k))
		}
	}
	if RequiredTier("unregistered") != "" {
		t.Error("未登记功能不应有最低档位限制")
	}
}
