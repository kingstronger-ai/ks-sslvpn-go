package handler

import (
	"net/http"

	"sslvpn/internal/license"
	"sslvpn/internal/util"
)

// featureLabel 功能键对应的中文展示名（用于升级提示文案）
var featureLabel = map[string]string{
	license.FeatDomainRoute:     "域名分流",
	license.FeatSSO:             "三渠道扫码登录",
	license.FeatCCD:             "CCD 高级配置",
	license.FeatLDAP:            "LDAP / AD 目录集成",
	license.FeatClientDownload:  "客户端分发与下载管控",
	license.FeatMultiInstance:   "多实例 / 集群部署",
	license.FeatPrivateIssuance: "私有化许可签发与在线登记",
	license.FeatACMERenew:       "证书自动续签",
}

// tierLabel 档位中文名
var tierLabel = map[string]string{
	license.TierCommunity:  "社区版",
	license.TierPro:        "专业版",
	license.TierEnterprise: "企业版",
}

// gateFeature 按授权档位拦截：当前许可未开启该功能时写入 403 并返回 false。
// 各高级功能 handler 在入口处调用；返回 true 表示放行。
func gateFeature(w http.ResponseWriter, key string) bool {
	if license.AllowFeature(key) {
		return true
	}
	name := featureLabel[key]
	if name == "" {
		name = "该功能"
	}
	need := tierLabel[license.RequiredTier(key)]
	if need == "" {
		need = "更高档位"
	}
	msg := name + "为" + need + "功能，当前授权档位未开启。"
	if need == "专业版" || need == "企业版" {
		msg += "如需启用，请联系作者获取" + need + "授权（详见文档站「捐赠与支持」页面）。"
	}
	util.FailCode(w, http.StatusForbidden, msg)
	return false
}
