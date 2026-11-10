package acme

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
)

// newAliyun 阿里云 DNS（Alidns）
func newAliyun(c Config) (challenge.Provider, error) {
	cfg := alidns.NewDefaultConfig()
	cfg.APIKey = c.AccessKey
	cfg.SecretKey = c.SecretKey
	return alidns.NewDNSProviderConfig(cfg)
}

// newTencent 腾讯云 DNSPod
func newTencent(c Config) (challenge.Provider, error) {
	cfg := tencentcloud.NewDefaultConfig()
	cfg.SecretID = c.AccessKey
	cfg.SecretKey = c.SecretKey
	return tencentcloud.NewDNSProviderConfig(cfg)
}
