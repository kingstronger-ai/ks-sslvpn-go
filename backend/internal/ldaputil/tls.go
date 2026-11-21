// Package ldaputil 中的共享 TLS 配置构建逻辑，供 handler 与 vpn 两条 LDAP 认证路径共用。
package ldaputil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// TLSConfig 按 tls_mode 构建 LDAP 连接的 TLS 配置。
//   - "" / "insecure"：兼容历史自签场景，不校验证书（有中间人风险，仅限可信内网）
//   - "system"：用系统根证书校验服务端
//   - "custom"：只信任 caCert 中的 PEM CA（自签 DC）
//   - "starttls"：与 system/custom 同校验规则，但必须走 StartTLS，不得用 ldaps
//
// serverName 用于证书名与连接地址不一致时覆盖 SNI；缺失时回退 host。
// 未知模式 / 自签 CA 缺失一律返回错误，避免拼写错误把证书校验静默降级。
func TLSConfig(verifyMode, caCert, serverName, host string) (*tls.Config, error) {
	mode := strings.ToLower(strings.TrimSpace(verifyMode))
	if mode == "" {
		mode = "insecure"
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if mode == "insecure" {
		cfg.InsecureSkipVerify = true // 显式兼容模式，管理界面需提示风险
		return cfg, nil
	}
	switch mode {
	case "system":
		// RootCAs=nil 表示使用系统默认证书池
	case "custom":
		pem := []byte(strings.TrimSpace(caCert))
		if len(pem) == 0 {
			return nil, fmt.Errorf("tls_mode=custom 但未配置 CA 证书")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 证书不是有效的 PEM 格式")
		}
		cfg.RootCAs = pool
	default:
		return nil, fmt.Errorf("未知的 TLS 模式 %q（可选 insecure/system/custom/starttls）", mode)
	}
	sn := strings.TrimSpace(serverName)
	if sn == "" {
		sn = strings.TrimSpace(host)
	}
	if sn == "" {
		return nil, fmt.Errorf("无法确定 TLS ServerName，请配置 tls_server_name")
	}
	cfg.ServerName = sn
	return cfg, nil
}

// VerifyMode 把 tls_mode 归一为实际用于校验证书的模式；starttls 按 CA 是否配置选 system/custom。
func VerifyMode(mode, caCert string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return "insecure"
	}
	if m == "starttls" {
		if strings.TrimSpace(caCert) != "" {
			return "custom"
		}
		return "system"
	}
	return m
}
