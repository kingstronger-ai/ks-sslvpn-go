package handler

import (
	"encoding/pem"
	"testing"
)

// TestLDAPTLSConfigModes 覆盖 LDAPS 证书校验的四种模式，
// 重点确保"未知模式/自签 CA 缺失"fail closed，不再默认 InsecureSkipVerify。
func TestLDAPTLSConfigModes(t *testing.T) {
	// ① 空值 / insecure：显式兼容旧自签场景，不校验证书
	for _, mode := range []string{"", "insecure"} {
		cfg, err := ldapTLSConfig(mode, "", "", "dc.example.com")
		if err != nil {
			t.Fatalf("mode=%q: %v", mode, err)
		}
		if !cfg.InsecureSkipVerify {
			t.Fatalf("mode=%q 应保留不校验证书的旧行为", mode)
		}
	}

	// ② system：校验证书，SNI 优先取 tls_server_name，缺省回退连接主机
	cfg, err := ldapTLSConfig("system", "", "dc.example.com", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.ServerName != "dc.example.com" {
		t.Fatalf("system 模式校验开关/SNI 错误: skip=%v sn=%q", cfg.InsecureSkipVerify, cfg.ServerName)
	}
	cfg, err = ldapTLSConfig("system", "", "", "dc.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "dc.example.com" {
		t.Fatalf("SNI 未回退连接主机: %q", cfg.ServerName)
	}

	// ③ custom：有效 PEM 建立私有根池，且必须开启校验
	cert := genTestPair(t, "dc.example.com")
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	cfg, err = ldapTLSConfig("custom", caPEM, "", "dc.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs == nil {
		t.Fatal("custom 模式必须用 CA 池校验证书")
	}

	// ④ fail closed：缺 CA、无效 PEM、未知模式一律拒绝，避免静默降级为不校验
	for name, tc := range map[string][3]string{
		"缺 CA":   {"custom", "", "dc.example.com"},
		"无效 PEM": {"custom", "not a pem", "dc.example.com"},
		"未知模式":   {"systm", "", "dc.example.com"},
	} {
		if _, err := ldapTLSConfig(tc[0], tc[1], "", tc[2]); err == nil {
			t.Errorf("%s 应返回错误", name)
		}
	}
}
