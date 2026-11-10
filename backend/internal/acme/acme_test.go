package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMask(t *testing.T) {
	if Mask("") != "" || Mask("short") != "****" {
		t.Error("短凭证应整体打码")
	}
	m := Mask("LTAI5tAbCdEfGhIjKl")
	if !strings.HasPrefix(m, "LTAI") || !strings.HasSuffix(m, "Kl") || strings.Contains(m, "AbCd") {
		t.Errorf("打码格式不对: %s", m)
	}
}

func TestNormalizeDomains(t *testing.T) {
	got := normalizeDomains([]string{" VPN.Example.com ", "vpn.example.com", "", "*.api.example.com.", "*.API.example.com"})
	want := []string{"vpn.example.com", "*.api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("去重失败: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 项应为 %s，实际 %s", i, want[i], got[i])
		}
	}
}

func TestSealOpenSecret(t *testing.T) {
	plain := "LTAI5tSecretKeyValue123456"
	enc := sealSecret(plain)
	if !strings.HasPrefix(enc, "enc1:") {
		t.Fatalf("凭证应加密存储，实际 %s", enc)
	}
	if strings.Contains(enc, plain) {
		t.Error("密文不应包含明文")
	}
	if openSecret(enc) != plain {
		t.Error("解密结果与原文不一致")
	}
	// 兼容历史明文
	if openSecret("plain-ak") != "plain-ak" {
		t.Error("明文凭证应原样返回")
	}
	// 密钥不匹配时应返回空而不是 panic
	if got := openSecret("enc1:AAAA"); got != "" {
		t.Errorf("非法密文应返回空，实际 %q", got)
	}
}

// 自签一张证书，验证过期天数与来源识别
func TestCertInfo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSLVPN_SSL_DIR", dir)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(20 * 24 * time.Hour),
		DNSNames:     []string{"vpn.example.com", "www.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	st := CertInfo()
	if st.Subject != "vpn.example.com" || st.NotAfter == "" {
		t.Errorf("证书信息解析失败: %+v", st)
	}
	if st.DaysLeft != 19 && st.DaysLeft != 20 {
		t.Errorf("剩余天数计算异常: %d", st.DaysLeft)
	}
	if st.Source != "self-signed" {
		t.Errorf("自签证书来源识别错误: %s", st.Source)
	}
	if !NeedsRenew(30) || NeedsRenew(7) {
		t.Error("NeedsRenew 判断不符合预期")
	}
}

// certWithIssuer 造一张由指定 CA 签发的叶子证书
func certWithIssuer(t *testing.T, issuerCN, issuerOrg, subjectCN string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: issuerCN},
	}
	if issuerOrg != "" {
		parent.Subject.Organization = []string{issuerOrg}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertSource(t *testing.T) {
	// 签发/上传时写入的标记优先，避免 LE 中间证书 CN 轮换导致误判
	if got := certSource(certWithIssuer(t, "Some CA", "Some Org", "vpn.example.com"), "acme"); got != "acme" {
		t.Errorf("已标记 acme 的证书应识别为自动签发，实际 %s", got)
	}
	if got := certSource(certWithIssuer(t, "E7", "", "vpn.example.com"), "upload"); got != "upload" {
		t.Errorf("手工上传的证书应识别为手工上传，实际 %s", got)
	}
	// 无标记时兜底识别 LE 新旧中间证书（含 2024 年后的 E7/E8/R11…）
	for _, cn := range []string{"R3", "R10", "E5", "E6", "E7", "E8", "R11", "R13", "YE1", "YE2", "XR1"} {
		if got := certSource(certWithIssuer(t, cn, "", "vpn.example.com"), ""); got != "acme" {
			t.Errorf("LE 中间证书 %s 应识别为 acme，实际 %s", cn, got)
		}
	}
	if got := certSource(certWithIssuer(t, "Some Intermediate", "Let's Encrypt", "vpn.example.com"), ""); got != "acme" {
		t.Errorf("按签发机构识别 LE 失败，实际 %s", got)
	}
	if got := certSource(certWithIssuer(t, "My Corp CA", "My Corp", "vpn.example.com"), ""); got != "upload" {
		t.Errorf("普通 CA 签发应识别为手工上传，实际 %s", got)
	}
	if got := certSource(certWithIssuer(t, "SSLVPN-Go Root", "", "vpn.example.com"), ""); got != "self-signed" {
		t.Errorf("本系统自签证书应识别为内置自签，实际 %s", got)
	}
}
