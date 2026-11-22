package healthcheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckTUNGracefulSkipOnWindows(t *testing.T) {
	c := CheckTUN(filepath.Join(t.TempDir(), "missing"), "windows")
	if c.Level != LevelSkip {
		t.Fatalf("Windows 应 graceful skip，得到 %s", c.Level)
	}
	if !strings.Contains(c.Message, "非 Linux") {
		t.Fatalf("skip 应标注原因：%s", c.Message)
	}
}

func TestCheckTUNFailOnLinuxMissing(t *testing.T) {
	c := CheckTUN(filepath.Join(t.TempDir(), "missing-tun"), "linux")
	if c.Level != LevelFail {
		t.Fatalf("Linux 下缺失 TUN 应 FAIL，得到 %s", c.Level)
	}
	if c.Fix == "" {
		t.Fatal("FAIL 必须给出修复命令提示")
	}
}

func TestCheckCapNetAdminBit(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with")
	without := filepath.Join(dir, "without")
	// CAP_NET_ADMIN = bit 12 => 0x1000
	if err := os.WriteFile(with, []byte("Name:\troot\nCapEff:\t0000000000001000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(without, []byte("CapEff:\t0000000000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := CheckCapNetAdmin(with, "linux"); c.Level != LevelPass {
		t.Fatalf("含 bit12 应 PASS，得到 %s: %s", c.Level, c.Message)
	}
	if c := CheckCapNetAdmin(without, "linux"); c.Level != LevelFail {
		t.Fatalf("不含 bit12 应 FAIL，得到 %s", c.Level)
	}
	if c := CheckCapNetAdmin(without, "windows"); c.Level != LevelSkip {
		t.Fatalf("Windows 应 SKIP，得到 %s", c.Level)
	}
}

func TestCheckIPForward(t *testing.T) {
	dir := t.TempDir()
	on := filepath.Join(dir, "on")
	off := filepath.Join(dir, "off")
	_ = os.WriteFile(on, []byte("1\n"), 0o600)
	_ = os.WriteFile(off, []byte("0\n"), 0o600)
	if c := CheckIPForward(on, "linux"); c.Level != LevelPass {
		t.Fatalf("ip_forward=1 应 PASS，得到 %s", c.Level)
	}
	if c := CheckIPForward(off, "linux"); c.Level != LevelFail {
		t.Fatalf("ip_forward=0 应 FAIL，得到 %s", c.Level)
	}
	if c := CheckIPForward(off, "windows"); c.Level != LevelSkip {
		t.Fatalf("Windows 应 SKIP，得到 %s", c.Level)
	}
}

func TestCheckPortsWithInjectedProbe(t *testing.T) {
	probe := func(network, addr string) error {
		if addr == ":9999" {
			return fmt.Errorf("address already in use")
		}
		return nil
	}
	c := CheckPorts(nil, "8080", "9999", probe)
	if c.Level != LevelWarn {
		t.Fatalf("端口冲突应 WARN，得到 %s: %s", c.Level, c.Message)
	}
	if !strings.Contains(c.Message, "9999") {
		t.Fatalf("报告应含冲突端口：%s", c.Message)
	}
}

func TestCheckCertsAndHostname(t *testing.T) {
	dir := t.TempDir()
	path := writeTestCert(t, filepath.Join(dir, "server.crt"), "vpn.example.com")
	days, err := CertDaysRemaining(path)
	if err != nil {
		t.Fatal(err)
	}
	if days < 29 || days > 31 {
		t.Fatalf("剩余天数应在 30 天左右，得到 %d", days)
	}
	if err := VerifyCertHostname(path, "vpn.example.com"); err != nil {
		t.Fatalf("域名应匹配：%v", err)
	}
	if err := VerifyCertHostname(path, "wrong.example.com"); err == nil {
		t.Fatal("域名不匹配应报错")
	}
	c := CheckCerts(path, path, "wrong.example.com")
	if c.Level != LevelWarn {
		t.Fatalf("域名不匹配应 WARN，得到 %s: %s", c.Level, c.Message)
	}
}

func TestCheckClockSkew(t *testing.T) {
	fetch := func() (time.Time, error) { return time.Now().Add(-10 * time.Minute), nil }
	if c := CheckClock(time.Now(), fetch); c.Level != LevelWarn {
		t.Fatalf("偏差 10 分钟应 WARN，得到 %s", c.Level)
	}
	fetchOK := func() (time.Time, error) { return time.Now().Add(-1 * time.Minute), nil }
	if c := CheckClock(time.Now(), fetchOK); c.Level != LevelPass {
		t.Fatalf("偏差 1 分钟应 PASS，得到 %s", c.Level)
	}
}

func TestRenderReportJSONAndSummary(t *testing.T) {
	checks := []Check{
		{ID: "a", Level: LevelPass},
		{ID: "b", Level: LevelFail},
		{ID: "c", Level: LevelSkip},
	}
	s := Summary(checks)
	if s["pass"] != 1 || s["fail"] != 1 || s["skip"] != 1 {
		t.Fatalf("统计错误：%v", s)
	}
	if !HasFail(checks) {
		t.Fatal("存在 FAIL 应返回 true")
	}
	out := RenderReport(checks, true)
	if !strings.Contains(out, `"checks"`) || !strings.Contains(out, `"summary"`) {
		t.Fatalf("JSON 报告缺少字段：%s", out)
	}
}

// writeTestCert 生成一张 30 天有效的自签证书用于测试
func writeTestCert(t *testing.T, path, dns string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dns},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		DNSNames:     []string{dns},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
