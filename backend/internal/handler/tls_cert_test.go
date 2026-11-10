package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// genTestPair 生成自签证书对（CN 可指定）
func genTestPair(t *testing.T, cn string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// TestWebTLSCertHotReload 验证：更换证书后，新 TLS 握手立即使用新证书（无需重启）
func TestWebTLSCertHotReload(t *testing.T) {
	initial := genTestPair(t, "initial-cert")
	SetWebTLSCert(initial)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c := CurrentWebTLSCert(); c != nil {
					return c, nil
				}
				return initial, nil
			},
		},
	}
	go srv.ServeTLS(ln, "", "")

	peerCN := func() string {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		c, err := x509.ParseCertificate(conn.ConnectionState().PeerCertificates[0].Raw)
		if err != nil {
			t.Fatal(err)
		}
		return c.Subject.CommonName
	}

	if got := peerCN(); got != "initial-cert" {
		t.Fatalf("初始证书 CN = %q, 期望 initial-cert", got)
	}

	// 热替换为自签自定义证书
	updated := genTestPair(t, "custom-cert")
	SetWebTLSCert(updated)
	if got := peerCN(); got != "custom-cert" {
		t.Fatalf("热替换后 CN = %q, 期望 custom-cert", got)
	}
}
