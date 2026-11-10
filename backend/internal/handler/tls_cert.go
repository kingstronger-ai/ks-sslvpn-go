package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"

	"sslvpn/internal/util"
)

// webTLSCert 当前 Web HTTPS 证书（支持运行中热替换，无需重启进程）
var webTLSCert atomic.Value // 存 *tls.Certificate

// SetWebTLSCert main 启动时注入初始证书；更新接口保存成功后热替换
func SetWebTLSCert(c *tls.Certificate) { webTLSCert.Store(c) }

// CurrentWebTLSCert TLS 握手回调读取当前生效证书
func CurrentWebTLSCert() *tls.Certificate {
	if v := webTLSCert.Load(); v != nil {
		return v.(*tls.Certificate)
	}
	return nil
}

// sslDir 证书目录（与 main.loadOrGenCert 同规则：SSLVPN_SSL_DIR 优先，默认数据目录下 ssl）
func sslDir() string {
	if d := os.Getenv("SSLVPN_SSL_DIR"); d != "" {
		return d
	}
	return "/var/lib/sslvpn/ssl"
}

// SysGetKeyFile 读取当前证书/私钥内容与证书摘要信息（管理员）
func SysGetKeyFile(w http.ResponseWriter, r *http.Request) {
	crt, _ := os.ReadFile(filepath.Join(sslDir(), "server.crt"))
	key, _ := os.ReadFile(filepath.Join(sslDir(), "server.key"))
	subject, notAfter := "", ""
	if block, _ := pem.Decode(crt); block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			subject = c.Subject.String()
			// 与浏览器证书查看器保持一致：转成容器本地时区（TZ=Asia/Shanghai）
			notAfter = c.NotAfter.Local().Format("2006-01-02 15:04:05")
		}
	}
	util.OK(w, map[string]any{
		"cert": string(crt), "key": string(key),
		"subject": subject, "not_after": notAfter,
	})
}
