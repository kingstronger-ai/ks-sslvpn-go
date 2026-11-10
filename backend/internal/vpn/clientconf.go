package vpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// ClientConfData 生成用户 .ovpn 所需数据
type ClientConfData struct {
	Host       string // 服务器地址（公网 IP 或域名）
	Port       int
	Proto      string
	ServerName string
	CACert     string
	UserCert   string
	UserKey    string
	TAKey      string
}

// BuildClientConf 渲染用户客户端配置（内联证书模式）
func BuildClientConf(svcName, username string, d ClientConfData) ([]byte, error) {
	var err error
	d.CACert, err = readFile(filepath.Join(PKIDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	if d.UserCert, err = readFile(filepath.Join(PKIDir, "issued", username+".crt")); err != nil {
		return nil, fmt.Errorf("用户证书不存在，请先重建配置: %w", err)
	}
	if d.UserKey, err = readFile(filepath.Join(PKIDir, "private", username+".key")); err != nil {
		return nil, fmt.Errorf("用户私钥不存在: %w", err)
	}
	if d.TAKey, err = readFile(filepath.Join(instanceDir(svcName), "ta.key")); err != nil {
		return nil, fmt.Errorf("ta.key 不存在: %w", err)
	}
	var buf strings.Builder
	if err := userTmpl.Execute(&buf, d); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

var _ = template.Must // 保持模板依赖引用
