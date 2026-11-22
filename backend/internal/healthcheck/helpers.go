package healthcheck

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertDaysRemaining 返回 PEM 文件内所有证书中「最早到期」的剩余天数。
// 已过期时返回负数；解析失败返回 error。
func CertDaysRemaining(pemPath string) (int, error) {
	b, err := os.ReadFile(pemPath)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	minDays := int(^uint(0) >> 1) // MaxInt
	found := false
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, fmt.Errorf("解析证书失败：%w", err)
		}
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		if days < minDays {
			minDays = days
		}
		found = true
	}
	if !found {
		return 0, fmt.Errorf("未找到 CERTIFICATE PEM 块")
	}
	return minDays, nil
}

// FailedLogins15m 统计最近 15 分钟 syslog 中的登录失败次数。
// 兼容两种 action：历史中文「登录失败」与新约定「login_fail」，
// 另一开发可能正在把登录日志接入统一埋点，这里两者都认。
func FailedLogins15m(dbs *sql.DB) int {
	if dbs == nil {
		return 0
	}
	var n int
	err := dbs.QueryRow(`SELECT COUNT(*) FROM syslog
		WHERE created_at >= datetime('now','localtime','-15 minutes')
		  AND (action LIKE '%login_fail%' OR action LIKE '%登录失败%' OR detail LIKE '%login_fail%')`).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// ServiceInfo service 表的精简投影，供 health / metrics / alert 共用。
type ServiceInfo struct {
	ID     int64
	Name   string
	Port   int
	Proto  string
	Status int
}

// ServiceRows 读取全部实例。
func ServiceRows(dbs *sql.DB) ([]ServiceInfo, error) {
	if dbs == nil {
		return nil, fmt.Errorf("数据库未打开")
	}
	rows, err := dbs.Query(`SELECT id, name, port, proto, status FROM service ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceInfo
	for rows.Next() {
		var s ServiceInfo
		if err := rows.Scan(&s.ID, &s.Name, &s.Port, &s.Proto, &s.Status); err == nil {
			out = append(out, s)
		}
	}
	return out, rows.Err()
}
