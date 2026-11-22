package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/healthcheck"
	"sslvpn/internal/vpn"
)

// dedupWindow 同一 (rule,key) 的最小重发间隔
const dedupWindow = 30 * time.Minute

var (
	dedupMu sync.Mutex
	dedup   = map[string]time.Time{}
)

// shouldSend 判断去重窗口内是否允许发送。
func shouldSend(key string, now time.Time) bool {
	dedupMu.Lock()
	defer dedupMu.Unlock()
	last, ok := dedup[key]
	if ok && now.Sub(last) < dedupWindow {
		return false
	}
	return true
}

// markSent 记录发送时间。
func markSent(key string, now time.Time) {
	dedupMu.Lock()
	dedup[key] = now
	dedupMu.Unlock()
}

// cleanupDedup 清理过期去重项，避免内存无限增长。
func cleanupDedup(now time.Time) {
	dedupMu.Lock()
	for k, t := range dedup {
		if now.Sub(t) >= dedupWindow {
			delete(dedup, k)
		}
	}
	dedupMu.Unlock()
}

type event struct {
	Rule    string
	Key     string
	Level   string
	Title   string
	Message string
}

// CheckAndNotify 执行四类规则并推送（受 enabled 开关与 30 分钟去重约束）。
func CheckAndNotify() {
	c, err := LoadConfig()
	if err != nil || !c.Enabled || len(c.Channels) == 0 {
		return
	}
	events := collectEvents()
	now := time.Now()
	cleanupDedup(now)
	for _, ev := range events {
		if !shouldSend(ev.Key, now) {
			continue
		}
		results := sendAll(c.Channels, ev.Title, ev.Message)
		markSent(ev.Key, now)
		addHistory(HistoryEntry{
			Rule: ev.Rule, Key: ev.Key, Level: ev.Level,
			Title: ev.Title, Message: ev.Message, Result: summarize(results),
		})
	}
}

// StartLoop 60 秒巡检一次，启动时立即跑一次。调用方用 go 启动。
func StartLoop() {
	CheckAndNotify()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		CheckAndNotify()
	}
}

func collectEvents() []event {
	var out []event
	out = append(out, certEvents()...)
	out = append(out, instanceEvents()...)
	out = append(out, diskEvents()...)
	out = append(out, bruteForceEvents()...)
	return out
}

// certPaths 与 healthcheck 保持同一路径推导规则
func certPaths() (caPath, serverPath, dir string) {
	dir = os.Getenv("SSLVPN_DATA_DIR")
	if dir == "" {
		dir = "/var/lib/sslvpn"
	}
	sslDir := os.Getenv("SSLVPN_SSL_DIR")
	if sslDir == "" {
		sslDir = filepath.Join(dir, "ssl")
	}
	pkiDir := os.Getenv("SSLVPN_PKI_DIR")
	if pkiDir == "" {
		pkiDir = filepath.Join(dir, "pki")
	}
	return filepath.Join(pkiDir, "ca.crt"), filepath.Join(sslDir, "server.crt"), dir
}

// certEvents 证书剩余 30/7/1 天分级告警。
func certEvents() []event {
	caPath, serverPath, _ := certPaths()
	var out []event
	for _, item := range []struct{ typ, path string }{{"ca", caPath}, {"server", serverPath}} {
		days, err := healthcheck.CertDaysRemaining(item.path)
		if err != nil || days > 30 {
			continue
		}
		level := "warning"
		if days <= 1 {
			level = "critical"
		} else if days <= 7 {
			level = "high"
		}
		out = append(out, event{
			Rule: "cert", Key: "cert:" + item.typ, Level: level,
			Title: fmt.Sprintf("【KSVPN】%s 证书即将过期（剩余 %d 天）", strings.ToUpper(item.typ), days),
			Message: fmt.Sprintf("%s 证书将在 %d 天后过期，请及时在管理页续签，否则客户端将出现证书错误导致断连。",
				strings.ToUpper(item.typ), days),
		})
	}
	return out
}

// instanceEvents service.status=1 但进程不存在 → 实例 down。
func instanceEvents() []event {
	if runtime.GOOS != "linux" {
		return nil // Windows 本机开发无 /proc，避免误报
	}
	services, err := healthcheck.ServiceRows(db.DB)
	if err != nil {
		return nil
	}
	var out []event
	for _, s := range services {
		if s.Status != 1 || vpn.IsRunning(s.Name) {
			continue
		}
		out = append(out, event{
			Rule: "instance", Key: "instance:" + s.Name, Level: "critical",
			Title:   "【KSVPN】实例已停止：" + s.Name,
			Message: fmt.Sprintf("实例 %s（端口 %d/%s）在数据库中标记为运行，但对应进程已不存在，请登录管理页重启或检查日志。", s.Name, s.Port, s.Proto),
		})
	}
	return out
}

// diskEvents 磁盘使用率 ≥85% 告警。
func diskEvents() []event {
	_, _, dir := certPaths()
	pct := healthcheck.DiskUsedPercent(dir)
	if pct < 85 {
		return nil
	}
	return []event{{
		Rule: "disk", Key: "disk", Level: "warning",
		Title:   fmt.Sprintf("【KSVPN】磁盘使用率达到 %d%%", pct),
		Message: fmt.Sprintf("数据分区使用率 %d%%（阈值 85%%），可能导致数据库写入失败，请清理日志或扩容。", pct),
	}}
}

// bruteForceEvents 15 分钟内登录失败 ≥10 次告警。
func bruteForceEvents() []event {
	n := healthcheck.FailedLogins15m(db.DB)
	if n < 10 {
		return nil
	}
	return []event{{
		Rule: "bruteforce", Key: "bruteforce", Level: "high",
		Title:   fmt.Sprintf("【KSVPN】疑似登录爆破：15 分钟内失败 %d 次", n),
		Message: fmt.Sprintf("最近 15 分钟 syslog 记录到 %d 次登录失败（阈值 10），请检查来源 IP 并考虑封禁或开启验证码。", n),
	}}
}
