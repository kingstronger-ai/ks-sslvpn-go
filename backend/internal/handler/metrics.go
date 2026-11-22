package handler

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"sslvpn/internal/db"
	"sslvpn/internal/healthcheck"
	"sslvpn/internal/vpn"
)

func init() {
	// 无需鉴权的 Prometheus 指标端点（裸路径 /metrics 由 main.go 兜底）
	reg("GET", "/metrics", false, Metrics)
}

// metricsData 指标采集结果；renderMetrics 为纯函数，便于单测输出格式。
type metricsData struct {
	up          int
	services    []healthcheck.ServiceInfo
	online      map[string]int
	certDays    map[string]int
	diskPercent int
	failedLogin int
}

// Metrics 输出 Prometheus 文本格式（text/plain; version=0.0.4）。
func Metrics(w http.ResponseWriter, r *http.Request) {
	dir := healthDataDir()
	data := metricsData{
		up:          1,
		certDays: map[string]int{
			"ca":     certDaysOrZero(filepath.Join(healthPKIDir(dir), "ca.crt")),
			"server": certDaysOrZero(filepath.Join(healthSSLDir(dir), "server.crt")),
		},
		diskPercent: healthcheck.DiskUsedPercent(dir),
		failedLogin: healthcheck.FailedLogins15m(db.DB),
	}
	services, _ := healthcheck.ServiceRows(db.DB)
	data.services = services
	data.online = make(map[string]int, len(services))
	for _, s := range services {
		// 复用 vpn 包现有的 management status 解析逻辑，不重复造轮子。
		data.online[s.Name] = len(vpn.ParseStatusLog(s.Name))
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprint(w, renderMetrics(data))
}

// metricLabel 用 strconv.Quote 转义标签值（与 Prometheus 文本格式兼容）。
func metricLabel(s string) string { return strconv.Quote(s) }

// renderMetrics 渲染全部指标，HELP/TYPE 注释齐全。
func renderMetrics(d metricsData) string {
	var b strings.Builder
	write := func(help, typ, name, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", name, help, name, typ, name, value)
	}

	write("sslvpn 进程是否存活（1=存活，0=失联）", "gauge", "sslvpn_up", strconv.Itoa(d.up))

	fmt.Fprintln(&b, "# HELP sslvpn_instance_status VPN 实例运行状态（来自 service.status：0=停止 1=运行）")
	fmt.Fprintln(&b, "# TYPE sslvpn_instance_status gauge")
	for _, s := range d.services {
		fmt.Fprintf(&b, "sslvpn_instance_status{name=%s} %d\n", metricLabel(s.Name), s.Status)
	}
	if len(d.services) == 0 {
		fmt.Fprintln(&b, "sslvpn_instance_status 0")
	}

	fmt.Fprintln(&b, "# HELP sslvpn_online_users 实例当前在线用户数（来自 management status）")
	fmt.Fprintln(&b, "# TYPE sslvpn_online_users gauge")
	for _, s := range d.services {
		fmt.Fprintf(&b, "sslvpn_online_users{name=%s} %d\n", metricLabel(s.Name), d.online[s.Name])
	}

	fmt.Fprintln(&b, "# HELP sslvpn_cert_days_remaining 证书剩余有效天数（负数表示已过期）")
	fmt.Fprintln(&b, "# TYPE sslvpn_cert_days_remaining gauge")
	fmt.Fprintf(&b, "sslvpn_cert_days_remaining{type=\"ca\"} %d\n", d.certDays["ca"])
	fmt.Fprintf(&b, "sslvpn_cert_days_remaining{type=\"server\"} %d\n", d.certDays["server"])

	write("数据分区磁盘使用率百分比（0-100，0 表示未知）", "gauge", "sslvpn_disk_used_percent", strconv.Itoa(d.diskPercent))
	write("最近 15 分钟登录失败次数（syslog 中 action 含 login_fail/登录失败）", "counter", "sslvpn_failed_logins_total", strconv.Itoa(d.failedLogin))

	return b.String()
}
