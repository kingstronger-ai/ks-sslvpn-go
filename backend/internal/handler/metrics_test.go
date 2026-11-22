package handler

import (
	"strings"
	"testing"

	"sslvpn/internal/healthcheck"
)

func TestRenderMetricsFormat(t *testing.T) {
	d := metricsData{
		up: 1,
		services: []healthcheck.ServiceInfo{
			{ID: 1, Name: `corp"vpn`, Port: 1194, Proto: "udp", Status: 1},
			{ID: 2, Name: "branch", Port: 1195, Proto: "udp", Status: 0},
		},
		online:      map[string]int{`corp"vpn`: 3, "branch": 0},
		certDays:    map[string]int{"ca": 200, "server": 12},
		diskPercent: 87,
		failedLogin: 11,
	}
	out := renderMetrics(d)
	for _, want := range []string{
		"# HELP sslvpn_up",
		"# TYPE sslvpn_up gauge",
		"sslvpn_up 1",
		"# HELP sslvpn_instance_status",
		"# TYPE sslvpn_instance_status gauge",
		`sslvpn_instance_status{name="corp\"vpn"} 1`,
		`sslvpn_instance_status{name="branch"} 0`,
		"# HELP sslvpn_online_users",
		"# TYPE sslvpn_online_users gauge",
		`sslvpn_online_users{name="corp\"vpn"} 3`,
		"# HELP sslvpn_cert_days_remaining",
		"# TYPE sslvpn_cert_days_remaining gauge",
		`sslvpn_cert_days_remaining{type="ca"} 200`,
		`sslvpn_cert_days_remaining{type="server"} 12`,
		"# HELP sslvpn_disk_used_percent",
		"# TYPE sslvpn_disk_used_percent gauge",
		"sslvpn_disk_used_percent 87",
		"# HELP sslvpn_failed_logins_total",
		"# TYPE sslvpn_failed_logins_total counter",
		"sslvpn_failed_logins_total 11",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("指标输出缺少 %q\n实际输出:\n%s", want, out)
		}
	}
	// 每个指标族都应有 HELP/TYPE
	if strings.Count(out, "# HELP") != 6 || strings.Count(out, "# TYPE") != 6 {
		t.Fatalf("HELP/TYPE 注释数量不对：HELP=%d TYPE=%d", strings.Count(out, "# HELP"), strings.Count(out, "# TYPE"))
	}
}

func TestRenderMetricsEmptyServices(t *testing.T) {
	out := renderMetrics(metricsData{up: 1, certDays: map[string]int{}})
	if !strings.Contains(out, "sslvpn_instance_status 0") {
		t.Fatal("无实例时应输出占位指标，避免 Prometheus 空序列")
	}
}
