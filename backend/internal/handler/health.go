package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"sslvpn/internal/db"
	"sslvpn/internal/healthcheck"
	"sslvpn/internal/vpn"
	"sslvpn/internal/version"
)

func init() {
	// 无需鉴权的健康探针（规范路径 /api/v1/health；裸路径 /health 由 main.go 兜底）
	reg("GET", "/health", false, Health)
}

// Health 健康页数据：复用 doctor 的全部检查逻辑。
// 返回扁平 JSON（同时带 code/msg 与统一响应约定兼容）。
func Health(w http.ResponseWriter, r *http.Request) {
	dir := healthDataDir()
	opt := healthcheck.Options{DataDir: dir}
	checks := healthcheck.RunAll(r.Context(), opt)
	summary := healthcheck.Summary(checks)

	status := "ok"
	if summary["fail"] > 0 {
		status = "error"
	} else if summary["warn"] > 0 {
		status = "degraded"
	}

	services, _ := healthcheck.ServiceRows(db.DB)
	instances := len(services)
	certDays := map[string]int{
		"ca":     certDaysOrZero(filepath.Join(healthPKIDir(dir), "ca.crt")),
		"server": certDaysOrZero(filepath.Join(healthSSLDir(dir), "server.crt")),
	}

	resp := map[string]any{
		"code":         1,
		"msg":          "ok",
		"status":       status,
		"version":      version.Version,
		"uptime":       healthcheck.Uptime().String(),
		"instances":    instances,
		"online":       len(vpn.AllOnlineUsers()),
		"cert_days":    certDays,
		"disk_percent": healthcheck.DiskUsedPercent(dir),
		"checks":       checks,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func healthDataDir() string {
	if d := os.Getenv("SSLVPN_DATA_DIR"); d != "" {
		return d
	}
	return "/var/lib/sslvpn"
}

func healthSSLDir(dir string) string {
	if d := os.Getenv("SSLVPN_SSL_DIR"); d != "" {
		return d
	}
	return filepath.Join(dir, "ssl")
}

func healthPKIDir(dir string) string {
	if d := os.Getenv("SSLVPN_PKI_DIR"); d != "" {
		return d
	}
	return filepath.Join(dir, "pki")
}

func certDaysOrZero(path string) int {
	days, err := healthcheck.CertDaysRemaining(path)
	if err != nil {
		return 0
	}
	return days
}
