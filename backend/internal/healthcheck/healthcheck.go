// Package healthcheck 提供 sslvpn doctor 与健康页共用的预检逻辑。
//
// 设计目标：
//   - 所有检查互相独立，单项失败不影响其它项；
//   - Linux 专有检查在 Windows 本机开发时 graceful skip，不 panic；
//   - 输入路径 / 探测函数可注入，便于单测 mock。
package healthcheck

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sslvpn/internal/db"
)

// Level 检查结论等级
type Level string

const (
	LevelPass Level = "pass"
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
	LevelSkip Level = "skip"
)

// Check 单项检查结果
type Check struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Options 检查参数；空字段由 RunAll 填充默认值。
type Options struct {
	DataDir string // 数据目录（决定 sqlite / 证书路径）
	SSLDir  string // 管理页证书目录，留空=dataDir/ssl
	PKIDir  string // PKI 目录，留空=dataDir/pki
	Domain  string // 期望证书域名，留空=读 settings.public_host / 环境变量
	DB      *sql.DB
	APIPort string
	WebPort string
}

// 可注入探测点（单测可替换）
var (
	ProbeTUNPath       = "/dev/net/tun"
	ProbeProcStatus    = "/proc/self/status"
	ProbeIPForwardPath = "/proc/sys/net/ipv4/ip_forward"
	ProbeHTTPDate      = fetchHTTPDate
	ProbeListen        = probeListen
)

var startedAt = time.Now()

// Uptime 进程运行时长
func Uptime() time.Duration { return time.Since(startedAt) }

// fetchHTTPDate 从公共站点 HEAD 请求读取 Date 头，作为粗略网络时间源。
func fetchHTTPDate() (time.Time, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	req, _ := http.NewRequest(http.MethodHead, "https://www.baidu.com", nil)
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	return http.ParseTime(resp.Header.Get("Date"))
}

// probeListen 按网络类型做一次绑定探测，成功即关闭释放。
func probeListen(network, addr string) error {
	if network == "udp" || network == "udp4" || network == "udp6" {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// RunAll 依次执行全部检查项。
func RunAll(ctx context.Context, opt Options) []Check {
	if opt.DataDir == "" {
		opt.DataDir = dataDir()
	}
	if opt.SSLDir == "" {
		opt.SSLDir = os.Getenv("SSLVPN_SSL_DIR")
		if opt.SSLDir == "" {
			opt.SSLDir = filepath.Join(opt.DataDir, "ssl")
		}
	}
	if opt.PKIDir == "" {
		opt.PKIDir = os.Getenv("SSLVPN_PKI_DIR")
		if opt.PKIDir == "" {
			opt.PKIDir = filepath.Join(opt.DataDir, "pki")
		}
	}
	if opt.Domain == "" {
		opt.Domain = os.Getenv("SSLVPN_CERT_DOMAIN")
	}
	if opt.DB == nil {
		opt.DB = db.DB
	}
	if opt.APIPort == "" {
		opt.APIPort = envOr("SSLVPN_API_PORT", "8080")
	}
	if opt.WebPort == "" {
		opt.WebPort = envOr("SSLVPN_WEB_PORT", "8443")
	}
	if opt.Domain == "" && opt.DB != nil {
		opt.Domain = db.GetSetting("public_host")
	}

	return []Check{
		CheckTUN(ProbeTUNPath, runtime.GOOS),
		CheckCapNetAdmin(ProbeProcStatus, runtime.GOOS),
		CheckIPForward(ProbeIPForwardPath, runtime.GOOS),
		CheckPorts(opt.DB, opt.APIPort, opt.WebPort, ProbeListen),
		CheckClock(time.Now(), ProbeHTTPDate),
		CheckCerts(filepath.Join(opt.PKIDir, "ca.crt"), filepath.Join(opt.SSLDir, "server.crt"), opt.Domain),
		CheckSQLite(opt.DB),
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func dataDir() string {
	if d := os.Getenv("SSLVPN_DATA_DIR"); d != "" {
		return d
	}
	return "/var/lib/sslvpn"
}

// ---- 单项检查 ----

// CheckTUN 检查 /dev/net/tun 是否存在且可读。
func CheckTUN(path, goos string) Check {
	c := Check{ID: "tun", Name: "TUN 设备"}
	if goos != "linux" {
		c.Level, c.Message = LevelSkip, "非 Linux 环境（"+goos+"），跳过 /dev/net/tun 检查"
		return c
	}
	f, err := os.Open(path)
	if err != nil {
		c.Level = LevelFail
		c.Message = fmt.Sprintf("%s 不存在或不可读：%v", path, err)
		c.Fix = "确认容器已加 --device /dev/net/tun（compose: devices: [\"/dev/net/tun:/dev/net/tun\"]），或以 root 运行"
		return c
	}
	_ = f.Close()
	c.Level, c.Message = LevelPass, path+" 存在且可读"
	return c
}

// CheckCapNetAdmin 读 /proc/self/status 的 CapEff 按位判断 CAP_NET_ADMIN(bit 12)。
func CheckCapNetAdmin(statusPath, goos string) Check {
	c := Check{ID: "cap_net_admin", Name: "CAP_NET_ADMIN 权限"}
	if goos != "linux" {
		c.Level, c.Message = LevelSkip, "非 Linux 环境（"+goos+"），跳过 capabilities 检查"
		return c
	}
	b, err := os.ReadFile(statusPath)
	if err != nil {
		c.Level, c.Message = LevelFail, "读取 "+statusPath+" 失败："+err.Error()
		c.Fix = "确认在容器内以 root 运行；docker compose 增加 cap_add: NET_ADMIN"
		return c
	}
	var capEff uint64
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(strings.TrimPrefix(line, "CapEff:"))
			if len(fields) > 0 {
				capEff, err = strconv.ParseUint(fields[0], 16, 64)
				if err != nil {
					c.Level, c.Message = LevelWarn, "CapEff 解析失败："+err.Error()
					return c
				}
			}
			break
		}
	}
	const capNetAdmin = 12
	if capEff&(1<<capNetAdmin) == 0 {
		c.Level = LevelFail
		c.Message = "当前进程缺少 CAP_NET_ADMIN（无法配置 TUN/iptables）"
		c.Fix = "docker-compose 增加 cap_add: NET_ADMIN（必要时再加 cap_add: NET_RAW），并确认 --privileged 未误关"
		return c
	}
	c.Level, c.Message = LevelPass, "CapEff 含 CAP_NET_ADMIN(bit 12)"
	return c
}

// CheckIPForward 检查 net.ipv4.ip_forward=1。
func CheckIPForward(procPath, goos string) Check {
	c := Check{ID: "ip_forward", Name: "IPv4 转发"}
	if goos != "linux" {
		c.Level, c.Message = LevelSkip, "非 Linux 环境（"+goos+"），跳过 ip_forward 检查"
		return c
	}
	b, err := os.ReadFile(procPath)
	if err != nil {
		c.Level, c.Message = LevelFail, "读取 "+procPath+" 失败："+err.Error()
		c.Fix = "执行 sysctl -w net.ipv4.ip_forward=1；docker compose 加 sysctls: {net.ipv4.ip_forward: 1}"
		return c
	}
	if strings.TrimSpace(string(b)) != "1" {
		c.Level = LevelFail
		c.Message = "net.ipv4.ip_forward 未开启（当前 " + strings.TrimSpace(string(b)) + "）"
		c.Fix = "执行 sysctl -w net.ipv4.ip_forward=1；docker compose 加 sysctls: {net.ipv4.ip_forward: 1}"
		return c
	}
	c.Level, c.Message = LevelPass, "net.ipv4.ip_forward=1"
	return c
}

// CheckPorts 检查管理端口与 service 表端口是否冲突。probe 可注入以便 mock。
func CheckPorts(dbs *sql.DB, apiPort, webPort string, probe func(network, addr string) error) Check {
	c := Check{ID: "ports", Name: "端口占用"}
	if probe == nil {
		probe = probeListen
	}
	type portEntry struct {
		network string
		port    string
		label   string
	}
	entries := []portEntry{
		{"tcp", apiPort, "管理 API 端口 " + apiPort},
		{"tcp", webPort, "管理 Web 端口 " + webPort},
	}
	if dbs != nil {
		rows, err := dbs.Query(`SELECT name, port, proto FROM service ORDER BY id`)
		if err == nil {
			for rows.Next() {
				var name, proto string
				var port int
				if rows.Scan(&name, &port, &proto) == nil {
					network := "udp"
					if strings.EqualFold(proto, "tcp") {
						network = "tcp"
					}
					entries = append(entries, portEntry{network, strconv.Itoa(port), "实例 " + name + " 的 " + network + " 端口 " + strconv.Itoa(port)})
				}
			}
			rows.Close()
		}
	}
	seen := map[string]bool{}
	conflicts := []string{}
	for _, e := range entries {
		if e.port == "" || seen[e.network+":"+e.port] {
			continue
		}
		seen[e.network+":"+e.port] = true
		if err := probe(e.network, ":"+e.port); err != nil {
			conflicts = append(conflicts, fmt.Sprintf("%s（%v）", e.label, err))
		}
	}
	if len(conflicts) > 0 {
		c.Level = LevelWarn
		c.Message = "以下端口当前无法绑定，可能已被占用：" + strings.Join(conflicts, "；")
		c.Fix = "修改 docker-compose 端口映射，或在管理页调整实例端口后重启；占用排查：ss -lntp / ss -lnup"
		return c
	}
	c.Level, c.Message = LevelPass, fmt.Sprintf("%d 个端口均可绑定", len(seen))
	return c
}

// CheckClock 与网络时间比对，偏差 >5min 告警。
func CheckClock(now time.Time, fetch func() (time.Time, error)) Check {
	c := Check{ID: "clock", Name: "系统时间"}
	if fetch == nil {
		fetch = fetchHTTPDate
	}
	remote, err := fetch()
	if err != nil {
		c.Level, c.Message = LevelWarn, "无法获取网络时间，跳过偏差比对："+err.Error()
		c.Fix = "确认服务器可访问公网；隔离网环境请手工校准时间（chronyd / ntpdate）"
		return c
	}
	diff := now.Sub(remote)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Minute {
		c.Level = LevelWarn
		c.Message = fmt.Sprintf("系统时间与网络时间偏差 %s（阈值 5 分钟）", diff.Round(time.Second))
		c.Fix = "执行 chronyc makestep 或 ntpdate -u pool.ntp.org 校准系统时间，否则证书校验会提前失败"
		return c
	}
	c.Level, c.Message = LevelPass, fmt.Sprintf("时间偏差 %s（阈值 5 分钟内）", diff.Round(time.Second))
	return c
}

// CheckCerts 解析 CA/server 证书，检查有效期与域名匹配。
func CheckCerts(caPath, serverPath, domain string) Check {
	c := Check{ID: "certs", Name: "证书链与域名"}
	var problems []string
	var ok []string
	for _, item := range []struct {
		typ  string
		path string
	}{{"ca", caPath}, {"server", serverPath}} {
		days, err := CertDaysRemaining(item.path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s 证书读取/解析失败（%s）：%v", item.typ, item.path, err))
			continue
		}
		if days < 0 {
			problems = append(problems, fmt.Sprintf("%s 证书已过期 %d 天", item.typ, -days))
		} else if days <= 30 {
			problems = append(problems, fmt.Sprintf("%s 证书仅剩 %d 天", item.typ, days))
		} else {
			ok = append(ok, fmt.Sprintf("%s 证书剩余 %d 天", item.typ, days))
		}
	}
	if domain != "" {
		if err := VerifyCertHostname(serverPath, domain); err != nil {
			problems = append(problems, "server 证书与域名 "+domain+" 不匹配："+err.Error())
		} else {
			ok = append(ok, "server 证书匹配域名 "+domain)
		}
	} else {
		ok = append(ok, "未配置期望域名，跳过域名匹配（可在「系统设置 → 公网地址」填写）")
	}
	c.Message = strings.Join(append(problems, ok...), "；")
	if len(problems) > 0 {
		c.Level = LevelWarn
		c.Fix = "在管理页「证书管理」重新签发证书，或执行 sslvpn init 生成自签证书；过期前请提前续签"
		return c
	}
	c.Level = LevelPass
	return c
}

// VerifyCertHostname 校验证书文件中的第一张证书是否匹配域名。
func VerifyCertHostname(pemPath, domain string) error {
	b, err := os.ReadFile(pemPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("PEM 解码失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	return cert.VerifyHostname(domain)
}

// CheckSQLite 检查数据库可写与 WAL 模式。
func CheckSQLite(dbs *sql.DB) Check {
	c := Check{ID: "sqlite", Name: "SQLite 数据库"}
	if dbs == nil {
		c.Level, c.Message = LevelFail, "数据库未打开"
		c.Fix = "确认数据目录可写：docker compose 挂载卷并给容器写权限"
		return c
	}
	tx, err := dbs.Begin()
	if err != nil {
		c.Level, c.Message = LevelFail, "开启事务失败："+err.Error()
		return c
	}
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS __healthcheck_probe__(x INTEGER)`)
	_ = tx.Rollback()
	if err != nil {
		c.Level = LevelFail
		c.Message = "数据库只读或不可写：" + err.Error()
		c.Fix = "确认数据目录挂载可写（chown 容器运行用户），并检查磁盘是否已满"
		return c
	}
	var mode string
	if err := dbs.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		c.Level, c.Message = LevelWarn, "读取 journal_mode 失败："+err.Error()
		return c
	}
	if !strings.EqualFold(mode, "wal") {
		c.Level = LevelWarn
		c.Message = "当前 journal_mode=" + mode + "，非 WAL（并发写入性能较差）"
		c.Fix = "执行 PRAGMA journal_mode=WAL；程序启动时 db.Open 已默认设置"
		return c
	}
	c.Level, c.Message = LevelPass, "数据库可写且处于 WAL 模式"
	return c
}

// ---- 报告渲染 ----

// RenderReport 渲染人类可读分组报告或 JSON。
func RenderReport(checks []Check, asJSON bool) string {
	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"checks":  checks,
			"summary": Summary(checks),
		}, "", "  ")
		return string(b)
	}
	var b strings.Builder
	groups := []struct {
		level Level
		label string
	}{{LevelPass, "PASS"}, {LevelWarn, "WARN"}, {LevelFail, "FAIL"}, {LevelSkip, "SKIP"}}
	fmt.Fprintln(&b, "KSVPN 预检报告（sslvpn doctor）")
	fmt.Fprintln(&b, strings.Repeat("─", 56))
	for _, g := range groups {
		var items []Check
		for _, c := range checks {
			if c.Level == g.level {
				items = append(items, c)
			}
		}
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(&b, "[%s] %d 项\n", g.label, len(items))
		for _, c := range items {
			fmt.Fprintf(&b, "  • %s：%s\n", c.Name, c.Message)
			if c.Fix != "" {
				fmt.Fprintf(&b, "      修复：%s\n", c.Fix)
			}
		}
	}
	s := Summary(checks)
	fmt.Fprintln(&b, strings.Repeat("─", 56))
	fmt.Fprintf(&b, "汇总：PASS=%d WARN=%d FAIL=%d SKIP=%d\n", s["pass"], s["warn"], s["fail"], s["skip"])
	fmt.Fprintln(&b, "下一步：访问管理页 https://<服务器地址>:8443 完成 6 步向导（改密 → 证书 → 公网地址 → 建实例 → 建用户 → 下发配置）")
	return b.String()
}

// Summary 统计各等级数量
func Summary(checks []Check) map[string]int {
	s := map[string]int{"pass": 0, "warn": 0, "fail": 0, "skip": 0}
	for _, c := range checks {
		s[string(c.Level)]++
	}
	return s
}

// HasFail 是否存在 FAIL
func HasFail(checks []Check) bool {
	for _, c := range checks {
		if c.Level == LevelFail {
			return true
		}
	}
	return false
}
