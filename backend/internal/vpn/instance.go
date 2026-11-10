// Package vpn OpenVPN 多实例管理：配置渲染、进程启停、PKI、CCD
package vpn

import (
	"crypto/rand"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

//go:embed templates/*.tmpl
var tmplFS embed.FS

var (
	// BaseDir OpenVPN 根目录，Docker 内为 /etc/openvpn（可用 SSLVPN_OPENVPN_DIR 覆盖）
	BaseDir = envOr("SSLVPN_OPENVPN_DIR", "/etc/openvpn")
	// PKIDir 证书目录
	PKIDir = envOr("SSLVPN_PKI_DIR", "/var/lib/sslvpn/pki")
	// BinOpenVPN openvpn 可执行文件
	BinOpenVPN = envOr("SSLVPN_BIN_OPENVPN", "/usr/sbin/openvpn")
	// BinEasyRSA easyrsa 脚本
	BinEasyRSA = envOr("SSLVPN_BIN_EASYRSA", "/usr/share/easy-rsa/easyrsa")

	mu       sync.Mutex // 串行化 PKI / 进程操作
	procs    = map[string]*exec.Cmd{}
	servTmpl = template.Must(template.ParseFS(tmplFS, "templates/server.conf.tmpl"))
	userTmpl = template.Must(template.ParseFS(tmplFS, "templates/client.ovpn.tmpl"))
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Service 服务实例数据结构（与 db.service 对应）
type Service struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Port           int    `json:"port"`
	Proto          string `json:"proto"`
	Subnet         string `json:"subnet"`
	Mask           string `json:"mask"`
	PushRoutes     string `json:"push_routes"`
	RedirectGW     int    `json:"redirect_gw"`
	ClientToClient int    `json:"client_to_client"`
	DuplicateCN    int    `json:"duplicate_cn"`
	MaxClients     int    `json:"max_clients"`
	Status         int    `json:"status"`
}

func instanceDir(name string) string { return filepath.Join(BaseDir, "instance", name) }

// HookDir 上下线钩子脚本目录
var HookDir = envOr("SSLVPN_HOOK_DIR", "/etc/openvpn/hooks")

// SelfBin 本程序可执行文件路径（openvpn 认证回调使用）
var SelfBin = envOr("SSLVPN_BIN_SELF", "/usr/local/bin/sslvpn")

// RenderServerConf 由服务数据渲染 server.conf
// DNSProvider 全局 DNS 推送提供者（由 main 注入，避免 vpn 包反向依赖 db）
var DNSProvider func() []string

// DomainRouteProvider 域名分流路由提供者（由 main 注入，返回 "ip 255.255.255.255" 形式的路由）
var DomainRouteProvider func(serviceID int64) []string

func RenderServerConf(s *Service) ([]byte, error) {
	if s.MaxClients <= 0 {
		s.MaxClients = 253
	}
	routes := []string{}
	for _, line := range strings.Split(s.PushRoutes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			routes = append(routes, line)
		}
	}
	// 域名分流：后台填的域名已在库里解析成 IPv4，追加为 /32 路由（去重）
	if DomainRouteProvider != nil {
		seen := make(map[string]bool, len(routes))
		for _, r := range routes {
			seen[r] = true
		}
		for _, r := range DomainRouteProvider(s.ID) {
			if r = strings.TrimSpace(r); r == "" || seen[r] {
				continue
			}
			seen[r] = true
			routes = append(routes, r)
		}
	}
	dns := []string{}
	if DNSProvider != nil {
		for _, d := range DNSProvider() {
			if d = strings.TrimSpace(d); d != "" {
				dns = append(dns, d)
			}
		}
	}
	var buf strings.Builder
	err := servTmpl.Execute(&buf, map[string]any{
		"S":              s,
		"Routes":         routes,
		"DNS":            dns,
		"RedirectGW":     s.RedirectGW == 1,
		"ClientToClient": s.ClientToClient == 1,
		"DuplicateCN":    s.DuplicateCN == 1,
		"InstanceDir":    instanceDir(s.Name),
		"PKIDir":         PKIDir,
		"HookDir":        HookDir,
		"Bin":            SelfBin,
	})
	return []byte(buf.String()), err
}

// CreateInstance 建实例目录 + 证书 + ta.key + 写配置
func CreateInstance(s *Service) error {
	mu.Lock()
	defer mu.Unlock()
	dir := instanceDir(s.Name)
	for _, p := range []string{dir, filepath.Join(dir, "ccd")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
	}
	// 服务端证书
	if err := easyrsa("build-server-full", s.Name, "nopass"); err != nil {
		return fmt.Errorf("签发服务端证书失败: %w", err)
	}
	// tls-auth 密钥
	ta, err := exec.Command(BinOpenVPN, "--genkey", "secret", filepath.Join(dir, "ta.key")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("生成 ta.key 失败: %s", string(ta))
	}
	// 私钥口令文件（askpass）
	passFile := filepath.Join(BaseDir, "keys", "auth.passwd")
	_ = os.MkdirAll(filepath.Dir(passFile), 0o700)
	if _, err := os.Stat(passFile); os.IsNotExist(err) {
		_ = os.WriteFile(passFile, []byte(randomPass(24)), 0o600)
	}
	return WriteInstanceConf(s)
}

func randomPass(n int) string {
	const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	for i := range out {
		out[i] = chars[buf[i]%byte(len(chars))]
	}
	return string(out)
}

// WriteInstanceConf 渲染并写入 server.conf
func WriteInstanceConf(s *Service) error {
	conf, err := RenderServerConf(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(instanceDir(s.Name), "server.conf"), conf, 0o644)
}

// StartInstance 启动 openvpn 进程
func StartInstance(s *Service) error {
	mu.Lock()
	defer mu.Unlock()
	if p, ok := procs[s.Name]; ok && p.Process != nil {
		return fmt.Errorf("实例已在运行")
	}
	// 服务端证书私钥有口令，openvpn askpass 从文件读
	cmd := exec.Command(BinOpenVPN, "--config", filepath.Join(instanceDir(s.Name), "server.conf"))
	logPath := filepath.Join(instanceDir(s.Name), "stdout.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close() // 子进程已继承 fd，父进程必须关闭，避免每次重启泄漏一个句柄
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	procs[s.Name] = cmd
	// cmd.Start() 只代表 fork 成功。openvpn 可能因配置错误、UDP 端口被旧进程占用
	// 而在几百毫秒内退出；若不校验，页面会显示「已启动」但实际没有实例，
	// 客户端保留着旧路由 → 内外网全部断流。Linux 下确认进程仍存活。
	if _, statErr := os.Stat("/proc/self/stat"); statErr == nil {
		time.Sleep(700 * time.Millisecond)
		if !isPidAlive(cmd.Process.Pid) {
			delete(procs, s.Name)
			return fmt.Errorf("openvpn 启动后立即退出: %s", logTail(logPath, 8))
		}
	}
	go func() { _ = cmd.Wait(); delete(procs, s.Name) }()
	return nil
}

// logTail 取日志末尾若干行，用于启动失败时给出可读原因
func logTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(无日志输出)"
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.TrimSpace(strings.Join(lines, " | "))
	if out == "" {
		return "(无日志输出)"
	}
	return out
}

// StopInstance 停止实例
func StopInstance(name string) error {
	mu.Lock()
	defer mu.Unlock()
	pids := []int{}
	if p, ok := procs[name]; ok && p.Process != nil {
		pids = append(pids, p.Process.Pid)
		if err := p.Process.Signal(os.Interrupt); err != nil {
			_ = p.Process.Kill()
		}
		delete(procs, name)
	}
	// 进程不归本进程管理（容器重启后由 entrypoint 拉起）时用 pid 兜底
	pidFile := filepath.Join(instanceDir(name), "vpn.pid")
	if b, err := os.ReadFile(pidFile); err == nil {
		pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
		if e == nil && pid > 0 {
			pids = append(pids, pid)
			_ = exec.Command("kill", strconv.Itoa(pid)).Run()
		}
		_ = os.Remove(pidFile)
	}
	// 等旧进程真正退出并释放 UDP 端口，否则紧接着 StartInstance 会撞「端口已被占用」
	// 而静默失败。最多等 4 秒。
	for i := 0; i < 40 && len(pids) > 0; i++ {
		alive := false
		for _, pid := range pids {
			if isPidAlive(pid) {
				alive = true
				break
			}
		}
		if !alive {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// IsRunning 检查实例是否运行
func IsRunning(name string) bool {
	if p, ok := procs[name]; ok && p.Process != nil {
		return true
	}
	pidFile := filepath.Join(instanceDir(name), "vpn.pid")
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	return e == nil && pid > 0 && isPidAlive(pid)
}

func isPidAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || len(b) == 0 {
		return false
	}
	// 格式：pid (comm) state ...，comm 可能含空格与括号，取最后一个 ')' 之后的状态位
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	// Z=僵尸进程、X=正在退出：/proc 目录还在，但实例已无法提供服务，必须判为未运行，
	// 否则页面一直显示「运行中」，用户不会想到去重启实例。
	return state != 'Z' && state != 'X'
}

// RemoveInstance 停止并删除实例目录（证书保留在 PKI 由调用方决定吊销）
func RemoveInstance(name string) error {
	_ = StopInstance(name)
	return os.RemoveAll(instanceDir(name))
}

// ---------- easy-rsa ----------

func easyrsa(args ...string) error {
	cmd := exec.Command(BinEasyRSA, append([]string{"--batch"}, args...)...)
	cmd.Env = append(os.Environ(),
		"EASYRSA_PKI="+PKIDir,
		"EASYRSA_BATCH=1",
		"EASYRSA_ALGO=rsa",
		"EASYRSA_KEY_SIZE=2048",
		"EASYRSA_CA_EXPIRE=3650",
		"EASYRSA_CERT_EXPIRE=3650",
	)
	cmd.Dir = filepath.Dir(PKIDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, tailStr(string(out), 400))
	}
	return nil
}

// InitPKI 初始化 CA（已存在则跳过；PKI 目录不存在时先 init-pki）
func InitPKI() error {
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(filepath.Join(PKIDir, "ca.crt")); err == nil {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(PKIDir), 0o755)
	if _, err := os.Stat(PKIDir); os.IsNotExist(err) {
		if err := easyrsa("init-pki"); err != nil {
			return err
		}
	}
	return easyrsa("build-ca", "nopass")
}

// IssueUserCert 为用户签发客户端证书
func IssueUserCert(username string) error {
	mu.Lock()
	defer mu.Unlock()
	return easyrsa("build-client-full", username, "nopass")
}

// RevokeUserCert 吊销用户证书
func RevokeUserCert(username string) error {
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(filepath.Join(PKIDir, "issued", username+".crt")); err != nil {
		return nil // 未签发过，跳过
	}
	if err := easyrsa("revoke", username); err != nil {
		return err
	}
	return easyrsa("gen-crl")
}

func tailStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// ---------- CCD ----------

// Ccd 单用户 CCD 规则
type Ccd struct {
	ID           int64  `json:"id"`
	ServiceID    int64  `json:"service_id"`
	Username     string `json:"username"`
	IfconfigPush string `json:"ifconfig_push"`
	Iroutes      string `json:"iroutes"`
	PushRoutes   string `json:"push_routes"`
	DNS          string `json:"dns"`        // 推送给该用户的 DNS，逗号/空格/换行分隔
	ProxyMode    int    `json:"proxy_mode"` // 0=继承服务实例 1=全局代理 2=仅内网(push-reset)
	Raw          string `json:"raw"`        // 原始 CCD 内容（非空时直接使用，优先于上面所有字段）

	// ExtraRoutes 系统托管的路由（"a.b.c.d 255.255.255.255"），来自「域名分流」按用户规则。
	// 不落库、不参与 JSON 往返，渲染时追加在最后；域名解析刷新后重写 CCD 即可生效，无需重启实例。
	ExtraRoutes []string `json:"-"`
}

// looksLikePushDirective 判断一行是否已是完整的 push 指令（兼容直接粘贴 push "..." 的写法）
func looksLikePushDirective(line string) bool {
	return strings.HasPrefix(line, "push ") || strings.HasPrefix(line, "push\t") ||
		line == "push-reset" || strings.HasPrefix(line, "push-remove")
}

// RenderCcd 由结构化字段生成 CCD 文件内容；Raw 非空时原样返回（ExtraRoutes 仍会追加）
func RenderCcd(c *Ccd) string {
	if strings.TrimSpace(c.Raw) != "" {
		return appendExtraRoutes(strings.TrimRight(c.Raw, "\n")+"\n", c.ExtraRoutes)
	}
	var b strings.Builder
	if c.ProxyMode == 2 {
		// 清空服务实例推送的所有选项，仅保留本 CCD 中的配置（用户重连后生效）
		b.WriteString("# 仅内网：忽略服务实例的全局代理等推送\npush-reset\n")
	}
	if c.IfconfigPush != "" {
		fmt.Fprintf(&b, "ifconfig-push %s\n", c.IfconfigPush)
	}
	for _, line := range strings.Split(c.Iroutes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Fprintf(&b, "iroute %s\n", line)
		}
	}
	if c.ProxyMode == 1 {
		b.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
	}
	// 用户级 DNS：优先用该用户配置的 DNS；用户选「全局代理」但没单独填时，
	// 沿用全局设置的 DNS（与实例级「勾选全局代理才推 DNS」保持一致）
	dnsList := strings.FieldsFunc(c.DNS, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
	if len(dnsList) == 0 && c.ProxyMode == 1 && DNSProvider != nil {
		dnsList = DNSProvider()
	}
	for _, d := range dnsList {
		if d = strings.TrimSpace(d); d != "" {
			fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", d)
		}
	}
	for _, line := range strings.Split(c.PushRoutes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if looksLikePushDirective(line) {
			fmt.Fprintf(&b, "%s\n", line)
		} else {
			fmt.Fprintf(&b, "push \"route %s\"\n", line)
		}
	}
	return appendExtraRoutes(b.String(), c.ExtraRoutes)
}

// appendExtraRoutes 追加系统托管路由（域名分流），跳过与已有内容重复的 IP
func appendExtraRoutes(body string, extra []string) string {
	if len(extra) == 0 {
		return body
	}
	var add strings.Builder
	for _, r := range extra {
		r = strings.TrimSpace(r)
		fields := strings.Fields(r)
		if len(fields) == 0 {
			continue
		}
		// 已手写过同一目标（push_routes / raw）时不再重复推送
		if strings.Contains(body, fields[0]+" ") || strings.Contains(add.String(), fields[0]+" ") {
			continue
		}
		fmt.Fprintf(&add, "push \"route %s\"\n", r)
	}
	if add.Len() == 0 {
		return body
	}
	var out strings.Builder
	out.WriteString(body)
	if body != "" && !strings.HasSuffix(body, "\n") {
		out.WriteString("\n")
	}
	out.WriteString("# ---- 域名分流（系统自动生成，随解析结果刷新；用户重新连接后生效）----\n")
	out.WriteString(add.String())
	return out.String()
}

// WriteCcd 渲染用户 CCD 文件到指定实例
func WriteCcd(svcName string, c *Ccd) error {
	dir := filepath.Join(instanceDir(svcName), "ccd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, c.Username), []byte(RenderCcd(c)), 0o644)
}

// RemoveCcd 删除用户 CCD 文件
func RemoveCcd(svcName, username string) error {
	return os.Remove(filepath.Join(instanceDir(svcName), "ccd", username))
}

// ---------- 在线状态 ----------

// OnlineUser 在线用户信息（来自 status.log）
type OnlineUser struct {
	Username   string `json:"username"`
	RealIP     string `json:"real_ip"`
	VirtualIP  string `json:"virtual_ip"`
	ConnectedS int64  `json:"connected_since"`
	RecvBytes  int64  `json:"bytes_recv"`
	SendBytes  int64  `json:"bytes_send"`
}

var cnLine = regexp.MustCompile(`^([^,]+),([0-9.]+):(\d+),(\d+),(\d+),(.*)$`)
var rtLine = regexp.MustCompile(`^([0-9a-fA-F.:]+),([^,]+),`)

// ParseStatusLog 解析 OpenVPN status.log（版本1格式，含 CLIENT LIST 与 ROUTING TABLE）
func ParseStatusLog(svcName string) []OnlineUser {
	data, err := os.ReadFile(filepath.Join(instanceDir(svcName), "status.log"))
	if err != nil {
		return nil
	}
	section := ""
	users := []OnlineUser{}
	idx := map[string]int{}
	vip := map[string]string{} // Common Name -> 虚拟 IP
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "OpenVPN CLIENT LIST"):
			section = "clients"
			continue
		case strings.HasPrefix(line, "ROUTING TABLE"):
			section = "routes"
			continue
		case strings.HasPrefix(line, "GLOBAL STATS"), line == "END":
			section = ""
			continue
		}
		switch section {
		case "clients":
			if strings.HasPrefix(line, "Updated,") || strings.HasPrefix(line, "Common Name,") {
				continue
			}
			// Common Name,Real Address(:port),Bytes Received,Bytes Sent,Connected Since
			if m := cnLine.FindStringSubmatch(line); m != nil {
				recv, _ := strconv.ParseInt(m[4], 10, 64)
				send, _ := strconv.ParseInt(m[5], 10, 64)
				users = append(users, OnlineUser{
					Username:  strings.TrimSpace(m[1]),
					RealIP:    m[2] + ":" + m[3],
					RecvBytes: recv, SendBytes: send,
					ConnectedS: parseSince(m[6]),
				})
				idx[strings.TrimSpace(m[1])] = len(users) - 1
			}
		case "routes":
			if strings.HasPrefix(line, "Virtual Address,") {
				continue
			}
			// Virtual Address,Common Name,Real Address,Last Ref
			if m := rtLine.FindStringSubmatch(line); m != nil {
				vip[strings.TrimSpace(m[2])] = strings.TrimSpace(m[1])
			}
		}
	}
	// 回填虚拟 IP；routing table 缺失时从 ipp.txt 补
	for i := range users {
		if v, ok := vip[users[i].Username]; ok {
			users[i].VirtualIP = v
		}
	}
	fillVIPFromIpp(svcName, users)
	return users
}

// fillVIPFromIpp 从 ifconfig-pool-persist 文件补充虚拟 IP
func fillVIPFromIpp(svcName string, users []OnlineUser) {
	for i := range users {
		if users[i].VirtualIP != "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(instanceDir(svcName), "ipp.txt"))
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(strings.TrimSpace(line), ",")
			if len(f) >= 2 && f[0] == users[i].Username {
				users[i].VirtualIP = f[1]
				break
			}
		}
	}
}

// parseSince "Tue Nov  3 16:00:00 2026"（ctime 格式，日期可能空格补位）-> unix 秒
func parseSince(s string) int64 {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"Mon Jan _2 15:04:05 2006", "Mon Jan 2 15:04:05 2006", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// AllOnlineUsers 汇总所有实例在线用户
func AllOnlineUsers() []OnlineUser {
	var all []OnlineUser
	entries, err := os.ReadDir(filepath.Join(BaseDir, "instance"))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			all = append(all, ParseStatusLog(e.Name())...)
		}
	}
	return all
}
