// Package vpn —— OpenVPN management 接口：在线用户强制下线
package vpn

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// KickTarget 待踢下线的目标（实例名 + 证书 CN，即 VPN 用户名）
type KickTarget struct {
	Service  string `json:"service"`
	Username string `json:"username"`
}

// KickResult 批量强制下线结果
type KickResult struct {
	Kicked    int      `json:"kicked"`     // 已成功下发指令的人数
	Failed    []string `json:"failed"`     // 管理接口报错或连接失败的目标
	NotOnline []string `json:"not_online"` // 已不在线的目标
}

// OpenVPN 管理接口同一时刻只允许一个客户端连接，串行化所有踢人操作。
var mgmtMu sync.Mutex

var mgmtLineRe = regexp.MustCompile(`(?m)^\s*management\s+`)

func managementSocket(name string) string { return filepath.Join(instanceDir(name), "mgmt.sock") }

// EnsureManagementConfs 为存量实例的 server.conf 补一行 management 指令。
// 只做"追加一行"：runInit 在 entrypoint 阶段执行时 DNSProvider / DomainRouteProvider
// 尚未注入，整份重写会丢掉 DNS 与域名分流路由。新实例由模板一次性写全。
// 返回修改的实例数；已含 management 的实例不重复追加。
func EnsureManagementConfs() (int, error) {
	base := filepath.Join(BaseDir, "instance")
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	changed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		conf := filepath.Join(base, e.Name(), "server.conf")
		b, err := os.ReadFile(conf)
		if err != nil {
			continue
		}
		if mgmtLineRe.Match(b) {
			continue
		}
		line := "management " + managementSocket(e.Name()) + " unix\n"
		if len(b) > 0 && b[len(b)-1] != '\n' {
			line = "\n" + line
		}
		f, err := os.OpenFile(conf, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		_, err = f.WriteString(line)
		_ = f.Close()
		if err == nil {
			changed++
		}
	}
	return changed, nil
}

// KickClients 按实例分组强制断开在线用户。返回成功下发数、失败与不在线明细。
func KickClients(targets []KickTarget) KickResult {
	mgmtMu.Lock()
	defer mgmtMu.Unlock()

	res := KickResult{Failed: []string{}, NotOnline: []string{}}
	groups := map[string][]string{}
	order := []string{}
	for _, t := range targets {
		svc := strings.TrimSpace(t.Service)
		cn := strings.TrimSpace(t.Username)
		if svc == "" || cn == "" {
			continue
		}
		if _, ok := groups[svc]; !ok {
			order = append(order, svc)
		}
		groups[svc] = append(groups[svc], cn)
	}

	for _, svc := range order {
		// 只踢当前确实在线的 CN：既防止伪造用户名，也避免对已断开的连接报错
		online := map[string]bool{}
		for _, u := range ParseStatusLog(svc) {
			online[u.Username] = true
		}
		seen := map[string]bool{}
		names := []string{}
		for _, cn := range groups[svc] {
			if seen[cn] {
				continue
			}
			seen[cn] = true
			if !online[cn] {
				res.NotOnline = append(res.NotOnline, svc+"/"+cn)
				continue
			}
			if _, err := formatKillCommand(cn); err != nil {
				res.Failed = append(res.Failed, svc+"/"+cn+": "+err.Error())
				continue
			}
			names = append(names, cn)
		}
		if len(names) == 0 {
			continue
		}
		kicked, failed, err := kickOnInstance(svc, names)
		res.Kicked += kicked
		res.Failed = append(res.Failed, failed...)
		if err != nil {
			res.Failed = append(res.Failed, svc+": "+err.Error())
		}
	}
	return res
}

// kickOnInstance 在一个管理连接里连续下发多条 kill 指令（管理接口只支持单客户端）。
func kickOnInstance(svc string, names []string) (kicked int, failed []string, err error) {
	sock := managementSocket(svc)
	if _, e := os.Stat(sock); e != nil {
		return 0, nil, fmt.Errorf("实例未启用管理接口，请重启该实例后重试")
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return 0, nil, fmt.Errorf("连接管理接口失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	failed = []string{}
	for _, cn := range names {
		cmd, _ := formatKillCommand(cn)
		if _, e := io.WriteString(conn, cmd+"\n"); e != nil {
			return kicked, failed, fmt.Errorf("发送指令失败: %w", e)
		}
		replied, ok := readKillReply(r)
		if replied && !ok {
			failed = append(failed, svc+"/"+cn+": 管理接口拒绝")
			continue
		}
		kicked++
	}
	_, _ = io.WriteString(conn, "quit\n")
	return kicked, failed, nil
}

// formatKillCommand 生成管理指令；CN 来自证书，禁止换行以免注入额外命令。
func formatKillCommand(cn string) (string, error) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "", fmt.Errorf("用户名为空")
	}
	if strings.ContainsAny(cn, "\r\n\x00") {
		return "", fmt.Errorf("用户名含非法字符")
	}
	return "kill " + cn, nil
}

// readKillReply 读取一条指令的响应。OpenVPN 对 kill 返回 SUCCESS:/ERROR:，
// 期间可能夹杂 >INFO: 等异步通知；读不到明确响应时按"指令已下发"处理。
func readKillReply(r *bufio.Reader) (replied bool, success bool) {
	for i := 0; i < 12; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return false, true
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") {
			continue
		}
		if strings.HasPrefix(line, "SUCCESS:") {
			return true, true
		}
		if strings.HasPrefix(line, "ERROR:") {
			return true, false
		}
	}
	return false, true
}
