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
	"strconv"
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
//
// 下线语义：使用 OpenVPN management 的 `client-kill <CID> HALT`，向客户端下发
// HALT 控制消息。客户端收到后注册 SIGTERM 并退出进程，不会自动重连；
// 而旧的 `kill <CN>` 走 RESTART（软 SIGUSR1），保存密码的客户端会自动重连回来，
// 表现为"踢不下去"。CID 通过 `status 3` 实时查询得到，未依赖可能滞后的 status.log。
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
		// 同一实例内去重（同一用户可能开了多条连接，去重后仍会踢掉其全部 CID）
		seen := map[string]bool{}
		names := []string{}
		for _, cn := range groups[svc] {
			if seen[cn] {
				continue
			}
			seen[cn] = true
			names = append(names, cn)
		}
		kicked, failed, offline, err := kickOnInstance(svc, names)
		res.Kicked += kicked
		res.Failed = append(res.Failed, failed...)
		res.NotOnline = append(res.NotOnline, offline...)
		if err != nil {
			res.Failed = append(res.Failed, svc+": "+err.Error())
		}
	}
	return res
}

// kickOnInstance 在一个管理连接内完成：查询 status 3 → 解析 CN→CID → 批量下发 HALT。
// 管理接口只支持单客户端，因此整个流程复用同一个连接，并串行执行。
func kickOnInstance(svc string, names []string) (kicked int, failed, notOnline []string, err error) {
	failed, notOnline = []string{}, []string{}

	sock := managementSocket(svc)
	if _, e := os.Stat(sock); e != nil {
		return 0, failed, notOnline, fmt.Errorf("实例未启用管理接口，请重启该实例后重试")
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return 0, failed, notOnline, fmt.Errorf("连接管理接口失败: %w", err)
	}
	defer conn.Close()

	// 查询阶段允许稍长超时（读完整份 status）；写入阶段仅防止 socket 半开挂死。
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	cn2cid, err := readStatus3(conn, r)
	if err != nil {
		return 0, failed, notOnline, fmt.Errorf("查询在线连接失败: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// CN 可能对应多条连接（同一账号多设备登录），全部踢掉。
	cmds := []string{}
	hit := map[string]bool{}
	for _, cn := range names {
		cids, ok := cn2cid[cn]
		if !ok || len(cids) == 0 {
			notOnline = append(notOnline, svc+"/"+cn)
			continue
		}
		okForUser := false
		for _, cid := range cids {
			cmd, ce := formatClientKillCommand(cid)
			if ce != nil {
				failed = append(failed, svc+"/"+cn+": "+ce.Error())
				continue
			}
			cmds = append(cmds, cmd)
			okForUser = true
		}
		if okForUser {
			hit[cn] = true
		}
	}

	for _, cmd := range cmds {
		if _, e := io.WriteString(conn, cmd+"\n"); e != nil {
			return kicked, failed, notOnline, fmt.Errorf("发送指令失败: %w", e)
		}
	}
	_, _ = io.WriteString(conn, "quit\n")
	return len(hit), failed, notOnline, nil
}

// readStatus3 向管理接口发送 `status 3` 并返回 CN → CID 列表。
// status 3 为 tab 分隔（版本 2 为逗号），CLIENT_LIST 行含 "Client ID" 列。
// 列位置从 HEADER 行动态解析，避免不同 OpenVPN 版本列数差异导致取错字段。
func readStatus3(conn net.Conn, r *bufio.Reader) (map[string][]string, error) {
	if _, err := io.WriteString(conn, "status 3\n"); err != nil {
		return nil, err
	}
	lines := []string{}
	for i := 0; i < 20000; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		t := strings.TrimRight(line, "\r\n")
		if t == "END" {
			break
		}
		// 跳过连接问候与异步通知（>INFO: / >LOG: / >STATE: 等）
		if t == "" || strings.HasPrefix(t, ">") {
			continue
		}
		lines = append(lines, t)
	}
	return parseStatus3Clients(lines), nil
}

// parseStatus3Clients 解析 status 3 输出，返回证书 CN → CID 列表。
func parseStatus3Clients(lines []string) map[string][]string {
	out := map[string][]string{}
	cnCol, cidCol := 1, 10 // OpenVPN 2.6 默认位置（HEADER 行首列偏移 1）
	for _, ln := range lines {
		sep := "\t"
		if !strings.Contains(ln, "\t") && strings.Contains(ln, ",") {
			sep = ","
		}
		f := strings.Split(ln, sep)
		if len(f) < 2 {
			continue
		}
		if f[0] == "HEADER" && f[1] == "CLIENT_LIST" {
			for i, v := range f {
				switch strings.TrimSpace(v) {
				case "Common Name":
					cnCol = i - 1
				case "Client ID":
					cidCol = i - 1
				}
			}
			continue
		}
		if f[0] != "CLIENT_LIST" || len(f) <= cidCol || len(f) <= cnCol {
			continue
		}
		cn := strings.TrimSpace(f[cnCol])
		cid := strings.TrimSpace(f[cidCol])
		if cn == "" || cid == "" {
			continue
		}
		if _, err := strconv.ParseUint(cid, 10, 64); err != nil {
			continue // CID 必须是数值，避免构造注入指令
		}
		out[cn] = append(out[cn], cid)
	}
	return out
}

// formatClientKillCommand 生成管理指令：client-kill <CID> HALT。
// HALT 使客户端进程退出且不重连；CID 来自 status 3，必须是纯数字，防止命令注入。
func formatClientKillCommand(cid string) (string, error) {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return "", fmt.Errorf("CID 为空")
	}
	if _, err := strconv.ParseUint(cid, 10, 64); err != nil {
		return "", fmt.Errorf("CID 非法")
	}
	return "client-kill " + cid + " HALT", nil
}
