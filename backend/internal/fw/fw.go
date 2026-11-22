// Package fw iptables 防火墙与 SNAT 管理
package fw

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

const (
	binIptables = "/usr/sbin/iptables"
	binSave     = "/usr/sbin/netfilter-persistent"
)

// runIPT 是执行 iptables 的唯一入口，抽成变量便于单测覆盖命令构造与错误处理。
var runIPT = func(args ...string) ([]byte, error) {
	return exec.Command(binIptables, args...).CombinedOutput()
}

func ipt(args ...string) error {
	out, err := runIPT(args...)
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OpenPort 放行端口
func OpenPort(port int, proto string) error {
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	if err := ipt("-A", "INPUT", "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT"); err != nil {
		return err
	}
	return persist()
}

// ClosePort 撤销放行
func ClosePort(port int, proto string) error {
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	if err := ipt("-D", "INPUT", "-p", proto, "--dport", fmt.Sprint(port), "-j", "ACCEPT"); err != nil {
		// 容忍不存在的规则
		_ = err
	}
	return persist()
}

// normalizeRule 校验并归一化自定义规则参数；所有进入 exec.Command 的参数都必须经过这里。
func normalizeRule(port int, proto, action, source string) (string, string, string, error) {
	if port < 1 || port > 65535 {
		return "", "", "", fmt.Errorf("port 必须在 1-65535 之间: %d", port)
	}
	switch proto {
	case "tcp", "udp":
	case "both":
		proto = "tcp" // 与 handler.FWAddRule 的归一化保持一致
	default:
		return "", "", "", fmt.Errorf("proto 仅支持 tcp/udp/both: %q", proto)
	}
	if action != "ACCEPT" && action != "DROP" {
		return "", "", "", fmt.Errorf("action 仅支持 ACCEPT/DROP: %q", action)
	}
	if source == "" {
		source = "0.0.0.0/0" // 与 handler.FWAddRule 的默认值保持一致
	}
	if net.ParseIP(source) == nil {
		if _, _, err := net.ParseCIDR(source); err != nil {
			return "", "", "", fmt.Errorf("source 必须是 IP 或 CIDR: %q", source)
		}
	}
	return proto, action, source, nil
}

// ruleArgs 按 AddRule 的固定顺序构造 iptables 参数：
// <op> INPUT -s <source> -p <proto> --dport <port> -j <ACCEPT|DROP>。
// -D 必须与 -A 使用完全相同的匹配条件，否则无法命中同一条规则。
func ruleArgs(op string, port int, proto, action, source string) ([]string, error) {
	proto, action, source, err := normalizeRule(port, proto, action, source)
	if err != nil {
		return nil, err
	}
	if op != "-A" && op != "-D" {
		return nil, fmt.Errorf("不支持的 iptables 操作: %q", op)
	}
	return []string{op, "INPUT", "-s", source, "-p", proto, "--dport", strconv.Itoa(port), "-j", action}, nil
}

// AddRule 自定义端口规则
func AddRule(port int, proto, action, source string) error {
	args, err := ruleArgs("-A", port, proto, action, source)
	if err != nil {
		return err
	}
	return ipt(args...)
}

// DeleteRule 按 AddRule 相同的参数顺序删除一条自定义端口规则。
// 规则不存在时视为成功（幂等）；其它执行错误原样返回，避免误判删除成功。
func DeleteRule(port int, proto, action, source string) error {
	args, err := ruleArgs("-D", port, proto, action, source)
	if err != nil {
		return err
	}
	out, err := runIPT(args...)
	if err != nil {
		if ruleMissing(out, err) {
			return nil
		}
		return fmt.Errorf("iptables -D 失败: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ruleMissing 仅在 iptables 进程确实执行过、且输出为“无此规则/链”提示时判定规则不存在。
// 命令找不到、权限不足等错误必须上抛，不能被幂等逻辑吞掉。
func ruleMissing(out []byte, err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	msg := strings.ToLower(string(out))
	return strings.Contains(msg, "bad rule") ||
		strings.Contains(msg, "no chain/target/match by that name")
}

// EnableSNAT 配置 NAT 伪装（出站网卡自动探测）
func EnableSNAT(subnet, outIface string) error {
	if err := ipt("-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", outIface, "-j", "MASQUERADE"); err == nil {
		return nil // 已存在
	}
	return ipt("-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", outIface, "-j", "MASQUERADE")
}

// DisableSNAT 移除 NAT 伪装
func DisableSNAT(subnet, outIface string) error {
	return ipt("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", outIface, "-j", "MASQUERADE")
}

// OutInterface 探测默认出站网卡
func OutInterface() string {
	out, err := exec.Command("/usr/sbin/ip", "route").Output()
	if err != nil {
		return "eth0"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "default ") {
			for i, f := range strings.Fields(line) {
				if f == "dev" && i+1 < len(strings.Fields(line)) {
					return strings.Fields(line)[i+1]
				}
			}
		}
	}
	return "eth0"
}

// OutInterfaceIP 探测出站网卡 IP（用于客户端配置 remote 地址）
func OutInterfaceIP() string {
	out, err := exec.Command("/usr/sbin/ip", "-4", "addr", "show", OutInterface()).Output()
	if err != nil {
		return "127.0.0.1"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strings.Split(fields[1], "/")[0]
			}
		}
	}
	return "127.0.0.1"
}

// EnableForward 开启内核路由转发
func EnableForward() error {
	return exec.Command("/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1").Run()
}

// persist 持久化防火墙规则（失败不阻塞，容器内无此工具）
func persist() error {
	_ = exec.Command(binSave, "save").Run()
	return nil
}
