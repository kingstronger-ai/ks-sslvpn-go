// Package fw iptables 防火墙与 SNAT 管理
package fw

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	binIptables = "/usr/sbin/iptables"
	binSave     = "/usr/sbin/netfilter-persistent"
)

func ipt(args ...string) error {
	out, err := exec.Command(binIptables, args...).CombinedOutput()
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

// AddRule 自定义端口规则
func AddRule(port int, proto, action, source string) error {
	j := "ACCEPT"
	if action == "DROP" {
		j = "DROP"
	}
	return ipt("-A", "INPUT", "-s", source, "-p", proto, "--dport", fmt.Sprint(port), "-j", j)
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
