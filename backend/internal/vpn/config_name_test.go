package vpn

import (
	"strings"
	"testing"
)

// TestSafeConfigName 校验交付给路径/命令行/easy-rsa 的名称片段：
// 合法账号放行，路径穿越 / 绝对 / 前导减号 / 非法字符一律拒绝。
func TestSafeConfigName(t *testing.T) {
	good := []string{"alice", "user_01", "a.b-c", "it-gpt@example.com", "A1@B.2", "x"}
	for _, n := range good {
		if !SafeConfigName(n) {
			t.Errorf("合法名称被拒绝: %q", n)
		}
	}
	bad := []string{
		"", "..", ".", "../ca", "../../etc/passwd", "/etc/passwd", "a/b", `a\b`,
		"-pki-dir", "--batch", "a b", "a\n", "a;b", "a$", strings.Repeat("a", 65),
	}
	for _, n := range bad {
		if SafeConfigName(n) {
			t.Errorf("危险名称被放行: %q", n)
		}
	}
}

// TestCcdSafeRaw 验证 CCD Raw 白名单：数据指令保留，可执行/脚本类指令剔除。
func TestCcdSafeRaw(t *testing.T) {
	raw := `# comment
ifconfig-push 10.8.0.2 255.255.255.0
iroute 192.168.1.0 255.255.255.0
push "route 10.0.0.0 255.0.0.0"
push-reset
script-security 2
up /etc/openvpn/hooks/connect.sh
plugin /usr/lib/foo.so
client-connect /tmp/x.sh
tls-verify /tmp/y.sh
`
	out := ccdSafeRaw(raw)
	for _, want := range []string{"# comment", "ifconfig-push", "iroute", `push "route`, "push-reset"} {
		if !strings.Contains(out, want) {
			t.Errorf("应保留 %q，实际输出:\n%s", want, out)
		}
	}
	for _, danger := range []string{"script-security", "up /", "plugin", "client-connect", "tls-verify"} {
		if strings.Contains(out, danger) {
			t.Errorf("危险指令未被过滤 %q，实际输出:\n%s", danger, out)
		}
	}
}
