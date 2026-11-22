package fw

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// stubIPT 替换 iptables 执行入口并记录每次调用的参数，测试结束自动还原。
func stubIPT(t *testing.T, fn func(args ...string) ([]byte, error)) *[][]string {
	t.Helper()
	old := runIPT
	var calls [][]string
	runIPT = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return fn(args...)
	}
	t.Cleanup(func() { runIPT = old })
	return &calls
}

func TestRuleArgsAddDeleteSymmetry(t *testing.T) {
	add, err := ruleArgs("-A", 443, "tcp", "DROP", "10.8.0.0/24")
	if err != nil {
		t.Fatalf("ruleArgs(-A): %v", err)
	}
	wantAdd := []string{"-A", "INPUT", "-s", "10.8.0.0/24", "-p", "tcp", "--dport", "443", "-j", "DROP"}
	if !reflect.DeepEqual(add, wantAdd) {
		t.Fatalf("AddRule 参数顺序不符\n got: %q\nwant: %q", add, wantAdd)
	}
	del, err := ruleArgs("-D", 443, "tcp", "DROP", "10.8.0.0/24")
	if err != nil {
		t.Fatalf("ruleArgs(-D): %v", err)
	}
	wantDel := append([]string{"-D"}, wantAdd[1:]...)
	if !reflect.DeepEqual(del, wantDel) {
		t.Fatalf("-D 参数必须与 -A 完全一致（仅操作不同）\n got: %q\nwant: %q", del, wantDel)
	}

	calls := stubIPT(t, func(args ...string) ([]byte, error) { return nil, nil })
	if err := DeleteRule(443, "tcp", "DROP", "10.8.0.0/24"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], wantDel) {
		t.Fatalf("DeleteRule 下发的命令不符: %q", *calls)
	}
}

func TestRuleArgsValidation(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		proto   string
		action  string
		source  string
		wantErr bool
		wantP   string
		wantJ   string
		wantS   string
	}{
		{"port zero", 0, "tcp", "ACCEPT", "0.0.0.0/0", true, "", "", ""},
		{"port too large", 65536, "tcp", "ACCEPT", "0.0.0.0/0", true, "", "", ""},
		{"port negative", -1, "tcp", "ACCEPT", "0.0.0.0/0", true, "", "", ""},
		{"bad proto", 443, "icmp", "ACCEPT", "0.0.0.0/0", true, "", "", ""},
		{"empty proto", 443, "", "ACCEPT", "0.0.0.0/0", true, "", "", ""},
		{"bad action", 443, "tcp", "REJECT", "0.0.0.0/0", true, "", "", ""},
		{"empty action", 443, "tcp", "", "0.0.0.0/0", true, "", "", ""},
		{"injection source", 443, "tcp", "ACCEPT", "0.0.0.0/0; rm -rf /", true, "", "", ""},
		{"invalid cidr", 443, "tcp", "ACCEPT", "10.0.0.0/99", true, "", "", ""},
		{"garbage source", 443, "tcp", "ACCEPT", "not-an-ip", true, "", "", ""},
		{"plain ip", 443, "tcp", "ACCEPT", "1.2.3.4", false, "tcp", "ACCEPT", "1.2.3.4"},
		{"cidr", 443, "udp", "DROP", "10.0.0.0/8", false, "udp", "DROP", "10.0.0.0/8"},
		{"both normalizes to tcp", 443, "both", "DROP", "10.0.0.0/8", false, "tcp", "DROP", "10.0.0.0/8"},
		{"empty source defaults", 443, "tcp", "ACCEPT", "", false, "tcp", "ACCEPT", "0.0.0.0/0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := ruleArgs("-D", tc.port, tc.proto, tc.action, tc.source)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望校验失败，实际通过: %q", args)
				}
				return
			}
			if err != nil {
				t.Fatalf("合法参数被拒绝: %v", err)
			}
			want := []string{"-D", "INPUT", "-s", tc.wantS, "-p", tc.wantP, "--dport", "443", "-j", tc.wantJ}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("参数不符\n got: %q\nwant: %q", args, want)
			}
		})
	}
	if _, err := ruleArgs("-X", 443, "tcp", "ACCEPT", "0.0.0.0/0"); err == nil {
		t.Fatal("非法 iptables 操作未被拒绝")
	}
}

func TestDeleteRuleRejectsBadInputWithoutExec(t *testing.T) {
	calls := stubIPT(t, func(args ...string) ([]byte, error) { return nil, nil })
	if err := DeleteRule(443, "tcp", "ACCEPT", "0.0.0.0/0 && touch /tmp/pwned"); err == nil {
		t.Fatal("危险 source 未被拒绝")
	}
	if len(*calls) != 0 {
		t.Fatalf("校验失败时不应执行 iptables，实际执行了: %q", *calls)
	}
}

func TestDeleteRuleMissingRuleIsIdempotent(t *testing.T) {
	for _, msg := range []string{
		"iptables: Bad rule (does a matching rule exist in that chain?).",
		"iptables: No chain/target/match by that name.",
	} {
		t.Run(msg, func(t *testing.T) {
			calls := stubIPT(t, func(args ...string) ([]byte, error) {
				return []byte(msg), &exec.ExitError{Stderr: []byte(msg)}
			})
			if err := DeleteRule(443, "tcp", "DROP", "10.8.0.0/24"); err != nil {
				t.Fatalf("规则不存在应视为成功，实际: %v", err)
			}
			if len(*calls) != 1 {
				t.Fatalf("应恰好执行一次 -D，实际: %q", *calls)
			}
		})
	}
}

func TestDeleteRuleSurfacesRealErrors(t *testing.T) {
	cases := []struct {
		name string
		out  []byte
		err  error
	}{
		{"permission denied", []byte("iptables: Permission denied (you must be root)."), &exec.ExitError{Stderr: []byte("permission denied")}},
		{"binary missing", nil, errors.New("exec: /usr/sbin/iptables: executable file not found")},
		{"unexpected output", []byte("iptables: something else went wrong"), &exec.ExitError{Stderr: []byte("something else")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubIPT(t, func(args ...string) ([]byte, error) { return tc.out, tc.err })
			err := DeleteRule(443, "tcp", "DROP", "10.8.0.0/24")
			if err == nil {
				t.Fatal("真实执行错误不应被吞掉")
			}
			if !strings.Contains(err.Error(), "iptables -D") {
				t.Fatalf("错误信息缺少上下文: %v", err)
			}
		})
	}
}
