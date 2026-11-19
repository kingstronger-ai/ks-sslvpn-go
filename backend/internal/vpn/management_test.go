package vpn

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatKillCommand(t *testing.T) {
	got, err := formatKillCommand("  alice@example.com  ")
	if err != nil || got != "kill alice@example.com" {
		t.Fatalf("正常 CN 指令错误: %q, %v", got, err)
	}
	for _, bad := range []string{"", "   ", "a\nb", "a\r\nb", "a\x00b"} {
		if _, err := formatKillCommand(bad); err == nil {
			t.Errorf("非法 CN %q 应被拒绝", bad)
		}
	}
}

func TestReadKillReply(t *testing.T) {
	cases := []struct {
		in      string
		replied bool
		ok      bool
	}{
		{">INFO:OpenVPN Management Interface Version 3\nSUCCESS: kill command succeeded\n", true, true},
		{">CLIENT:CONNECT,1,1\nERROR: client not found\n", true, false},
		{">INFO:version\n>LOG:123,I,hello\n", false, true}, // 只有异步通知，视为已下发
	}
	for _, c := range cases {
		r := bufio.NewReader(strings.NewReader(c.in))
		replied, ok := readKillReply(r)
		if replied != c.replied || ok != c.ok {
			t.Errorf("响应解析错误 %q: got (%v,%v), want (%v,%v)", c.in, replied, ok, c.replied, c.ok)
		}
	}
}

// 存量实例只补一次 management 行，且保留原有配置（DNS/域名分流等）
func TestEnsureManagementConfsIdempotent(t *testing.T) {
	oldBase := BaseDir
	dir := t.TempDir()
	BaseDir = dir
	defer func() { BaseDir = oldBase }()

	inst := filepath.Join(dir, "instance", "office")
	if err := os.MkdirAll(inst, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(inst, "server.conf")
	original := "port 1194\npush \"dhcp-option DNS 1.1.1.1\"\n"
	if err := os.WriteFile(conf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := EnsureManagementConfs()
	if err != nil || n != 1 {
		t.Fatalf("首次迁移应改 1 个实例: n=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(conf)
	text := string(b)
	if !strings.Contains(text, "management "+filepath.Join(inst, "mgmt.sock")+" unix") {
		t.Errorf("未写入 management 行: %s", text)
	}
	if !strings.Contains(text, `push "dhcp-option DNS 1.1.1.1"`) {
		t.Errorf("原有配置被破坏: %s", text)
	}

	n, err = EnsureManagementConfs()
	if err != nil || n != 0 {
		t.Fatalf("二次迁移应改 0 个实例: n=%d err=%v", n, err)
	}
	b2, _ := os.ReadFile(conf)
	if string(b2) != text {
		t.Errorf("重复迁移不应改动配置")
	}
}
