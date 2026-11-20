package vpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatClientKillCommand(t *testing.T) {
	got, err := formatClientKillCommand("  12  ")
	if err != nil || got != "client-kill 12 HALT" {
		t.Fatalf("正常 CID 指令错误: %q, %v", got, err)
	}
	for _, bad := range []string{"", "   ", "abc", "1\nclient-kill 2 HALT", "1\r\n2", "-1", "1 2", "1\x00"} {
		if _, err := formatClientKillCommand(bad); err == nil {
			t.Errorf("非法 CID %q 应被拒绝", bad)
		}
	}
}

func TestParseStatus3Clients(t *testing.T) {
	// OpenVPN 2.6 status 3：tab 分隔，CLIENT_LIST 行含 Client ID 列；
	// 同一 CN 可能有多条连接，必须映射到多个 CID。
	in := []string{
		">INFO:OpenVPN Management Interface Version 3", // 问候，应被上层过滤，这里也验证容错
		"TITLE\tOpenVPN 2.6.12",
		"TIME\tWed Nov 18 16:00:00 2026\t1763472000",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
		"CLIENT_LIST\talice\t1.1.1.1:4000\t10.8.0.2\t\t100\t200\tWed Nov 18 15:00:00 2026\t1763468400\talice\t3\t1\tAES-256-GCM",
		"CLIENT_LIST\tbob\t2.2.2.2:4000\t10.8.0.3\t\t10\t20\tWed Nov 18 15:10:00 2026\t1763469000\tbob\t4\t2\tAES-256-GCM",
		"CLIENT_LIST\talice\t1.1.1.1:4001\t10.8.0.4\t\t5\t6\tWed Nov 18 15:20:00 2026\t1763469600\talice\t7\t3\tAES-256-GCM",
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)",
		"ROUTING_TABLE\t10.8.0.2\talice\t1.1.1.1:4000\t1763472000\t1763472000",
		"GLOBAL_STATS\tMax bcast/mcast queue length\t0",
		"END",
	}
	got := parseStatus3Clients(in)
	if len(got["alice"]) != 2 || got["alice"][0] != "3" || got["alice"][1] != "7" {
		t.Errorf("alice 多连接 CID 解析错误: %v", got["alice"])
	}
	if len(got["bob"]) != 1 || got["bob"][0] != "4" {
		t.Errorf("bob CID 解析错误: %v", got["bob"])
	}
	if _, ok := got["END"]; ok {
		t.Errorf("END 不应被解析为用户")
	}
}

func TestParseStatus3ClientsCommaFallback(t *testing.T) {
	// status 2 使用逗号分隔；列头动态解析保证仍能取到 CID。
	in := []string{
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
		"CLIENT_LIST,carol,3.3.3.3:4000,10.8.0.5,,1,2,Wed Nov 18 15:00:00 2026,1763468400,carol,9,1,AES-256-GCM",
	}
	got := parseStatus3Clients(in)
	if len(got["carol"]) != 1 || got["carol"][0] != "9" {
		t.Errorf("逗号分隔解析错误: %v", got)
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
