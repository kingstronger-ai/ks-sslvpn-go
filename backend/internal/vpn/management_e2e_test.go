package vpn

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// 端到端：模拟 OpenVPN management unix socket，验证跨实例多选批量下发 HALT 指令。
// 服务端需先响应 `status 3`（返回 CLIENT_LIST 含 CID），再接收 client-kill 指令。
// Windows 的 AF_UNIX 要求短绝对路径，故用盘符根下的短目录；Linux/macOS 用 t.TempDir。
func TestKickClientsBatchOverManagementSocket(t *testing.T) {
	oldBase := BaseDir
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		// AF_UNIX 要求短绝对路径：在盘符根下建唯一短目录
		root := filepath.VolumeName(dir) + string(os.PathSeparator)
		short, err := os.MkdirTemp(root, "kst")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(short)
		dir = short
	}
	BaseDir = dir
	defer func() { BaseDir = oldBase }()

	statusHead := "TITLE\tOpenVPN 2.6.12\n" +
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n"

	type fakeServer struct {
		ln   net.Listener
		text string
	}
	makeInstance := func(name, status3 string) *fakeServer {
		inst := filepath.Join(dir, "instance", name)
		if err := os.MkdirAll(inst, 0o755); err != nil {
			t.Fatal(err)
		}
		// 伪装成"已启用管理接口"：socket 文件存在即可被探测到
		ln, err := net.Listen("unix", managementSocket(name))
		if err != nil {
			t.Fatal(err)
		}
		return &fakeServer{ln: ln, text: status3}
	}

	s1 := makeInstance("office", statusHead+"CLIENT_LIST\talice\t1.1.1.1:4000\t10.8.0.2\t\t1\t2\tWed Nov 18 15:00:00 2026\t1\talice\t11\t1\tAES-256-GCM\nEND\n")
	s2 := makeInstance("branch", statusHead+"CLIENT_LIST\tbob\t2.2.2.2:4000\t10.8.0.3\t\t1\t2\tWed Nov 18 15:00:00 2026\t1\tbob\t22\t1\tAES-256-GCM\nEND\n")
	defer s1.ln.Close()
	defer s2.ln.Close()

	got := make(chan string, 16)
	serve := func(s *fakeServer) {
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if line == "quit" {
						return
					}
					if line == "status 3" {
						_, _ = c.Write([]byte(">INFO:OpenVPN Management Interface Version 3\n" + s.text))
						continue
					}
					got <- line
					_, _ = c.Write([]byte("SUCCESS: client-kill command succeeded\n"))
				}
			}(c)
		}
	}
	go serve(s1)
	go serve(s2)

	res := KickClients([]KickTarget{
		{Service: "office", Username: "alice"},
		{Service: "branch", Username: "bob"},
		{Service: "office", Username: "ghost"}, // 不在线
		{Service: "office", Username: "alice"}, // 重复，应去重
	})

	if res.Kicked != 2 {
		t.Errorf("应成功下发 2 人, got %d (%+v)", res.Kicked, res)
	}
	if len(res.NotOnline) != 1 || !strings.Contains(res.NotOnline[0], "ghost") {
		t.Errorf("不在线目标识别错误: %v", res.NotOnline)
	}
	if len(res.Failed) != 0 {
		t.Errorf("不应有失败: %v", res.Failed)
	}

	time.Sleep(100 * time.Millisecond)
	cmds := []string{}
	for len(got) > 0 {
		cmds = append(cmds, <-got)
	}
	sort.Strings(cmds)
	if len(cmds) != 2 || cmds[0] != "client-kill 11 HALT" || cmds[1] != "client-kill 22 HALT" {
		t.Errorf("下发的 HALT 指令错误: %v", cmds)
	}
}
