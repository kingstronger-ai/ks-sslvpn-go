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

// 端到端：模拟 OpenVPN management unix socket，验证跨实例多选批量 kill 指令下发。
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

	makeInstance := func(name string, clients string) net.Listener {
		inst := filepath.Join(dir, "instance", name)
		if err := os.MkdirAll(inst, 0o755); err != nil {
			t.Fatal(err)
		}
		status := "OpenVPN CLIENT LIST\nUpdated,Wed Nov 18 16:00:00 2026\n" +
			"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" + clients +
			"ROUTING TABLE\nVirtual Address,Common Name,Real Address,Last Ref\nGLOBAL STATS\nEND\n"
		if err := os.WriteFile(filepath.Join(inst, "status.log"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		// 伪装成"已启用管理接口"：socket 文件存在即可被 KickClients 探测到
		ln, err := net.Listen("unix", managementSocket(name))
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}

	ln1 := makeInstance("office", "alice,1.1.1.1:4000,1,2,Wed Nov 18 15:00:00 2026\n")
	ln2 := makeInstance("branch", "bob,2.2.2.2:4000,1,2,Wed Nov 18 15:00:00 2026\n")
	defer ln1.Close()
	defer ln2.Close()

	got := make(chan string, 16)
	serve := func(ln net.Listener) {
		for {
			c, err := ln.Accept()
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
					got <- line
					_, _ = c.Write([]byte("SUCCESS: kill command succeeded\n"))
				}
			}(c)
		}
	}
	go serve(ln1)
	go serve(ln2)

	res := KickClients([]KickTarget{
		{Service: "office", Username: "alice"},
		{Service: "branch", Username: "bob"},
		{Service: "office", Username: "ghost"}, // 不在线
		{Service: "office", Username: "alice"}, // 重复，应去重
	})

	if res.Kicked != 2 {
		t.Errorf("应成功下发 2 条, got %d (%+v)", res.Kicked, res)
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
	if len(cmds) != 2 || cmds[0] != "kill alice" || cmds[1] != "kill bob" {
		t.Errorf("下发的指令错误: %v", cmds)
	}
}
