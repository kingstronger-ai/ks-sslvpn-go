package vpn

import (
	"os"
	"path/filepath"
	"testing"
)

// status.log 解析：在线用户必须带实例名，批量踢人才能按实例分组下发
func TestParseStatusLogWithService(t *testing.T) {
	oldBase := BaseDir
	dir := t.TempDir()
	BaseDir = dir
	defer func() { BaseDir = oldBase }()

	inst := filepath.Join(dir, "instance", "office")
	if err := os.MkdirAll(inst, 0o755); err != nil {
		t.Fatal(err)
	}
	status := `OpenVPN CLIENT LIST
Updated,Wed Nov 18 16:00:00 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,1.2.3.4:4000,100,200,Wed Nov 18 15:00:00 2026
bob@example.com,5.6.7.8:5000,300,400,Wed Nov 18 15:10:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,alice,1.2.3.4:4000,Wed Nov 18 15:59:00 2026
GLOBAL STATS
Max bcast/mcast queue length,0
END
`
	if err := os.WriteFile(filepath.Join(inst, "status.log"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	users := ParseStatusLog("office")
	if len(users) != 2 {
		t.Fatalf("应解析出 2 个在线用户, got %d", len(users))
	}
	for _, u := range users {
		if u.Service != "office" {
			t.Errorf("用户 %s 缺少实例名: %q", u.Username, u.Service)
		}
	}
	if users[0].Username != "alice" || users[0].VirtualIP != "10.8.0.2" || users[0].RealIP != "1.2.3.4:4000" {
		t.Errorf("alice 字段解析错误: %+v", users[0])
	}
	if users[1].Username != "bob@example.com" {
		t.Errorf("邮箱形态用户名解析错误: %+v", users[1])
	}
}

// 实例启动失败时靠日志末尾定位原因，验证截取逻辑
func TestLogTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "stdout.log")
	if err := os.WriteFile(p, []byte("line1\nline2\nline3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := logTail(p, 2); got != "line2 | line3" {
		t.Errorf("末尾两行截取错误: %q", got)
	}
	if got := logTail(p+".missing", 2); got != "(无日志输出)" {
		t.Errorf("日志不存在时应返回占位提示: %q", got)
	}
}
