package vpn

import (
	"os"
	"path/filepath"
	"testing"
)

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
