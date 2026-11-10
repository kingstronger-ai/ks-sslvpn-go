package util

import (
	"strings"
	"testing"
)

func TestRandomPassword(t *testing.T) {
	for i := 0; i < 500; i++ {
		p := RandomPassword(12)
		if len(p) != 12 {
			t.Fatalf("长度应为 12，实际 %d: %s", len(p), p)
		}
		var up, low, dig bool
		for _, c := range p {
			switch {
			case strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ", c):
				up = true
			case strings.ContainsRune("abcdefghijkmnopqrstuvwxyz", c):
				low = true
			case strings.ContainsRune("23456789", c):
				dig = true
			default:
				t.Fatalf("出现非法/易混淆字符 %q: %s", c, p)
			}
		}
		if !up || !low || !dig {
			t.Fatalf("缺少字符类别 up=%v low=%v dig=%v: %s", up, low, dig, p)
		}
	}
	// 抽两次不应相同
	if RandomPassword(12) == RandomPassword(12) {
		t.Fatal("两次生成结果相同，随机性异常")
	}
}
