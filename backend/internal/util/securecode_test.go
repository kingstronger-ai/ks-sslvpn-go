package util

import (
	"strings"
	"testing"
)

// TestRandomAlnumCode 验证邮件安全码：长度正确、字符集安全（无易混淆字符）、随机分布。
func TestRandomAlnumCode(t *testing.T) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		code := RandomAlnumCode(8)
		if len(code) != 8 {
			t.Fatalf("长度应为 8，实际 %d: %s", len(code), code)
		}
		for _, c := range code {
			if !strings.ContainsRune(alphabet, c) {
				t.Fatalf("非法/易混淆字符 %q: %s", c, code)
			}
		}
		if seen[code] {
			t.Fatalf("出现重复验证码（随机性异常）: %s", code)
		}
		seen[code] = true
	}
}

// TestRandomAlnumCodeDefaultLen 非正长度回退到 8。
func TestRandomAlnumCodeDefaultLen(t *testing.T) {
	if got := RandomAlnumCode(0); len(got) != 8 {
		t.Fatalf("默认长度应为 8，实际 %d", len(got))
	}
}

// TestHMACSHA256Hex 验证 HMAC 稳定、区分密钥、六十四位 hex。
func TestHMACSHA256Hex(t *testing.T) {
	a := HMACSHA256Hex("key", "code")
	b := HMACSHA256Hex("key", "code")
	if a != b || len(a) != 64 {
		t.Fatalf("HMAC 不稳定或长度异常: %s / %s", a, b)
	}
	if a == HMACSHA256Hex("other", "code") {
		t.Fatal("不同密钥不应产生相同摘要")
	}
	if a == HMACSHA256Hex("key", "code2") {
		t.Fatal("不同明文不应产生相同摘要")
	}
	if a == "code" {
		t.Fatal("库中不应存明文验证码")
	}
}
