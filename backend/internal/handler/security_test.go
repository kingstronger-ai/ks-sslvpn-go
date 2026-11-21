package handler

import (
	"testing"
	"time"
)

// TestSafeUpdateRef 验证升级源/升级包引用：拒绝明文 http，放行 https / 本地绝对路径。
func TestSafeUpdateRef(t *testing.T) {
	for _, bad := range []string{
		"http://example.com/version.json",
		"HTTP://example.com/x.tar.gz",
		"https:///path", // 无主机
		"relative/path",
		"",
	} {
		if err := safeUpdateRef(bad); err == nil {
			t.Errorf("应拒绝不安全引用 %q", bad)
		}
	}
	for _, good := range []string{
		"https://raw.githubusercontent.com/x/version.json",
		"https://gitee.com/x/releases/download/v1/pkg.tar.gz",
		"/opt/sslvpn-upgrade/packages/x.tar.gz",
		"file:///var/lib/sslvpn/upgrade/version.json",
	} {
		if err := safeUpdateRef(good); err != nil {
			t.Errorf("应放行安全引用 %q: %v", good, err)
		}
	}
}

// TestCodeAttemptLock IP+target 双维度：连续失败达到阈值锁定，清晰的维度不受牵连。
func TestCodeAttemptLock(t *testing.T) {
	ipKey, tKey := "ip:1.2.3.4", "t:admin@example.com"
	codeClear(ipKey, tKey)
	defer codeClear(ipKey, tKey)

	for i := 0; i < codeMaxFails-1; i++ {
		codeFail(ipKey, tKey)
	}
	if codeLocked(ipKey, tKey) {
		t.Fatal("未达阈值不应锁定")
	}
	codeFail(ipKey, tKey) // 第 5 次触发锁定
	if !codeLocked(ipKey, tKey) {
		t.Fatal("达到失败阈值应锁定")
	}
	// 另一个 target 的相同 IP 也被 ip 维度锁定（符合预期：该 IP 已被标记）
	if !codeLocked("ip:1.2.3.4", "t:other@example.com") {
		t.Fatal("IP 维度命中应锁定")
	}
	// 完全不同的 IP 不受影响
	if codeLocked("ip:9.9.9.9", "t:other@example.com") {
		t.Fatal("无关 IP 不应被锁定")
	}
	// 清除后解锁
	codeClear(ipKey, tKey, "ip:1.2.3.4")
	if codeLocked(ipKey, tKey) {
		t.Fatal("清除后应解锁")
	}
}

// TestCanSendCode 同 target 60 秒冷却，防邮件轰炸。
func TestCanSendCode(t *testing.T) {
	target := "cooldown_test@example.com"
	codeClear("send:" + target)
	defer codeClear("send:" + target)

	if !canSendCode(target) {
		t.Fatal("首次发码应允许")
	}
	if canSendCode(target) {
		t.Fatal("冷却期内重复发码应被拒绝")
	}
	// 模拟时间流逝：直接改写 lastSent
	codeAttempts.Lock()
	codeAttempts.m["send:"+target].lastSent = time.Now().Add(-codeSendInterval - time.Second)
	codeAttempts.Unlock()
	if !canSendCode(target) {
		t.Fatal("超过冷却期应允许再次发码")
	}
}

// TestNormalizeExpireDate 到期日期：空=永久，YYYY-MM-DD 规范化，其它格式拒绝。
func TestNormalizeExpireDate(t *testing.T) {
	if got, ok := normalizeExpireDate(""); !ok || got != "" {
		t.Fatalf("空应为永久: %q %v", got, ok)
	}
	if got, ok := normalizeExpireDate("  2030-01-02  "); !ok || got != "2030-01-02" {
		t.Fatalf("合法日期应规范化: %q %v", got, ok)
	}
	for _, bad := range []string{
		"2030/01/02", "<script>alert(1)</script>", "2026-13-01", "abc", "2030-1-2x",
	} {
		if _, ok := normalizeExpireDate(bad); ok {
			t.Errorf("非法日期应拒绝: %q", bad)
		}
	}
}
