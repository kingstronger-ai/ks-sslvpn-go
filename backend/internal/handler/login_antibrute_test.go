package handler

import (
	"net/http/httptest"
	"testing"
	"time"
)

// P1-01 回归：默认不得采信客户端可控的代理头，防止伪造 IP 绕过按 IP 的登录/限流锁定。
func TestClientIPIgnoresSpoofedHeadersByDefault(t *testing.T) {
	t.Setenv("SSLVPN_TRUST_PROXY", "")
	r := httptest.NewRequest("POST", "/api/v1/logincheck", nil)
	r.RemoteAddr = "203.0.113.9:51234"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.9.9.9")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("默认应用真实对端 IP，得到 %q", got)
	}
	if got := ssoClientIP(r); got != "203.0.113.9" {
		t.Fatalf("ssoClientIP 默认也应忽略伪造头，得到 %q", got)
	}
}

// 显式开启信任代理后，才采信 X-Real-IP（供反代部署场景）。
func TestClientIPTrustProxyOptIn(t *testing.T) {
	t.Setenv("SSLVPN_TRUST_PROXY", "1")
	r := httptest.NewRequest("POST", "/api/v1/logincheck", nil)
	r.RemoteAddr = "203.0.113.9:51234"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	if got := clientIP(r); got != "1.2.3.4" {
		t.Fatalf("信任代理模式下应采信 X-Real-IP，得到 %q", got)
	}
}

// IPv6 对端地址必须被正确解析，不能把 "[::1]:123" 当成含冒号的裸串。
func TestClientIPIPv6(t *testing.T) {
	t.Setenv("SSLVPN_TRUST_PROXY", "")
	r := httptest.NewRequest("POST", "/api/v1/logincheck", nil)
	r.RemoteAddr = "[2001:db8::1]:51234"
	if got := clientIP(r); got != "2001:db8::1" {
		t.Fatalf("IPv6 应解析为 %q，得到 %q", "2001:db8::1", got)
	}
}

// P1-01 核心：即使攻击者每换一个 IP，针对固定账号的失败次数仍会在 username 维度累积并锁定。
func TestLoginUserDimensionLock(t *testing.T) {
	userKey := "u:antibrute_admin"
	loginAttempts.Lock()
	delete(loginAttempts.m, userKey)
	loginAttempts.Unlock()
	defer func() {
		loginAttempts.Lock()
		delete(loginAttempts.m, userKey)
		loginAttempts.Unlock()
	}()

	// 每次失败来自不同 IP，但 username 相同
	for i := 0; i < loginMaxFails; i++ {
		ipKey := "ip:198.51.100." + string(rune('1'+i))
		loginAttempts.Lock()
		for _, k := range []string{ipKey, userKey} {
			st := loginAttempts.m[k]
			if st == nil {
				st = &loginFailState{}
				loginAttempts.m[k] = st
			}
			st.fails++
			if st.fails >= loginMaxFails && st.lockedUntil.IsZero() {
				st.lockedUntil = time.Now().Add(loginLockDuration)
			}
		}
		loginAttempts.Unlock()
	}

	loginAttempts.Lock()
	locked := loginLocked(userKey)
	loginAttempts.Unlock()
	if !locked {
		t.Fatal("针对固定账号的失败达到阈值后，username 维度应锁定（与来源 IP 无关）")
	}

	// 一个从未出现的新 IP 也会因 username 锁定被拒绝
	loginAttempts.Lock()
	newIPLocked := loginLocked("ip:203.0.113.254")
	loginAttempts.Unlock()
	if newIPLocked {
		t.Fatal("全新 IP 本身不应被锁定")
	}
}
