package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sslvpn/internal/db"
)

// uniqueRemote 为每个子请求生成不同的远端地址，避免限流计数串扰。
func uniqueRemote() string {
	n := time.Now().UnixNano()
	return fmt.Sprintf("10.%d.%d.%d:5555", (n/65536)%255, (n/256)%255, n%255)
}

// seedToken 直接落库一条 token（校验层测试用），返回明文与 id。
func seedToken(t *testing.T, name, scope string, expiresAt, revoked int64) (plain string, id int64) {
	t.Helper()
	plain, hash, prefix, err := NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO api_token(name,token_hash,prefix,scope,created_by,created_at,expires_at,revoked)
		VALUES(?,?,?,?,?,?,?,?)`, name, hash, prefix, scope, "seed_admin", time.Now().Unix(), expiresAt, revoked)
	if err != nil {
		t.Fatal(err)
	}
	id, _ = res.LastInsertId()
	t.Cleanup(func() { _, _ = db.DB.Exec(`DELETE FROM api_token WHERE id=?`, id) })
	return plain, id
}

func newBearerRequest(method, path, token, remote string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// 生成规则：格式、长度、唯一性；库中只存 hash，prefix 取前 12 字符。
func TestNewAPITokenFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		plain, hash, prefix, err := NewAPIToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(plain, APITokenPrefix) || len(plain) != 49 {
			t.Fatalf("明文格式应为 ksvpn_ + 43 位 base64url，得到 %q (len=%d)", plain, len(plain))
		}
		if strings.Contains(plain, "=") {
			t.Fatalf("base64url 不应带 padding: %q", plain)
		}
		if hash != HashAPIToken(plain) || hash == plain {
			t.Fatal("hash 必须是明文的 sha256，且不能等于明文")
		}
		if prefix != plain[:APITokenPrefixLen] || len(prefix) != 12 {
			t.Fatalf("prefix 应取明文前 12 字符，得到 %q", prefix)
		}
		if seen[plain] || seen[hash] {
			t.Fatal("随机 token 不应重复")
		}
		seen[plain], seen[hash] = true, true
	}
}

// 校验：过期 / revoked / 错误 token 一律拒绝；成功后容错更新 last_used_at。
func TestAuthenticateTokenExpiryRevokedAndLastUsed(t *testing.T) {
	now := time.Now().Unix()
	valid, id := seedToken(t, "token_valid", TokenScopeRead, 0, 0)
	_, _ = db.DB.Exec(`UPDATE api_token SET last_used_at=0 WHERE id=?`, id)
	expired, _ := seedToken(t, "token_expired", TokenScopeRead, now-1, 0)
	revoked, _ := seedToken(t, "token_revoked", TokenScopeRead, 0, 1)
	future, _ := seedToken(t, "token_future", TokenScopeWrite, now+3600, 0)

	info, ok := AuthenticateToken(valid)
	if !ok || info.Name != "token_valid" || info.Scope != TokenScopeRead || info.CreatedBy != "seed_admin" || info.Prefix != valid[:12] {
		t.Fatalf("有效 token 应校验通过并携带元数据: %+v ok=%v", info, ok)
	}
	var lastUsed int64
	if err := db.DB.QueryRow(`SELECT last_used_at FROM api_token WHERE id=?`, id).Scan(&lastUsed); err != nil || lastUsed <= 0 {
		t.Fatalf("认证成功后应更新 last_used_at: %d err=%v", lastUsed, err)
	}
	for _, bad := range []string{expired, revoked, "ksvpn_" + strings.Repeat("A", 43), "not-a-token", ""} {
		if _, ok := AuthenticateToken(bad); ok {
			t.Fatalf("无效 token 不应通过: %q", bad)
		}
	}
	if _, ok := AuthenticateToken(future); !ok {
		t.Fatal("未到期的 write token 应校验通过")
	}
}

// TokenAuth 的 scope 隔离与 context 注入；失败返回 HTTP 401 与约定 JSON。
func TestTokenAuthScopeAndContext(t *testing.T) {
	readToken, _ := seedToken(t, "token_read_only", TokenScopeRead, 0, 0)
	writeToken, _ := seedToken(t, "token_write", TokenScopeWrite, 0, 0)
	seenInfo := TokenInfo{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("成功校验后 context 中应有 TokenInfo")
		}
		seenInfo = info
		w.WriteHeader(http.StatusOK)
	})
	assertStatus := func(t *testing.T, token, scope string, want int) {
		t.Helper()
		rr := httptest.NewRecorder()
		TokenAuth(next, scope).ServeHTTP(rr, newBearerRequest(http.MethodGet, "/api/v1/x", token, uniqueRemote()))
		if rr.Code != want {
			t.Fatalf("scope=%s token=%q: 期望 HTTP %d，实际 %d，body=%s", scope, token[:min(12, len(token))], want, rr.Code, rr.Body.String())
		}
		if want == http.StatusUnauthorized && !strings.Contains(rr.Body.String(), `"code":401`) ||
			want == http.StatusUnauthorized && !strings.Contains(rr.Body.String(), "API Token 无效或权限不足") {
			t.Fatalf("401 响应体不符: %s", rr.Body.String())
		}
	}
	// 社区版：write Token 在任意鉴权入口都降级为 read，不能获得写权限。
	assertStatus(t, readToken, TokenScopeWrite, http.StatusUnauthorized)
	assertStatus(t, writeToken, TokenScopeWrite, http.StatusUnauthorized)
	assertStatus(t, readToken, TokenScopeRead, http.StatusOK)
	assertStatus(t, writeToken, TokenScopeRead, http.StatusOK)
	assertStatus(t, "", TokenScopeRead, http.StatusUnauthorized)
	if seenInfo.Scope != TokenScopeRead {
		t.Fatalf("context 中的 scope 应为最后一次成功请求的 read，实际 %q", seenInfo.Scope)
	}
}

// TokenAuthDispatch：仅 Bearer ksvpn_ 走 token 校验；其余原样落 fallback（继续 session 认证）。
func TestTokenAuthDispatch(t *testing.T) {
	readToken, _ := seedToken(t, "dispatch_read", TokenScopeRead, 0, 0)
	writeToken, _ := seedToken(t, "dispatch_write", TokenScopeWrite, 0, 0)
	called := 0
	var got TokenInfo
	var hasInfo bool
	lastScope := ""
	fallback := func(w http.ResponseWriter, r *http.Request) {
		called++
		got, hasInfo = TokenInfoFromContext(r.Context())
		_, _ = w.Write([]byte("fallback"))
	}

	run := func(method, token string, wantStatus int, wantFallback bool) {
		t.Helper()
		called = 0
		got, hasInfo = TokenInfo{}, false
		rr := httptest.NewRecorder()
		TokenAuthDispatch(fallback)(rr, newBearerRequest(method, "/api/v1/x", token, uniqueRemote()))
		if rr.Code != wantStatus {
			t.Fatalf("%s token=%q: 期望 %d，实际 %d (%s)", method, token[:min(12, len(token))], wantStatus, rr.Code, rr.Body.String())
		}
		if wantFallback && (called != 1 || rr.Body.String() != "fallback") {
			t.Fatal("应原样调用 fallback")
		}
		if !wantFallback && called != 0 {
			t.Fatal("校验失败时不应调用 fallback")
		}
		if wantFallback && token != "" && strings.HasPrefix(token, APITokenPrefix) && !hasInfo {
			t.Fatal("token 路径通过时应注入 TokenInfo")
		}
		if wantFallback && hasInfo {
			lastScope = got.Scope
		}
	}

	run(http.MethodGet, "", http.StatusOK, true)                      // 无 token → session 路径
	run(http.MethodGet, "old-session-token", http.StatusOK, true)     // Bearer 非 ksvpn_ → session 路径
	run(http.MethodGet, readToken, http.StatusOK, true)               // GET + read → 通过
	run(http.MethodHead, readToken, http.StatusOK, true)              // HEAD + read → 通过
	run(http.MethodPost, readToken, http.StatusUnauthorized, false)   // POST + read → 拒绝
	run(http.MethodDelete, readToken, http.StatusUnauthorized, false) // DELETE + read → 拒绝
	// 社区版（测试环境无许可）：write Token 在鉴权层即降级为 read，
	// 通用 API 写方法与 MCP 写工具使用同一套口径，不能二选一绕过。
	run(http.MethodGet, writeToken, http.StatusOK, true) // GET + write → 通过（降级后 read）
	run(http.MethodPost, writeToken, http.StatusUnauthorized, false)
	run(http.MethodGet, "ksvpn_badbadbadbadbadbadbadbadbadbad", http.StatusUnauthorized, false)
	if lastScope != TokenScopeRead {
		t.Fatalf("社区版成功请求注入的 scope 应为 read（write 被降级），实际 %q", lastScope)
	}
	if got := EffectiveAPITokenScope(TokenInfo{Scope: TokenScopeWrite}); got != TokenScopeRead {
		t.Fatalf("社区版 write 应降级为 read，实际 %q", got)
	}
}

// 同 IP 连续失败 10 次后锁定 10min；成功后清零。
func TestTokenFailRateLimit(t *testing.T) {
	ip := "192.0.2.77"
	t.Cleanup(func() {
		tokenFailures.Lock()
		delete(tokenFailures.m, ip)
		tokenFailures.Unlock()
	})
	token, _ := seedToken(t, "ratelimit_token", TokenScopeRead, 0, 0)
	for i := 0; i < tokenMaxFails; i++ {
		recordTokenFail(ip)
	}
	if !tokenIPLocked(ip) {
		t.Fatal("连续 10 次失败后该 IP 应被锁定")
	}
	r := newBearerRequest(http.MethodGet, "/api/v1/x", token, ip+":5555")
	rr := httptest.NewRecorder()
	TokenAuthDispatch(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("锁定期内即使 token 有效也应拒绝，实际 %d", rr.Code)
	}
	clearTokenFail(ip)
	if tokenIPLocked(ip) {
		t.Fatal("清零后应解除锁定")
	}
}

// 直接验证 context 取值不与其他 context key 冲突（空 context 返回 false）。
func TestTokenInfoFromContextEmpty(t *testing.T) {
	if _, ok := TokenInfoFromContext(context.Background()); ok {
		t.Fatal("空 context 不应返回 TokenInfo")
	}
}
