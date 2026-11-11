package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

// TestMaxUsersPayloadJSON 校验 mu 字段的编解码：
// 带上限时写入 mu，不限制时省略该字段；旧许可串没有 mu，解析后应为 0（不限制）。
func TestMaxUsersPayloadJSON(t *testing.T) {
	raw, err := json.Marshal(Payload{ID: "1", Expire: "2027-12-31", MaxUsers: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"mu":100`) {
		t.Errorf("带用户数上限的许可应写入 mu，got %s", raw)
	}

	raw, err = json.Marshal(Payload{ID: "2", Expire: "2027-12-31"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"mu"`) {
		t.Errorf("不限制用户数时不应写入 mu，got %s", raw)
	}

	// 旧许可串（无 mu）→ 兼容为不限制
	var old Payload
	if err := json.Unmarshal([]byte(`{"id":"1","e":"2027-12-31","ed":"pro"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.MaxUsers != 0 {
		t.Errorf("旧许可串 MaxUsers 应为 0，got %d", old.MaxUsers)
	}
	var limited Payload
	if err := json.Unmarshal([]byte(`{"id":"1","e":"2027-12-31","ed":"pro","mu":50}`), &limited); err != nil {
		t.Fatal(err)
	}
	if limited.MaxUsers != 50 || limited.Tier() != TierPro {
		t.Errorf("带 mu 的许可解析错误: MaxUsers=%d Tier=%s", limited.MaxUsers, limited.Tier())
	}
}

// TestQuotaAllowed 校验配额判断：不限制 / 刚好用满 / 超限 / 批量一次超量。
func TestQuotaAllowed(t *testing.T) {
	cases := []struct {
		limit, used, n int
		want           bool
	}{
		{0, 500, 1, true},    // 不限制
		{-1, 500, 1, true},   // 负值也按不限制
		{100, 0, 1, true},    // 空库
		{100, 99, 1, true},   // 刚好用满
		{100, 100, 1, false}, // 已满
		{100, 98, 5, false},  // 批量一次超量
		{100, 95, 5, true},   // 批量刚好
		{100, 120, 1, false}, // 已超额（换成更小许可）
		{100, 0, 0, true},    // 新增 0 个
	}
	for _, c := range cases {
		if got := quotaAllowed(c.limit, c.used, c.n); got != c.want {
			t.Errorf("quotaAllowed(%d,%d,%d)=%v, want %v", c.limit, c.used, c.n, got, c.want)
		}
	}
}

// TestSignWritesMaxUsers 真实走一遍 Sign()，确认签发出来的许可串里
// 带上限时含 mu，不限制时完全没有该字段（旧许可串形态）。
func TestSignWritesMaxUsers(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	payloadOf := func(p Payload) (Payload, string) {
		tok, err := Sign(p, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(tok, ".")
		if len(parts) != 2 {
			t.Fatalf("许可串格式错误: %s", tok)
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var got Payload
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		return got, string(raw)
	}

	got, raw := payloadOf(Payload{ID: "1", Expire: "2027-12-31", Edition: "pro", MaxUsers: 50})
	if got.MaxUsers != 50 || !strings.Contains(raw, `"mu":50`) {
		t.Errorf("带 -max-users 的许可应写 mu:50，got %s", raw)
	}
	if got.Tier() != TierPro {
		t.Errorf("档位应保持 pro，got %s", got.Tier())
	}

	got, raw = payloadOf(Payload{ID: "2", Expire: "2027-12-31", Edition: "pro"})
	if got.MaxUsers != 0 || strings.Contains(raw, `"mu"`) {
		t.Errorf("不限制用户数时许可不应含 mu，got %s", raw)
	}
}

// TestStatusUserQuotaFields 校验状态里的用户配额字段能正确序列化给前端。
func TestStatusUserQuotaFields(t *testing.T) {
	raw, _ := json.Marshal(Status{State: StateLicensed, MaxUsers: 50, UserCount: 12, UserLeft: 38})
	s := string(raw)
	for _, k := range []string{`"max_users":50`, `"user_count":12`, `"user_left":38`} {
		if !strings.Contains(s, k) {
			t.Errorf("状态缺少 %s，got %s", k, s)
		}
	}
	raw, _ = json.Marshal(Status{State: StateTrial, UserLeft: -1})
	if !strings.Contains(string(raw), `"user_left":-1`) {
		t.Errorf("不限制时 user_left 应为 -1，got %s", raw)
	}
}
