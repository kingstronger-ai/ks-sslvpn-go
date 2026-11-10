package vpn

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sslvpn/internal/db"
)

// TestMain 整个包共用一个临时库：
// auth-verify 子进程按 SSLVPN_DB 打开库，必须与 db.Open 落到同一个文件，
// 否则各用例各开一个库，认证必然查不到数据。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sslvpn-vpn-test")
	if err != nil {
		panic(err)
	}
	dbFile := filepath.Join(dir, "sslvpn.db")
	os.Setenv("SSLVPN_DATA_DIR", dir)
	os.Setenv("SSLVPN_DB", dbFile)
	os.Setenv("SSLVPN_LOGDIR", filepath.Join(dir, "logs"))
	if err := db.Open(dir); err != nil {
		panic(err)
	}
	code := m.Run()
	if db.DB != nil {
		_ = db.DB.Close()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestDBPathHonorsDataDir 认证子进程必须读主进程同一个库文件
func TestDBPathHonorsDataDir(t *testing.T) {
	t.Setenv("SSLVPN_DB", "")
	t.Setenv("SSLVPN_DATA_DIR", "/var/lib/sslvpn")
	if got := DBPath(); got != "/var/lib/sslvpn/sslvpn.db" {
		t.Fatalf("DBPath() = %q, want /var/lib/sslvpn/sslvpn.db", got)
	}
	t.Setenv("SSLVPN_DATA_DIR", "")
	if got := DBPath(); got != "/var/lib/sslvpn/sslvpn.db" {
		t.Fatalf("默认路径 = %q，应与主进程 defaultDataDir 一致", got)
	}
	t.Setenv("SSLVPN_DB", "/x/custom.db")
	if got := DBPath(); got != "/x/custom.db" {
		t.Fatalf("SSLVPN_DB 未生效: %q", got)
	}
}

// TestVerifyLocalAccount 本地账号认证：正确密码通过，错误密码拒绝
func TestVerifyLocalAccount(t *testing.T) {
	dir := t.TempDir() // 仅用于放 via-file，库用 TestMain 的共享库
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO account(username,password,auth_type,email,group_id,status)
		VALUES('wq','p@ss','local','wq@x.com',0,1)`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"正确密码", "wq\np@ss\n", 0},
		{"错误密码", "wq\nbad\n", 1},
		{"不存在用户", "nobody\nx\n", 1},
	}
	for _, c := range cases {
		vf := filepath.Join(dir, "vp")
		if err := os.WriteFile(vf, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := VerifyVPNCredentials(vf); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}

	// 禁用账号也必须拒绝
	if _, err := db.DB.Exec(`UPDATE account SET status=0 WHERE username='wq'`); err != nil {
		t.Fatal(err)
	}
	vf := filepath.Join(dir, "vp2")
	_ = os.WriteFile(vf, []byte("wq\np@ss\n"), 0o600)
	if got := VerifyVPNCredentials(vf); got != 1 {
		t.Errorf("禁用账号应拒绝, got %d", got)
	}
}

// TestVerifyFeishuToken 飞书一次性口令（FS1.*）走认证回调：有效→通过，重放/过期→拒绝
func TestVerifyFeishuToken(t *testing.T) {
	dir := t.TempDir()
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO account(username,password,auth_type,email,group_id,status)
		VALUES('fsuser','-','feishu','fs@x.com',0,1)`); err != nil {
		t.Fatal(err)
	}

	token := FeishuTokenPrefix + "test-token-abcdefghijklmnop"
	now := time.Now().Unix()
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO sso_token(token_hash,token_id,username,email,method,consumed,created_at,expires_at)
		VALUES(?,?,'fsuser','fs@x.com','feishu',0,?,?)`,
		TokenDigest(token), TokenDigest(token)[:12], now, now+60); err != nil {
		t.Fatal(err)
	}

	write := func(name, pass string) string {
		vf := filepath.Join(dir, name)
		if err := os.WriteFile(vf, []byte("fsuser\n"+pass+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return vf
	}
	if got := VerifyVPNCredentials(write("vf1", token)); got != 0 {
		t.Fatalf("有效口令应通过, got %d", got)
	}
	if got := VerifyVPNCredentials(write("vf2", token)); got != 1 {
		t.Errorf("重放口令必须拒绝, got %d", got)
	}
	// 已过期口令同样拒绝
	old := FeishuTokenPrefix + "expired-token-abcdefghijkl"
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO sso_token(token_hash,token_id,username,email,method,consumed,created_at,expires_at)
		VALUES(?,?,'fsuser','fs@x.com','feishu',0,?,?)`,
		TokenDigest(old), TokenDigest(old)[:12], now-120, now-60); err != nil {
		t.Fatal(err)
	}
	if got := VerifyVPNCredentials(write("vf3", old)); got != 1 {
		t.Errorf("过期口令必须拒绝, got %d", got)
	}
}
