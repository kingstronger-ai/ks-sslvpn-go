package vpn

import (
	"os"
	"path/filepath"
	"testing"

	"sslvpn/internal/db"
)

// OpenVPN auth-verify 子进程必须与配置下发链路使用同一套别名解析：
// 客户端把用户输入的登录名写进 auth-user-pass 文件，解析成真实短名后才能查到账号。
func TestVerifyAliasLogin(t *testing.T) {
	clean := func() {
		_, _ = db.DB.Exec(`DELETE FROM account WHERE username IN ('aliasverify','aliaspeer2')`)
		_, _ = db.DB.Exec(`DELETE FROM settings WHERE k IN (?,?)`, SetAliasMail, SetAliasUPN)
	}
	clean()
	t.Cleanup(clean)

	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,email,login_aliases,status,group_id)
		VALUES('aliasverify','Passw0rd123','local','shared@example.com','zhangsan@example.com',1,0)`); err != nil {
		t.Fatal(err)
	}
	// 共用邮箱：只开邮箱开关时不能误登
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,email,status,group_id)
		VALUES('aliaspeer2','Passw0rd123','local','shared@example.com',1,0)`); err != nil {
		t.Fatal(err)
	}

	via := filepath.Join(t.TempDir(), "via")
	write := func(user string) {
		if err := os.WriteFile(via, []byte(user+"\nPassw0rd123\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 默认关闭：别名拒绝
	write("zhangsan@example.com")
	if got := VerifyVPNCredentials(via); got != 1 {
		t.Fatalf("默认关闭时别名应被拒，退出码 %d", got)
	}
	// 开启 UPN/DN：显式别名生效
	db.SetSetting(SetAliasUPN, "1")
	if got := VerifyVPNCredentials(via); got != 0 {
		t.Fatalf("开启 UPN/DN 后别名应认证通过，退出码 %d", got)
	}
	// 关闭后恢复默认
	db.SetSetting(SetAliasUPN, "0")
	if got := VerifyVPNCredentials(via); got != 1 {
		t.Fatalf("关闭开关后别名应重新被拒，退出码 %d", got)
	}
	// 短账号始终可用
	write("aliasverify")
	if got := VerifyVPNCredentials(via); got != 0 {
		t.Fatalf("短账号应始终通过，退出码 %d", got)
	}
}
