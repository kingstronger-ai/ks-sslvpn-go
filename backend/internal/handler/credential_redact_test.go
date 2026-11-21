package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"sslvpn/internal/db"
)

// P2-04 / F-02 回归：LDAP bind_pass 不得明文回显，且前端留空提交不得清空已存口令。
func TestLdapBindPassNotEchoedAndKeptOnBlank(t *testing.T) {
	const secret = "SuperSecretBindPass123"
	_, err := db.DB.Exec(`INSERT INTO ldap_conf(id,server,port,bind_dn,bind_pass,base_dn,filter,enabled,tls_mode)
		VALUES(1,'ldap://10.0.0.1',389,'cn=admin',?,'dc=example,dc=com','(uid=%s)',1,'insecure')
		ON CONFLICT(id) DO UPDATE SET bind_pass=excluded.bind_pass`, secret)
	if err != nil {
		// 老库可能没有 tls_mode 列，退到最小列集合
		_, err = db.DB.Exec(`INSERT INTO ldap_conf(id,server,port,bind_dn,bind_pass,base_dn,filter,enabled)
			VALUES(1,'ldap://10.0.0.1',389,'cn=admin',?,'dc=example,dc=com','(uid=%s)',1)
			ON CONFLICT(id) DO UPDATE SET bind_pass=excluded.bind_pass`, secret)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`DELETE FROM ldap_conf WHERE id=1`)
	})

	// 1) 读接口不得回传明文口令
	r := httptest.NewRequest("GET", "/api/v1/ldap/get", nil)
	w := httptest.NewRecorder()
	LdapGet(w, r)
	body := w.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("LdapGet 回显了明文 bind_pass：%s", body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	data, _ := out["data"].(map[string]any)
	if data == nil {
		data = out
	}
	if set, ok := data["bind_pass_set"].(bool); !ok || !set {
		t.Fatalf("应返回 bind_pass_set=true：%s", body)
	}
	if _, ok := data["bind_pass"]; ok {
		t.Fatal("响应不应包含 bind_pass 字段")
	}

	// 2) 留空提交后，库里口令保持不变
	payload := `{"server":"ldap://10.0.0.1","port":389,"bind_dn":"cn=admin","bind_pass":"",` +
		`"base_dn":"dc=example,dc=com","filter":"(uid=%s)","enabled":1,"tls_mode":"insecure"}`
	r2 := httptest.NewRequest("POST", "/api/v1/ldap/update", strings.NewReader(payload))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	LdapUpdate(w2, r2)
	if !strings.Contains(w2.Body.String(), `"code":1`) && !strings.Contains(w2.Body.String(), `"code": 1`) {
		t.Fatalf("LdapUpdate 留空提交应成功：%s", w2.Body.String())
	}
	var kept string
	if err := db.DB.QueryRow(`SELECT bind_pass FROM ldap_conf WHERE id=1`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != secret {
		t.Fatalf("留空提交不得清空口令，期望 %q 得到 %q", secret, kept)
	}
}

// P2-04 / F-02 回归：SMTP 口令不得明文回显，留空提交保持原值。
func TestSMTPPassNotEchoedAndKeptOnBlank(t *testing.T) {
	const secret = "SuperSecretSMTPPass123"
	db.SetSetting("smtp", `{"host":"smtp.example.com","port":465,"user":"u@example.com","pass":"`+secret+`","sender":"u@example.com"}`)
	t.Cleanup(func() { db.SetSetting("smtp", "") })

	r := httptest.NewRequest("GET", "/api/v1/system/getEmail", nil)
	w := httptest.NewRecorder()
	SysGetSMTP(w, r)
	body := w.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("SysGetSMTP 回显了明文口令：%s", body)
	}
	if !strings.Contains(body, "pass_set") || !strings.Contains(body, "true") {
		t.Fatalf("应返回 pass_set=true：%s", body)
	}

	payload := `{"host":"smtp.example.com","port":465,"user":"u@example.com","pass":"","sender":"u@example.com"}`
	r2 := httptest.NewRequest("POST", "/api/v1/system/updateEmail", strings.NewReader(payload))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	SysUpdateEmail(w2, r2)
	var kept map[string]any
	_ = json.Unmarshal([]byte(db.GetSetting("smtp")), &kept)
	if kept["pass"] != secret {
		t.Fatalf("留空提交不得清空 SMTP 口令，期望 %q 得到 %v", secret, kept["pass"])
	}
}
