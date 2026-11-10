// Package vpn 登录别名解析：配置下发（handler.LDAPProfile）与 OpenVPN auth-verify 共用。
//
// 需求：默认只允许短账号登录；管理员开启后，同一个账号还能用邮箱 / UPN(DN) 形态登录。
// 别名在服务端解析成真实的 account.username，后续查账号、LDAP 绑定、签发配置和
// auth-verify 全部使用真实用户名，因此 LDAP 搜索过滤器保持 (uid=%s) 即可，客户端零改动。
package vpn

import (
	"database/sql"
	"strings"
)

const (
	// SetAliasMail 允许用 account.email 作为登录名（默认关闭）。
	SetAliasMail = "login_alias_mail"
	// SetAliasUPN 允许用 account.login_aliases 里的 UPN/DN 作为登录名（默认关闭）。
	SetAliasUPN = "login_alias_upn"
)

// aliasNameValid 与 handler.validName 使用同一字符集，避免别名绕过用户名校验。
// 字母数字 _ . - @，长度 1..64（与 X.509 CN 上限一致）。
func aliasNameValid(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-' || c == '@') {
			return false
		}
	}
	return true
}

func aliasSettingOn(d *sql.DB, key string) bool {
	var v string
	return d.QueryRow(`SELECT v FROM settings WHERE k=?`, key).Scan(&v) == nil && v == "1"
}

// uniqueAliasOwner 返回唯一命中的 VPN 用户名。0 条或多条都视为不可用：
// 多个账号共用同一邮箱/UPN 时拒绝登录，避免误登到别人的账号。
func uniqueAliasOwner(d *sql.DB, query, arg string) (string, bool) {
	rows, err := d.Query(query, arg)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	var name string
	n := 0
	for rows.Next() {
		var x string
		if rows.Scan(&x) == nil {
			name = x
			n++
		}
	}
	return name, n == 1
}

// ResolveLoginName 把客户端输入的登录标识解析成 account.username。
//
//   - 精确匹配短账号：始终允许（默认行为，不受开关影响）。
//   - 邮箱别名：需开启 login_alias_mail，按 account.email 忽略大小写精确匹配。
//   - UPN / DN 别名：需开启 login_alias_upn，按 account.login_aliases 逗号列表精确匹配。
//
// 只接受含 @ 的别名；歧义、禁用账号、未开启的方式一律拒绝，失败时安全降级为「只允许短账号」。
func ResolveLoginName(d *sql.DB, input string) (string, bool) {
	name := strings.TrimSpace(input)
	if d == nil || !aliasNameValid(name) {
		return "", false
	}
	// 短账号永远可用；这里不检查 status，后续两处调用方都会做启用/过期校验。
	if real, ok := uniqueAliasOwner(d, `SELECT username FROM account WHERE username=?`, name); ok {
		return real, true
	}
	if !strings.Contains(name, "@") {
		return "", false
	}
	lower := strings.ToLower(name)
	// 显式登录别名优先于联系邮箱：多个账号共用同一 email 时，管理员在
	// login_aliases 里明确指定的映射仍然生效（短账号与 DN 常无字符串对应关系）。
	if aliasSettingOn(d, SetAliasUPN) {
		// instr 是字面匹配，不会把别名里的 _ 当成 LIKE 通配符。
		if real, ok := uniqueAliasOwner(d,
			`SELECT username FROM account WHERE status=1 AND
			 instr(','||lower(COALESCE(login_aliases,''))||',', ','||?||',')>0`, lower); ok {
			return real, true
		}
	}
	if aliasSettingOn(d, SetAliasMail) {
		if real, ok := uniqueAliasOwner(d,
			`SELECT username FROM account WHERE status=1 AND lower(email)=?`, lower); ok {
			return real, true
		}
	}
	return "", false
}
