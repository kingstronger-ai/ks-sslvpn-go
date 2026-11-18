// Package ldaputil 提供 handler 与 vpn 两个包共用的 LDAP 停用判定逻辑。
// AD 域与 OpenLDAP/go-ldap-admin 的停用机制不同，这里统一兼容。
package ldaputil

import (
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// DisabledAttrs 判定停用需要额外读取的 LDAP 属性。
//
// 覆盖三类目录：
//   - Windows AD：userAccountControl（禁用位/锁定位）、accountExpires（账号过期）、
//     lockoutTime（锁定）、msDS-UserAccountDisabled（AD 计算属性）
//   - OpenLDAP ppolicy：pwdAccountLockedTime
//   - 389DS：nsAccountLock
//   - 自定义：accountStatus / employeeStatus / enabled
var DisabledAttrs = []string{
	"userAccountControl", "accountExpires", "lockoutTime", "msDS-UserAccountDisabled",
	"pwdAccountLockedTime", "nsAccountLock",
	"shadowExpire", "accountStatus", "employeeStatus", "enabled",
}

// fileTimeNever 是 AD 表示"永不过期/未锁定"的哨兵值。
const (
	fileTimeNever     int64 = 9223372036854775807
	fileTimeUnixEpoch int64 = 11644473600 // 1601-01-01 → 1970-01-01 的秒数
)

// adFileTimeExpired 判断 AD FILETIME（100ns since 1601-01-01）是否已过期。
// 0 与 fileTimeNever 表示永不过期；解析失败/负数保守视为未过期，避免误禁用。
func adFileTimeExpired(v string, now time.Time) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n == fileTimeNever {
		return false
	}
	sec := n/10000000 - fileTimeUnixEpoch
	return time.Unix(sec, 0).Before(now)
}

// EntryDisabled 判断一个 LDAP 条目是否被属性标记为停用。
// 未命中任何属性视为启用，交由上层"账号是否还在目录中"的存在性判定处理
// （go-ldap-admin 的停用即删号，这类账号不会出现在查询结果里）。
func EntryDisabled(e *goldap.Entry) bool {
	if e == nil {
		return false
	}
	now := time.Now()

	// Windows AD：userAccountControl 位掩码。
	// 0x2 = ACCOUNTDISABLE（如 514 = 普通用户+禁用），0x10 = LOCKOUT。
	if v := strings.TrimSpace(e.GetAttributeValue("userAccountControl")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n&(0x2|0x10) != 0 {
			return true
		}
	}
	// Windows AD：账号过期时间（FILETIME）。0 / 9223372036854775807 表示永不过期。
	if adFileTimeExpired(e.GetAttributeValue("accountExpires"), now) {
		return true
	}
	// Windows AD：锁定时间 > 0 表示处于锁定状态（2008+ 解锁后清零）。
	if v := strings.TrimSpace(e.GetAttributeValue("lockoutTime")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n != fileTimeNever {
			return true
		}
	}
	// Windows AD：计算属性 TRUE 表示禁用（2008+，与 UAC 禁用位等价）。
	if strings.EqualFold(strings.TrimSpace(e.GetAttributeValue("msDS-UserAccountDisabled")), "true") {
		return true
	}
	// OpenLDAP ppolicy：pwdAccountLockedTime 非空即锁定；000001010000Z 是"从不锁定"哨兵值。
	if v := strings.TrimSpace(e.GetAttributeValue("pwdAccountLockedTime")); v != "" && v != "000001010000Z" {
		return true
	}
	// 389DS：nsAccountLock=TRUE。
	if strings.EqualFold(strings.TrimSpace(e.GetAttributeValue("nsAccountLock")), "true") {
		return true
	}
	// 自定义状态属性。
	for _, k := range []string{"accountStatus", "employeeStatus", "enabled"} {
		v := strings.ToLower(strings.TrimSpace(e.GetAttributeValue(k)))
		switch v {
		case "disabled", "inactive", "0", "false", "no", "locked":
			return true
		}
	}
	return false
}

// UsernameAttr 从登录过滤器中提取用户名属性名。
// 支持 (uid=%s)、(sAMAccountName=%s)、(mail=%s) 以及 AD 常见的复合过滤器
// (&(objectClass=user)(sAMAccountName=%s))、(|(uid=%s)(mail=%s))。
// 取 %s 前紧邻的 "=" 左侧属性名；解析失败回退 uid。
func UsernameAttr(filter string) string {
	f := strings.TrimSpace(filter)
	i := strings.Index(f, "%s")
	if i < 0 {
		return "uid"
	}
	prefix := f[:i]
	eq := strings.LastIndex(prefix, "=")
	if eq < 0 {
		return "uid"
	}
	j := eq - 1
	for j >= 0 {
		c := prefix[j]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			j--
			continue
		}
		break
	}
	attr := prefix[j+1 : eq]
	if attr == "" || strings.ContainsAny(attr, "()&|!") {
		return "uid"
	}
	return attr
}
