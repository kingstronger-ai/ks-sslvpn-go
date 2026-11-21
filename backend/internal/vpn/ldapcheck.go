// LDAP 认证（vpn 包内实现：auth-verify 子命令进程可独立调用）
package vpn

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"sslvpn/internal/ldaputil"
)

// LDAPBindCheck 从数据库读取 LDAP 配置并校验用户名密码
func LDAPBindCheck(username, password string) bool {
	d, err := sql.Open("sqlite", "file:"+DBPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return false
	}
	defer d.Close()

	var server string
	var port int
	var bindDN, bindPass, baseDN, ou, filter, disabledFilter, tlsMode, caCert, tlsServerName string
	err = d.QueryRow(`SELECT server,port,bind_dn,bind_pass,base_dn,ou,filter,disabled_filter,tls_mode,ca_cert,tls_server_name FROM ldap_conf WHERE id=1`).
		Scan(&server, &port, &bindDN, &bindPass, &baseDN, &ou, &filter, &disabledFilter, &tlsMode, &caCert, &tlsServerName)
	if err != nil || server == "" {
		return false
	}
	if filter == "" {
		filter = "(uid=%s)"
	}
	// 兼容 "ldap://10.0.0.1"、"ldaps://host:636"、尾部斜杠等写法
	serverRaw := server
	server = normalizeLDAPAddr(server, &port)

	scheme := "ldap://"
	if port == 636 || strings.HasPrefix(strings.ToLower(strings.TrimSpace(serverRaw)), "ldaps://") {
		scheme = "ldaps://"
	}
	// 与 handler 路径共用同一套 TLS 规则：明文端口 + 校验模式强制 StartTLS，
	// 避免"以为在校验、实则明文传管理员密码"。
	mode := strings.ToLower(strings.TrimSpace(tlsMode))
	if mode == "" {
		mode = "insecure"
	}
	if mode == "starttls" && scheme == "ldaps://" {
		return false
	}
	cfg, err := ldaputil.TLSConfig(ldaputil.VerifyMode(tlsMode, caCert), caCert, tlsServerName, server)
	if err != nil {
		return false
	}
	conn, err := goldap.DialURL(scheme+fmt.Sprintf("%s:%d", server, port), goldap.DialWithTLSConfig(cfg))
	if err != nil {
		return false
	}
	defer conn.Close()
	if scheme != "ldaps://" && (mode == "system" || mode == "custom" || mode == "starttls") {
		if err := conn.StartTLS(cfg); err != nil {
			return false
		}
	}
	if err := conn.Bind(bindDN, bindPass); err != nil {
		return false
	}

	searchBase := baseDN
	if ou != "" {
		searchBase = fmt.Sprintf("ou=%s,%s", ou, baseDN)
	}
	// 用户名转义，防止 )(&| 等字符篡改过滤器、绕过停用判定。
	f := strings.ReplaceAll(filter, "%s", goldap.EscapeFilter(username))
	attrs := append([]string{"dn"}, ldaputil.DisabledAttrs...)
	// 取全部命中（sizeLimit=0），而非只取首条：目录中同名多条时，停用记录可能排在后面。
	// 与 handler 侧 BindCheck 保持一致：任一命中被标记停用即拒绝。
	req := goldap.NewSearchRequest(searchBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 10, false, f, attrs, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		if res, err = conn.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases, 0, 10, false, f, attrs, nil)); err != nil || len(res.Entries) == 0 {
			return false // 删除型停用：LDAP 里已无此账号，搜不到 DN 直接拒绝
		}
	}
	// 保留账号型停用：任一命中被标记停用（AD UAC 禁用位/账号过期/锁定、ppolicy 等）即拒绝。
	for _, e := range res.Entries {
		if ldaputil.EntryDisabled(e) {
			return false
		}
	}
	// 自定义停用过滤器：命中 DN 集合与任一候选 DN 相等即拒绝（拒绝优先）。
	// 失败时放行，避免因过滤器语法问题误拒所有 LDAP 登录，由同步侧继续维护状态。
	disabledDNs := map[string]bool{}
	if strings.TrimSpace(disabledFilter) != "" {
		if dre, derr := conn.Search(goldap.NewSearchRequest(searchBase, goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases, 0, 10, false, disabledFilter, []string{"dn"}, nil)); derr == nil {
			for _, de := range dre.Entries {
				disabledDNs[strings.ToLower(de.DN)] = true
			}
		}
	}
	// 选定用于 bind 的 DN：必须唯一且未被停用过滤器命中；多条同名且状态冲突按拒绝优先。
	bindDNEntry := ""
	for _, e := range res.Entries {
		if disabledDNs[strings.ToLower(e.DN)] {
			return false
		}
		if bindDNEntry != "" && !strings.EqualFold(bindDNEntry, e.DN) {
			return false // 多个不同 DN 命中同一用户名，无法唯一确定身份，拒绝
		}
		bindDNEntry = e.DN
	}
	if bindDNEntry == "" {
		return false
	}
	return conn.Bind(bindDNEntry, password) == nil
}

// normalizeLDAPAddr 规范化 LDAP 地址：去掉 scheme / 尾部斜杠 / 内嵌端口，返回纯主机名。
// 若地址中带了端口而 port 未单独配置，则回填到 port。
func normalizeLDAPAddr(server string, port *int) string {
	s := strings.TrimSpace(server)
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "ldaps://"):
		s = s[len("ldaps://"):]
		if *port == 0 {
			*port = 636
		}
	case strings.HasPrefix(low, "ldap://"):
		s = s[len("ldap://"):]
	}
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i:], "]") {
		hostPart, portPart := s[:i], s[i+1:]
		if p, err := strconv.Atoi(portPart); err == nil && p > 0 && p < 65536 {
			s = hostPart
			if *port == 0 {
				*port = p
			}
		}
	}
	if *port == 0 {
		*port = 389
	}
	return s
}
