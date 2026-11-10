// LDAP 认证（vpn 包内实现：auth-verify 子命令进程可独立调用）
package vpn

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
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
	var bindDN, bindPass, baseDN, ou, filter string
	err = d.QueryRow(`SELECT server,port,bind_dn,bind_pass,base_dn,ou,filter FROM ldap_conf WHERE id=1`).
		Scan(&server, &port, &bindDN, &bindPass, &baseDN, &ou, &filter)
	if err != nil || server == "" {
		return false
	}
	if filter == "" {
		filter = "(uid=%s)"
	}
	// 兼容 "ldap://10.0.0.1"、"ldaps://host:636"、尾部斜杠等写法
	server = normalizeLDAPAddr(server, &port)

	scheme := "ldap://"
	if port == 636 {
		scheme = "ldaps://"
	}
	conn, err := goldap.DialURL(scheme+fmt.Sprintf("%s:%d", server, port),
		goldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.Bind(bindDN, bindPass); err != nil {
		return false
	}

	searchBase := baseDN
	if ou != "" {
		searchBase = fmt.Sprintf("ou=%s,%s", ou, baseDN)
	}
	f := strings.ReplaceAll(filter, "%s", username)
	req := goldap.NewSearchRequest(searchBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		1, 10, false, f, []string{"dn"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		if res, err = conn.Search(goldap.NewSearchRequest(baseDN, goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases, 1, 10, false, f, []string{"dn"}, nil)); err != nil || len(res.Entries) == 0 {
			return false
		}
	}
	return conn.Bind(res.Entries[0].DN, password) == nil
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
