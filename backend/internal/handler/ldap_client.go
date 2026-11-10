// LDAP 客户端封装（go-ldap）
package handler

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

func tlsCfg() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // 内网自签场景
}

type ldapClient struct {
	conn     *goldap.Conn
	baseDN   string
	ou       string
	filter   string
	bindDN   string
	bindPass string
}

func newLDAPClient(server string, port int, bindDN, bindPass, baseDN, ou, filter string) (ldapClient, error) {
	scheme := "ldap://"
	if port == 636 {
		scheme = "ldaps://"
	}
	host := strings.TrimSpace(server)
	// 兼容填写完整 URL：ldap://host[:port] / ldaps://host[:port]
	if i := strings.Index(host, "://"); i >= 0 {
		if strings.HasPrefix(strings.ToLower(host[:i]), "ldaps") {
			scheme = "ldaps://"
		}
		host = host[i+3:]
	}
	host = strings.TrimSuffix(host, "/")
	// 地址内嵌端口则以地址为准
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		host = h
		if n, cerr := strconv.Atoi(p); cerr == nil {
			port = n
		}
	}
	if host == "" {
		return ldapClient{}, fmt.Errorf("LDAP 服务器地址为空")
	}
	conn, err := goldap.DialURL(scheme+fmt.Sprintf("%s:%d", host, port), goldap.DialWithTLSConfig(tlsCfg()))
	if err != nil {
		return ldapClient{}, err
	}
	if err := conn.Bind(bindDN, bindPass); err != nil {
		conn.Close()
		return ldapClient{}, fmt.Errorf("管理员绑定失败: %s", err.Error())
	}
	return ldapClient{conn: conn, baseDN: baseDN, ou: ou, filter: filter, bindDN: bindDN, bindPass: bindPass}, nil
}

func (c *ldapClient) Close() { c.conn.Close() }

func (c *ldapClient) searchBase() string {
	if c.ou != "" {
		return fmt.Sprintf("ou=%s,%s", c.ou, c.baseDN)
	}
	return c.baseDN
}

// BindCheck 用管理员查找用户 DN 后以用户密码二次绑定验证
func (c *ldapClient) BindCheck(username, password string) error {
	f := strings.ReplaceAll(c.filter, "%s", username)
	req := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		1, 10, false, f, []string{"dn"}, nil)
	res, err := c.conn.Search(req)
	if err != nil {
		return err
	}
	if len(res.Entries) == 0 {
		// 兜底：在 base_dn 全局搜
		req.BaseDN = c.baseDN
		if res, err = c.conn.Search(req); err != nil || len(res.Entries) == 0 {
			return fmt.Errorf("用户不存在")
		}
	}
	userDN := res.Entries[0].DN
	return c.conn.Bind(userDN, password)
}

// LdapRecord 检索结果（DN + 属性名小写映射）
type LdapRecord struct {
	DN    string
	Attrs map[string]string
}

// SearchFilter 按给定过滤器在搜索基下检索，返回每条记录的指定属性。
// 限制最多取 3 条即可判断是否唯一；ou 下无结果时回退到 base_dn 全库。
func (c *ldapClient) SearchFilter(filter string, attrs ...string) ([]LdapRecord, error) {
	if len(attrs) == 0 {
		attrs = []string{"uid", "cn"}
	}
	run := func(base string) ([]LdapRecord, error) {
		req := goldap.NewSearchRequest(base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			3, 10, false, filter, attrs, nil)
		res, err := c.conn.Search(req)
		if err != nil {
			return nil, err
		}
		out := make([]LdapRecord, 0, len(res.Entries))
		for _, e := range res.Entries {
			rec := LdapRecord{DN: e.DN, Attrs: map[string]string{}}
			for _, a := range attrs {
				if v := e.GetAttributeValue(a); v != "" {
					rec.Attrs[strings.ToLower(a)] = v
				}
			}
			out = append(out, rec)
		}
		return out, nil
	}
	recs, err := run(c.searchBase())
	if err != nil && c.ou != "" {
		return run(c.baseDN)
	}
	if len(recs) == 0 && c.ou != "" {
		return run(c.baseDN)
	}
	return recs, err
}

// LdapUser LDAP 用户明细
type LdapUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// ListUsersDetail 列出用户明细（uid + cn/sn + mail）
func (c *ldapClient) ListUsersDetail() ([]LdapUser, error) {
	attr := "uid"
	f := c.filter
	if i := strings.Index(f, "="); i > 0 && strings.HasPrefix(strings.TrimSpace(f), "(") {
		if k := strings.TrimLeft(strings.Split(f, "=")[0], "(%"); k != "" && k != "uid" {
			attr = strings.TrimPrefix(k, "uid")
		}
	}
	req := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "("+attr+"=*)", []string{attr, "cn", "sn", "mail"}, nil)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	var users []LdapUser
	for _, e := range res.Entries {
		u := e.GetAttributeValue(attr)
		if u == "" {
			continue
		}
		dn := e.GetAttributeValue("cn")
		if dn == "" {
			dn = e.GetAttributeValue("sn")
		}
		users = append(users, LdapUser{Username: u, DisplayName: dn, Email: e.GetAttributeValue("mail")})
	}
	return users, nil
}

// ListUsers 列出用户 uid
func (c *ldapClient) ListUsers() ([]string, error) {
	attr := "uid"
	f := c.filter
	if i := strings.Index(f, "="); i > 0 && strings.HasPrefix(strings.TrimSpace(f), "(") {
		if k := strings.TrimLeft(strings.Split(f, "=")[0], "(%"); k != "" && k != "uid" {
			attr = strings.TrimPrefix(k, "uid")
		}
	}
	req := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "("+attr+"=*)", []string{attr}, nil)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, err
	}
	var users []string
	for _, e := range res.Entries {
		if v := e.GetAttributeValue(attr); v != "" {
			users = append(users, v)
		}
	}
	return users, nil
}
