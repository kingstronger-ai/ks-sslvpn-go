// LDAP 客户端封装（go-ldap）
package handler

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"sslvpn/internal/ldaputil"
)

func tlsCfg() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // 内网自签场景
}

type ldapClient struct {
	conn           *goldap.Conn
	baseDN         string
	ou             string
	filter         string
	bindDN         string
	bindPass       string
	disabledFilter string // 可选：命中该过滤器的 LDAP 账号视为停用（保留账号式 OpenLDAP）
}

func newLDAPClient(server string, port int, bindDN, bindPass, baseDN, ou, filter, disabledFilter string) (ldapClient, error) {
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
	return ldapClient{conn: conn, baseDN: baseDN, ou: ou, filter: filter, bindDN: bindDN, bindPass: bindPass, disabledFilter: disabledFilter}, nil
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
	// AD 保留账号式停用：bind 前检查属性标记（UAC 禁用位/账号过期/锁定等），命中直接拒绝。
	if ldaputil.EntryDisabled(res.Entries[0]) {
		return fmt.Errorf("账号已被停用")
	}
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
	Disabled    bool   `json:"disabled"` // LDAP 侧被标记为停用（存在但禁用）
}

// searchAll 用分页搜索突破 AD 默认 1000 条上限；普通 LDAP 亦兼容。
func (c *ldapClient) searchAll(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	return c.conn.SearchWithPaging(req, 500)
}

// ldapEntryDisabled 保留薄包装（包内测试与历史调用沿用），判定统一走 ldaputil。
func ldapEntryDisabled(e *goldap.Entry) bool { return ldaputil.EntryDisabled(e) }

// ListUsersDetail 列出用户明细（用户名 + cn/sn + mail + 停用状态）
func (c *ldapClient) ListUsersDetail() ([]LdapUser, error) {
	attr := ldaputil.UsernameAttr(c.filter)
	attrs := append([]string{attr, "cn", "sn", "mail", "sAMAccountName", "userPrincipalName"}, ldaputil.DisabledAttrs...)
	req := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "("+attr+"=*)", attrs, nil)
	res, err := c.searchAll(req)
	if err != nil {
		return nil, err
	}

	// 自定义停用过滤器：命中该过滤器的账号用户名集合（保留账号式 OpenLDAP/AD 的兜底判定）。
	// 查询失败不阻断主流程；返回属性按所有常见身份字段收集，与主列表用户名比对。
	customDisabled := map[string]bool{}
	if strings.TrimSpace(c.disabledFilter) != "" {
		dreq := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree,
			goldap.NeverDerefAliases, 0, 0, false, c.disabledFilter,
			[]string{"uid", "cn", "sn", "mail", "sAMAccountName", "userPrincipalName"}, nil)
		if dre, derr := c.searchAll(dreq); derr == nil {
			for _, de := range dre.Entries {
				for _, k := range []string{"uid", "sAMAccountName", "userPrincipalName", "mail", "cn", "sn"} {
					if v := de.GetAttributeValue(k); v != "" {
						customDisabled[strings.ToLower(v)] = true
					}
				}
			}
		}
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
		users = append(users, LdapUser{
			Username: u, DisplayName: dn, Email: e.GetAttributeValue("mail"),
			Disabled: ldaputil.EntryDisabled(e) || customDisabled[strings.ToLower(u)] ||
				customDisabled[strings.ToLower(e.GetAttributeValue("sAMAccountName"))] ||
				customDisabled[strings.ToLower(e.GetAttributeValue("userPrincipalName"))],
		})
	}
	return users, nil
}

// ListUsers 列出用户用户名
func (c *ldapClient) ListUsers() ([]string, error) {
	attr := ldaputil.UsernameAttr(c.filter)
	req := goldap.NewSearchRequest(c.searchBase(), goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "("+attr+"=*)", []string{attr}, nil)
	res, err := c.searchAll(req)
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
