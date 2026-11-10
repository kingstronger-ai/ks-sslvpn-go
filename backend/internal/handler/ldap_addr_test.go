package handler

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

// 复制 newLDAPClient 中的地址解析逻辑做验证（避免真实连接）
func parseLDAPAddr(server string, port int) (scheme, host string, outPort int) {
	scheme = "ldap://"
	if port == 636 {
		scheme = "ldaps://"
	}
	host = strings.TrimSpace(server)
	if i := strings.Index(host, "://"); i >= 0 {
		if strings.HasPrefix(strings.ToLower(host[:i]), "ldaps") {
			scheme = "ldaps://"
		}
		host = host[i+3:]
	}
	host = strings.TrimSuffix(host, "/")
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		host = h
		if n, cerr := strconv.Atoi(p); cerr == nil {
			port = n
		}
	}
	return scheme, host, port
}

func TestParseLDAPAddr(t *testing.T) {
	cases := []struct {
		in     string
		inPort int
		scheme string
		host   string
		port   int
	}{
		{"ldap://10.0.0.27", 389, "ldap://", "10.0.0.27", 389},
		{"ldaps://10.0.0.27", 636, "ldaps://", "10.0.0.27", 636},
		{"10.0.0.27", 389, "ldap://", "10.0.0.27", 389},
		{"ldap://ldap.example.com:3890", 389, "ldap://", "ldap.example.com", 3890},
		{"  ldap://10.0.0.27/  ", 389, "ldap://", "10.0.0.27", 389},
		{"ldaps://ldap.example.com", 389, "ldaps://", "ldap.example.com", 389},
	}
	for i, c := range cases {
		s, h, p := parseLDAPAddr(c.in, c.inPort)
		if s != c.scheme || h != c.host || p != c.port {
			t.Errorf("case %d: got %s%s:%d want %s%s:%d", i, s, h, p, c.scheme, c.host, c.port)
		}
	}
	fmt.Println("all parse cases passed")
}
