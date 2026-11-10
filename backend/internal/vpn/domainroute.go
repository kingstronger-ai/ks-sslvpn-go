package vpn

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DomainRoute 域名分流规则。
//
// OpenVPN 的路由只认 IP（push "route <net> <mask>"），不认域名。
// 因此后台配置的域名必须先解析成 IPv4，再以 /32 主机路由下发。
// 解析结果由后台定时刷新；IP 变化后需要重启实例（客户端重连）才会生效。
type DomainRoute struct {
	ID         int64  `json:"id"`
	ServiceID  int64  `json:"service_id"`
	Username   string `json:"username"` // 非空=仅该用户（写 CCD，重连生效）；空=实例级（写 server.conf，需重启）
	Domain     string `json:"domain"`
	Note       string `json:"note"`
	Enabled    int    `json:"enabled"`
	IPs        string `json:"ips"`
	ResolvedAt int64  `json:"resolved_at"`
	TTL        int    `json:"ttl"`
	LastError  string `json:"last_error"`
}

// DefaultDomainRouteTTL 默认重新解析间隔（秒）
const DefaultDomainRouteTTL = 300

// domainRe 宽松的域名格式校验（标签 1-63、总长 <=253）
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// NormalizeDomain 规范化域名输入（容忍 http(s)://、路径、端口、大小写、末尾点）
func NormalizeDomain(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	if strings.Contains(s, "*") {
		return "", fmt.Errorf("不支持通配符域名，请填写具体主机名（如 oa.example.com）")
	}
	if net.ParseIP(s) != nil {
		return "", fmt.Errorf("%s 是 IP 地址，请改用「推送路由」配置网段", s)
	}
	if len(s) > 253 || !domainRe.MatchString(s) {
		return "", fmt.Errorf("域名格式不正确：%s", raw)
	}
	return s, nil
}

// lookupIPv4 解析域名（变量化便于测试替换）
var lookupIPv4 = func(ctx context.Context, host string) ([]string, error) {
	ipv4, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ipv4))
	for _, ip := range ipv4 {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out, nil
}

// ResolveDomainIPv4 解析域名，返回去重、按数值排序的 IPv4 列表
func ResolveDomainIPv4(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, err := lookupIPv4(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("解析失败：%v", err)
	}
	ips = dedupeIPv4(ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("没有解析到 IPv4 记录（只有 AAAA/IPv6 时 OpenVPN 无法按域名分流）")
	}
	return ips, nil
}

// dedupeIPv4 去重排序，顺带过滤非法/非 IPv4 值
func dedupeIPv4(ips []string) []string {
	seen := make(map[string]bool, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		seen[ip] = true
		out = append(out, parsed.To4().String())
	}
	sort.Slice(out, func(i, j int) bool {
		return string(net.ParseIP(out[i]).To4()) < string(net.ParseIP(out[j]).To4())
	})
	return out
}

// DomainRouteLines 某实例应额外推送的路由行（"a.b.c.d 255.255.255.255"）
//
// 只返回实例级规则（username 为空）——这类规则写进 server.conf，改动需重启实例。
// 按用户的规则走 CCD（DomainRouteForUser），用户重连即生效，不重启实例。
// service_id=0 的规则对所有实例生效。不加 /32 之外的路由，避免把整段公网拽进 VPN。
func DomainRouteLines(conn *sql.DB, serviceID int64) []string {
	if conn == nil {
		return nil
	}
	rows, err := conn.Query(`SELECT COALESCE(ips,'') FROM domain_route
		WHERE enabled=1 AND COALESCE(username,'')='' AND (service_id=0 OR service_id=?)
		ORDER BY id`, serviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		for _, ip := range strings.Split(raw, ",") {
			ip = strings.TrimSpace(ip)
			parsed := net.ParseIP(ip)
			if ip == "" || seen[ip] || parsed == nil || parsed.To4() == nil {
				continue
			}
			seen[ip] = true
			out = append(out, parsed.To4().String()+" 255.255.255.255")
		}
	}
	return out
}

// AllServiceIDs 全部实例 ID（service_id=0 的规则要展开到每个实例）
func AllServiceIDs(conn *sql.DB) []int64 {
	if conn == nil {
		return nil
	}
	rows, err := conn.Query(`SELECT id FROM service ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// DomainRouteScope 一条规则的作用域：service_id + username（username 为空表示实例级）
type DomainRouteScope struct {
	ServiceID int64  `json:"service_id"`
	Username  string `json:"username"`
}

// RefreshDomainRoutes 重新解析到期（force=true 时全部）的启用规则。
// 返回 IP 发生变化的规则数，以及受影响的作用域列表。
func RefreshDomainRoutes(conn *sql.DB, force bool) (int, []DomainRouteScope, error) {
	if conn == nil {
		return 0, nil, nil
	}
	rows, err := conn.Query(`SELECT id,service_id,COALESCE(username,''),domain,COALESCE(ips,''),
		COALESCE(resolved_at,0),COALESCE(ttl,?) FROM domain_route WHERE enabled=1 ORDER BY id`,
		DefaultDomainRouteTTL)
	if err != nil {
		return 0, nil, err
	}
	type pending struct {
		id              int64
		scope           DomainRouteScope
		domain          string
		oldIPs          string
		resolvedAt, ttl int64
	}
	var todo []pending
	now := time.Now().Unix()
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.scope.ServiceID, &p.scope.Username, &p.domain, &p.oldIPs,
			&p.resolvedAt, &p.ttl); err != nil {
			continue
		}
		if p.ttl <= 0 {
			p.ttl = DefaultDomainRouteTTL
		}
		if !force && p.resolvedAt+p.ttl > now {
			continue
		}
		todo = append(todo, p)
	}
	rows.Close()

	changed := 0
	affected := []DomainRouteScope{}
	seen := map[string]bool{}
	for _, p := range todo {
		ips, rerr := ResolveDomainIPv4(context.Background(), p.domain)
		stamp := time.Now().Unix()
		if rerr != nil {
			// 记录错误但同样推进 resolved_at，避免每轮都去打 DNS
			_, _ = conn.Exec(`UPDATE domain_route SET resolved_at=?,last_error=?,updated_at=? WHERE id=?`,
				stamp, rerr.Error(), time.Now().Format("2006-01-02 15:04:05"), p.id)
			continue
		}
		newIPs := strings.Join(ips, ",")
		if _, err := conn.Exec(`UPDATE domain_route SET ips=?,resolved_at=?,last_error='',updated_at=? WHERE id=?`,
			newIPs, stamp, time.Now().Format("2006-01-02 15:04:05"), p.id); err != nil {
			continue
		}
		if newIPs != p.oldIPs {
			changed++
			key := fmt.Sprintf("%d|%s", p.scope.ServiceID, p.scope.Username)
			if !seen[key] {
				seen[key] = true
				affected = append(affected, p.scope)
			}
		}
	}
	sort.Slice(affected, func(i, j int) bool {
		if affected[i].ServiceID != affected[j].ServiceID {
			return affected[i].ServiceID < affected[j].ServiceID
		}
		return affected[i].Username < affected[j].Username
	})
	return changed, affected, nil
}
