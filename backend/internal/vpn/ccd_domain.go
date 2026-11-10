package vpn

import (
	"database/sql"
	"net"
	"strings"
)

// 按用户维度的域名分流：把域名解析出的 IPv4 写进该用户的 CCD 文件。
//
// OpenVPN 在客户端连接时才读取 ccd/<username>，所以：
//   - 改域名 / 改解析结果 / 加删规则，只重写 CCD 文件即可，**不需要重启实例**；
//   - 用户主动重连（或客户端自动重连）后就拿到新路由。
//
// 实例级规则（username 为空）仍然走 server.conf 的全局 push，那部分才需要重启。

// DomainRouteForUser 某用户在某实例上应额外推送的 /32 路由（"a.b.c.d 255.255.255.255"）
// service_id=0 的规则对所有实例生效；用户名比较忽略大小写。
// 已由实例级规则（server.conf 全局 push）覆盖的 IP 不再重复下发。
func DomainRouteForUser(conn *sql.DB, serviceID int64, username string) []string {
	username = strings.TrimSpace(username)
	if conn == nil || username == "" {
		return nil
	}
	global := map[string]bool{}
	if rows, err := conn.Query(`SELECT COALESCE(ips,'') FROM domain_route
		WHERE enabled=1 AND COALESCE(username,'')='' AND (service_id=0 OR service_id=?)`, serviceID); err == nil {
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				continue
			}
			for _, ip := range strings.Split(raw, ",") {
				if ip = strings.TrimSpace(ip); ip != "" {
					global[ip] = true
				}
			}
		}
		rows.Close()
	}

	rows, err := conn.Query(`SELECT COALESCE(ips,'') FROM domain_route
		WHERE enabled=1 AND username<>'' AND lower(username)=lower(?)
		  AND (service_id=0 OR service_id=?)
		ORDER BY id`, username, serviceID)
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
			if ip == "" || seen[ip] || global[ip] || parsed == nil || parsed.To4() == nil {
				continue
			}
			seen[ip] = true
			out = append(out, parsed.To4().String()+" 255.255.255.255")
		}
	}
	return out
}

// LoadCcd 读取某用户在某实例的 CCD 记录（不存在返回 nil）
func LoadCcd(conn *sql.DB, serviceID int64, username string) *Ccd {
	if conn == nil || username == "" {
		return nil
	}
	var c Ccd
	var pm int64
	err := conn.QueryRow(`SELECT id,service_id,username,COALESCE(ifconfig_push,''),COALESCE(iroutes,''),
		COALESCE(push_routes,''),COALESCE(dns,''),COALESCE(proxy_mode,0),COALESCE(raw,'')
		FROM ccd WHERE service_id=? AND username=?`, serviceID, username).
		Scan(&c.ID, &c.ServiceID, &c.Username, &c.IfconfigPush, &c.Iroutes, &c.PushRoutes, &c.DNS, &pm, &c.Raw)
	if err != nil {
		return nil
	}
	c.ProxyMode = int(pm)
	return &c
}

// ServiceNameByID 实例名（不存在返回空）
func ServiceNameByID(conn *sql.DB, id int64) string {
	if conn == nil || id <= 0 {
		return ""
	}
	var name string
	if conn.QueryRow(`SELECT name FROM service WHERE id=?`, id).Scan(&name) != nil {
		return ""
	}
	return name
}

// ServicesForUser 该用户实际会用到的实例：
// 已配 CCD 的实例 ∪ 所在用户分组关联的实例；都没有时退回全部实例。
func ServicesForUser(conn *sql.DB, username string) []int64 {
	if conn == nil || username == "" {
		return nil
	}
	rows, err := conn.Query(`SELECT DISTINCT service_id FROM ccd WHERE username=?
		UNION
		SELECT DISTINCT gs.service_id FROM group_service gs
		  JOIN account a ON a.group_id=gs.group_id
		 WHERE a.username=?`, username, username)
	if err != nil {
		return AllServiceIDs(conn)
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return AllServiceIDs(conn)
	}
	return ids
}

// WriteCcdWithDomain 按库里的 CCD 配置 + 该用户的域名路由，重写 CCD 文件。
// 没有 CCD 记录但存在域名规则时，也会写一个只含路由的文件（不动 ifconfig-push）。
func WriteCcdWithDomain(conn *sql.DB, svcName string, serviceID int64, username string) error {
	if svcName == "" || username == "" {
		return nil
	}
	c := LoadCcd(conn, serviceID, username)
	if c == nil {
		c = &Ccd{ServiceID: serviceID, Username: username}
	}
	c.ExtraRoutes = DomainRouteForUser(conn, serviceID, username)
	return WriteCcd(svcName, c)
}

// SyncDomainCcd 同步一批作用域的 CCD 文件（仅用户维度规则生效；实例级规则忽略）。
// 返回重写的文件数。
func SyncDomainCcd(conn *sql.DB, scopes []DomainRouteScope) (int, error) {
	written := 0
	for _, sc := range scopes {
		username := strings.TrimSpace(sc.Username)
		if username == "" {
			continue
		}
		ids := []int64{sc.ServiceID}
		if sc.ServiceID == 0 {
			ids = ServicesForUser(conn, username)
		}
		for _, id := range ids {
			name := ServiceNameByID(conn, id)
			if name == "" {
				continue
			}
			if err := WriteCcdWithDomain(conn, name, id, username); err != nil {
				continue
			}
			written++
		}
	}
	return written, nil
}

// SyncAllDomainCcd 全量重建所有带用户维度的 CCD 文件（启动时调用，保证文件与库一致）
func SyncAllDomainCcd(conn *sql.DB) (int, error) {
	if conn == nil {
		return 0, nil
	}
	rows, err := conn.Query(`SELECT DISTINCT service_id,username FROM domain_route
		WHERE enabled=1 AND username<>'' ORDER BY service_id,username`)
	if err != nil {
		return 0, err
	}
	scopes := []DomainRouteScope{}
	for rows.Next() {
		var sc DomainRouteScope
		if rows.Scan(&sc.ServiceID, &sc.Username) == nil {
			scopes = append(scopes, sc)
		}
	}
	rows.Close()
	return SyncDomainCcd(conn, scopes)
}

// UserDomainRoutes 某用户名下所有域名规则（用于管理页展示/清理）
func UserDomainRoutes(conn *sql.DB, username string) []string {
	if conn == nil || username == "" {
		return nil
	}
	rows, err := conn.Query(`SELECT domain FROM domain_route
		WHERE username<>'' AND lower(username)=lower(?) ORDER BY domain`, username)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			out = append(out, d)
		}
	}
	return out
}
