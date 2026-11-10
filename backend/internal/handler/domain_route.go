package handler

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// 域名分流：后台填域名 → 服务端解析成 IPv4 → 以 /32 路由下发
//
// OpenVPN 只认 IP 路由，所以这里做的是「域名到 IP 的翻译 + 定时刷新」。两种生效方式：
//
//	按用户（默认）：路由写进该用户的 CCD 文件 —— 改完**不需要重启实例**，用户重连即生效；
//	实例级（username 为空）：路由写进 server.conf 的全局 push —— 必须重启实例才生效。
//
// 日常使用请用按用户的方式。

// domainRouteDirtyKey 记录需要重启才生效的实例（"0" 表示全部实例）；仅实例级规则会用到
const domainRouteDirtyKey = "domain_route_dirty"

func MarkDomainRouteDirty(serviceIDs []int64) {
	set := map[string]bool{}
	for _, v := range strings.Split(db.GetSetting(domainRouteDirtyKey), ",") {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = true
		}
	}
	for _, id := range serviceIDs {
		set[fmt.Sprint(id)] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	db.SetSetting(domainRouteDirtyKey, strings.Join(keys, ","))
}

func clearDomainRouteDirty() { db.SetSetting(domainRouteDirtyKey, "") }

// normalizeUsernames 拆出待下发的用户名（支持逗号/空格/换行分隔），去重并校验
func normalizeUsernames(list []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range list {
		for _, u := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' || r == '；'
		}) {
			u = strings.TrimSpace(u)
			if u == "" || seen[strings.ToLower(u)] {
				continue
			}
			if !validName(u) {
				return nil, fmt.Errorf("用户名格式不正确：%s", u)
			}
			seen[strings.ToLower(u)] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// DomainRouteList GET /domainRoute/list
func DomainRouteList(w http.ResponseWriter, r *http.Request) {
	nameByID := map[int64]string{}
	services := []map[string]any{}
	if rows, err := db.DB.Query(`SELECT id,name FROM service ORDER BY id`); err == nil {
		for rows.Next() {
			var id int64
			var name string
			if rows.Scan(&id, &name) == nil {
				nameByID[id] = name
				services = append(services, map[string]any{"id": id, "name": name})
			}
		}
		rows.Close()
	}

	list := []map[string]any{}
	rows, err := db.DB.Query(`SELECT id,COALESCE(service_id,0),COALESCE(username,''),domain,COALESCE(note,''),
		COALESCE(enabled,1),COALESCE(ips,''),COALESCE(resolved_at,0),COALESCE(ttl,300),COALESCE(last_error,'')
		FROM domain_route ORDER BY COALESCE(username,''),id DESC`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, svcID, enabled, resolvedAt, ttl int64
		var username, domain, note, ips, lastErr string
		if rows.Scan(&id, &svcID, &username, &domain, &note, &enabled, &ips, &resolvedAt, &ttl, &lastErr) != nil {
			continue
		}
		ipList := []string{}
		for _, ip := range strings.Split(ips, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ipList = append(ipList, ip)
			}
		}
		scope := "全部实例（所有用户）"
		if username != "" {
			if svcID > 0 {
				if name, ok := nameByID[svcID]; ok {
					scope = username + " @ " + name
				} else {
					scope = username
				}
			} else {
				scope = username + "（全部实例）"
			}
		} else if svcID > 0 {
			if name, ok := nameByID[svcID]; ok {
				scope = name + "（该实例所有用户）"
			} else {
				scope = fmt.Sprintf("实例 #%d（已删除）", svcID)
			}
		}
		item := map[string]any{
			"id": id, "service_id": svcID, "username": username, "service_name": scope,
			"domain": domain, "note": note, "enabled": enabled, "scope_user": username != "",
			"ips": ipList, "resolved_at": resolvedAt, "ttl": ttl, "last_error": lastErr,
		}
		if resolvedAt > 0 {
			item["resolved_text"] = time.Unix(resolvedAt, 0).Format("2006-01-02 15:04:05")
		} else {
			item["resolved_text"] = ""
		}
		list = append(list, item)
	}

	// 只有实例级规则才需要「应用变更（重启实例）」
	dirty := []string{}
	dirtyIDs := []int64{}
	for _, v := range strings.Split(db.GetSetting(domainRouteDirtyKey), ",") {
		if v = strings.TrimSpace(v); v != "" {
			n := "全部实例"
			if v != "0" {
				n = nameByID[atoi64(v)]
				if n == "" {
					continue
				}
			}
			if !containsStr(dirty, n) {
				dirty = append(dirty, n)
			}
			if v != "0" {
				dirtyIDs = append(dirtyIDs, atoi64(v))
			}
		}
	}
	util.OK(w, map[string]any{
		"list": list, "services": services,
		"pending_names": dirty, "pending_ids": dirtyIDs,
		"default_ttl": vpn.DefaultDomainRouteTTL,
	})
}

// resolveDomainNow 立即解析一次（失败只记录错误，不影响入库）
func resolveDomainNow(domain string) ([]string, string) {
	ips, err := vpn.ResolveDomainIPv4(context.Background(), domain)
	if err != nil {
		return nil, err.Error()
	}
	return ips, "解析成功：" + strings.Join(ips, ", ")
}

func lastErrOf(ips []string, msg string) string {
	if len(ips) == 0 {
		return msg
	}
	return ""
}

// toScopes 用户名列表 → 作用域（service_id 原样保留，0 表示全部实例）
func toScopes(users []string, serviceID int64) []vpn.DomainRouteScope {
	out := make([]vpn.DomainRouteScope, 0, len(users))
	for _, u := range users {
		out = append(out, vpn.DomainRouteScope{ServiceID: serviceID, Username: u})
	}
	return out
}

// DomainRouteAdd POST /domainRoute/add
// body: {domain, service_id, username|usernames, note, ttl, enabled, scope:"user"|"instance"}
func DomainRouteAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain    string   `json:"domain"`
		ServiceID int64    `json:"service_id"`
		Username  string   `json:"username"`
		Usernames []string `json:"usernames"`
		Note      string   `json:"note"`
		TTL       int      `json:"ttl"`
		Enabled   int      `json:"enabled"`
		Scope     string   `json:"scope"` // user（默认）| instance
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	domain, derr := vpn.NormalizeDomain(req.Domain)
	if derr != nil {
		util.Fail(w, derr.Error())
		return
	}
	if req.TTL <= 0 || req.TTL > 86400 {
		req.TTL = vpn.DefaultDomainRouteTTL
	}
	enabled := boolInt(req.Enabled != 0)

	// 实例级：写 server.conf 全局 push（需要重启实例），仅保留给「对所有人」的场景
	instanceScope := strings.EqualFold(strings.TrimSpace(req.Scope), "instance") ||
		strings.TrimSpace(req.Username) == "*"
	if instanceScope {
		var exists int64
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE service_id=? AND COALESCE(username,'')='' AND domain=?`,
			req.ServiceID, domain).Scan(&exists)
		if exists > 0 {
			util.Fail(w, "该域名在此范围内已存在")
			return
		}
		ips, msg := resolveDomainNow(domain)
		if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,note,enabled,ips,resolved_at,last_error,ttl,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, req.ServiceID, "", domain, req.Note, enabled,
			strings.Join(ips, ","), time.Now().Unix(), lastErrOf(ips, msg), req.TTL, db.Now(), db.Now()); err != nil {
			util.Fail(w, "保存失败: "+err.Error())
			return
		}
		MarkDomainRouteDirty([]int64{req.ServiceID})
		db.Syslog("admin", "添加域名分流(实例级)", domain+" → "+strings.Join(ips, ","), clientIP(r))
		util.OKMsg(w, "已添加（实例级，需「应用变更」重启实例后生效）："+msg, map[string]any{"ips": ips, "added": 1})
		return
	}

	users, uerr := normalizeUsernames(append([]string{req.Username}, req.Usernames...))
	if uerr != nil {
		util.Fail(w, uerr.Error())
		return
	}
	if len(users) == 0 {
		util.Fail(w, "请填写要下发该域名的用户（多个用户名用逗号或换行分隔）")
		return
	}
	ips, msg := resolveDomainNow(domain)
	added, skipped := 0, 0
	for _, u := range users {
		var exists int64
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE service_id=? AND lower(username)=lower(?) AND domain=?`,
			req.ServiceID, u, domain).Scan(&exists)
		if exists > 0 {
			skipped++
			continue
		}
		if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,note,enabled,ips,resolved_at,last_error,ttl,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, req.ServiceID, u, domain, req.Note, enabled,
			strings.Join(ips, ","), time.Now().Unix(), lastErrOf(ips, msg), req.TTL, db.Now(), db.Now()); err != nil {
			skipped++
			continue
		}
		added++
	}
	written, _ := vpn.SyncDomainCcd(db.DB, toScopes(users, req.ServiceID))
	db.Syslog("admin", "添加域名分流", fmt.Sprintf("%s → %s 用户=%s", domain, strings.Join(ips, ","), strings.Join(users, ",")), clientIP(r))
	util.OKMsg(w, fmt.Sprintf("已保存 %d 个用户（跳过 %d），重写 %d 个 CCD 文件；%s。用户重新连接 VPN 后生效",
		added, skipped, written, msg),
		map[string]any{"ips": ips, "added": added, "skipped": skipped, "ccd_written": written})
}

// normalizeDomainList 把一行一个 / 逗号分隔 / 数组形式的域名统一规范化并去重。
// 任一域名非法则整批拒绝，避免部分写入。
func normalizeDomainList(raw string, list []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range append([]string{raw}, list...) {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '，' || r == ';' || r == '；' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
		}) {
			d, err := vpn.NormalizeDomain(part)
			if err != nil {
				return nil, fmt.Errorf("域名 %q 无效：%v", part, err)
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请至少填写一个域名")
	}
	if len(out) > 50 {
		return nil, fmt.Errorf("一次最多添加 50 个域名，请分批")
	}
	return out, nil
}

// DomainRouteAddMulti POST /domainRoute/addMulti
// 一次给多个用户添加多个域名（域名 × 用户 笛卡尔积），末尾统一重写一次 CCD。
// body: {domain: "a.com\nb.com" | domains: [...], service_id, username|usernames, note, ttl, enabled}
func DomainRouteAddMulti(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain    string   `json:"domain"`
		Domains   []string `json:"domains"`
		ServiceID int64    `json:"service_id"`
		Username  string   `json:"username"`
		Usernames []string `json:"usernames"`
		Note      string   `json:"note"`
		TTL       int      `json:"ttl"`
		Enabled   int      `json:"enabled"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	domains, derr := normalizeDomainList(req.Domain, req.Domains)
	if derr != nil {
		util.Fail(w, derr.Error())
		return
	}
	users, uerr := normalizeUsernames(append([]string{req.Username}, req.Usernames...))
	if uerr != nil {
		util.Fail(w, uerr.Error())
		return
	}
	if len(users) == 0 {
		util.Fail(w, "请选择要下发的用户")
		return
	}
	if req.TTL <= 0 || req.TTL > 86400 {
		req.TTL = vpn.DefaultDomainRouteTTL
	}
	enabled := boolInt(req.Enabled != 0)

	// 逐个域名 DNS 解析最多阻塞 8s，并发解析避免 N 个域名串行等待
	type resolved struct {
		ips []string
		msg string
	}
	results := make([]resolved, len(domains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ips, msg := resolveDomainNow(d)
			results[i] = resolved{ips: ips, msg: msg}
		}(i, d)
	}
	wg.Wait()

	added, skipped := 0, 0
	failDomains := []string{}
	now := time.Now().Unix()
	for i, d := range domains {
		res := results[i]
		if len(res.ips) == 0 {
			failDomains = append(failDomains, d)
		}
		for _, u := range users {
			var exists int64
			_ = db.DB.QueryRow(`SELECT COUNT(*) FROM domain_route WHERE service_id=? AND lower(username)=lower(?) AND domain=?`,
				req.ServiceID, u, d).Scan(&exists)
			if exists > 0 {
				skipped++
				continue
			}
			if _, err := db.DB.Exec(`INSERT INTO domain_route(service_id,username,domain,note,enabled,ips,resolved_at,last_error,ttl,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,?,?)`, req.ServiceID, u, d, req.Note, enabled,
				strings.Join(res.ips, ","), now, lastErrOf(res.ips, res.msg), req.TTL, db.Now(), db.Now()); err != nil {
				skipped++
				continue
			}
			added++
		}
	}
	written, _ := vpn.SyncDomainCcd(db.DB, toScopes(users, req.ServiceID))
	suffix := ""
	if len(failDomains) > 0 {
		suffix = "；⚠️ 以下域名暂未解析到 IPv4（后台会自动重试）：" + strings.Join(failDomains, "、")
	}
	db.Syslog("admin", "批量添加域名分流", fmt.Sprintf("域名=%d 用户=%d 新增=%d", len(domains), len(users), added), clientIP(r))
	util.OKMsg(w, fmt.Sprintf("已添加 %d 条规则（跳过重复/失败 %d），重写 %d 个 CCD 文件；用户重新连接 VPN 后生效%s",
		added, skipped, written, suffix),
		map[string]any{"added": added, "skipped": skipped, "ccd_written": written,
			"domains": len(domains), "users": len(users), "unresolved": failDomains})
}

// DomainRouteUpdate POST /domainRoute/update
func DomainRouteUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        int64   `json:"id"`
		ServiceID *int64  `json:"service_id"`
		Username  *string `json:"username"`
		Note      *string `json:"note"`
		TTL       *int    `json:"ttl"`
		Enabled   *int    `json:"enabled"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID <= 0 {
		util.Fail(w, "参数错误")
		return
	}
	var svcID, enabled, ttl int64
	var username, note, domain string
	if err := db.DB.QueryRow(`SELECT COALESCE(service_id,0),COALESCE(username,''),COALESCE(note,''),
		COALESCE(enabled,1),COALESCE(ttl,300),domain FROM domain_route WHERE id=?`, req.ID).
		Scan(&svcID, &username, &note, &enabled, &ttl, &domain); err != nil {
		util.Fail(w, "规则不存在")
		return
	}
	oldUser, oldSvc := username, svcID
	if req.ServiceID != nil {
		svcID = *req.ServiceID
	}
	if req.Note != nil {
		note = *req.Note
	}
	if req.Enabled != nil {
		enabled = int64(boolInt(*req.Enabled != 0))
	}
	if req.TTL != nil && *req.TTL > 0 && *req.TTL <= 86400 {
		ttl = int64(*req.TTL)
	}
	if req.Username != nil {
		username = strings.TrimSpace(*req.Username)
		if username == "*" {
			username = ""
		}
		if username != "" && !validName(username) {
			util.Fail(w, "用户名格式不正确")
			return
		}
	}
	if _, err := db.DB.Exec(`UPDATE domain_route SET service_id=?,username=?,note=?,enabled=?,ttl=?,updated_at=? WHERE id=?`,
		svcID, username, note, enabled, ttl, db.Now(), req.ID); err != nil {
		util.Fail(w, "保存失败")
		return
	}
	// 换了用户/实例时，旧作用域的 CCD 也要重写，避免残留旧路由
	scopes := []vpn.DomainRouteScope{{ServiceID: svcID, Username: username}}
	if oldUser != username || oldSvc != svcID {
		scopes = append(scopes, vpn.DomainRouteScope{ServiceID: oldSvc, Username: oldUser})
	}
	written, _ := vpn.SyncDomainCcd(db.DB, scopes)
	msg := fmt.Sprintf("已保存，重写 %d 个 CCD 文件；用户重连后生效", written)
	if username == "" {
		MarkDomainRouteDirty([]int64{svcID})
		msg = "已保存（实例级规则：需点「应用变更」重启实例才生效）"
	}
	db.Syslog("admin", "修改域名分流", fmt.Sprintf("#%d %s enabled=%d user=%s", req.ID, domain, enabled, username), clientIP(r))
	util.OKMsg(w, msg, map[string]any{"ccd_written": written})
}

// DomainRouteDelete POST /domainRoute/delete（支持 id 或 ids 批量）
func DomainRouteDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  int64   `json:"id"`
		IDs []int64 `json:"ids"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	ids := append([]int64{}, req.IDs...)
	if req.ID > 0 {
		ids = append(ids, req.ID)
	}
	if len(ids) == 0 {
		util.Fail(w, "参数错误")
		return
	}
	deleted := 0
	scopes := []vpn.DomainRouteScope{}
	dirtyInstances := []int64{}
	for _, id := range ids {
		var svcID int64
		var username, domain string
		if db.DB.QueryRow(`SELECT COALESCE(service_id,0),COALESCE(username,''),domain FROM domain_route WHERE id=?`, id).
			Scan(&svcID, &username, &domain) != nil {
			continue
		}
		if _, err := db.DB.Exec(`DELETE FROM domain_route WHERE id=?`, id); err != nil {
			continue
		}
		deleted++
		if username == "" {
			dirtyInstances = append(dirtyInstances, svcID)
		} else {
			scopes = append(scopes, vpn.DomainRouteScope{ServiceID: svcID, Username: username})
		}
		db.Syslog("admin", "删除域名分流", domain+" user="+username, clientIP(r))
	}
	written, _ := vpn.SyncDomainCcd(db.DB, scopes)
	if len(dirtyInstances) > 0 {
		MarkDomainRouteDirty(dirtyInstances)
	}
	msg := fmt.Sprintf("已删除 %d 条，重写 %d 个 CCD 文件；用户重连后该路由即取消", deleted, written)
	if len(dirtyInstances) > 0 {
		msg += "（含实例级规则，需「应用变更」重启实例）"
	}
	util.OKMsg(w, msg, map[string]any{"deleted": deleted, "ccd_written": written})
}

// DomainRouteResolve POST /domainRoute/resolve　（id=0 表示全部重新解析）
func DomainRouteResolve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	_ = util.ReadJSON(r, &req)

	if req.ID > 0 {
		var domain string
		var svcID int64
		var username string
		if err := db.DB.QueryRow(`SELECT domain,COALESCE(service_id,0),COALESCE(username,'') FROM domain_route WHERE id=?`, req.ID).
			Scan(&domain, &svcID, &username); err != nil {
			util.Fail(w, "规则不存在")
			return
		}
		ips, err := vpn.ResolveDomainIPv4(context.Background(), domain)
		if err != nil {
			_, _ = db.DB.Exec(`UPDATE domain_route SET last_error=?,resolved_at=? WHERE id=?`,
				err.Error(), time.Now().Unix(), req.ID)
			util.Fail(w, err.Error())
			return
		}
		_, _ = db.DB.Exec(`UPDATE domain_route SET ips=?,resolved_at=?,last_error='' WHERE id=?`,
			strings.Join(ips, ","), time.Now().Unix(), req.ID)
		written, _ := vpn.SyncDomainCcd(db.DB, []vpn.DomainRouteScope{{ServiceID: svcID, Username: username}})
		msg := "解析成功：" + strings.Join(ips, ", ")
		if username == "" {
			MarkDomainRouteDirty([]int64{svcID})
			msg += "（实例级，需应用变更重启实例）"
		} else {
			msg += fmt.Sprintf("，已更新 %d 个 CCD 文件，用户重连后生效", written)
		}
		util.OKMsg(w, msg, map[string]any{"ips": ips, "ccd_written": written})
		return
	}

	changed, affected, err := vpn.RefreshDomainRoutes(db.DB, true)
	if err != nil {
		util.Fail(w, "解析失败: "+err.Error())
		return
	}
	userScopes := []vpn.DomainRouteScope{}
	instances := []int64{}
	for _, sc := range affected {
		if sc.Username == "" {
			instances = append(instances, sc.ServiceID)
		} else {
			userScopes = append(userScopes, sc)
		}
	}
	written, _ := vpn.SyncDomainCcd(db.DB, userScopes)
	if len(instances) > 0 {
		MarkDomainRouteDirty(instances)
	}
	msg := fmt.Sprintf("已重新解析全部规则，%d 条 IP 有变化；%d 个 CCD 文件已更新（用户重连即生效）", changed, written)
	if len(instances) > 0 {
		msg += "；实例级规则需「应用变更」重启实例"
	}
	util.OKMsg(w, msg, map[string]any{"changed": changed, "ccd_written": written})
}

// DomainRouteApply POST /domainRoute/apply　仅处理实例级规则：重启实例让新路由生效
func DomainRouteApply(w http.ResponseWriter, r *http.Request) {
	ids := []int64{}
	for _, v := range strings.Split(db.GetSetting(domainRouteDirtyKey), ",") {
		if v = strings.TrimSpace(v); v != "" {
			ids = append(ids, atoi64(v))
		}
	}
	if len(ids) == 0 {
		util.OKMsg(w, "没有需要重启生效的变更（按用户的域名分流已即时写入 CCD，用户重连即可）", nil)
		return
	}
	all := false
	for _, id := range ids {
		if id == 0 {
			all = true
		}
	}
	if all {
		ids = vpn.AllServiceIDs(db.DB)
	}

	done := []string{}
	failed := []string{}
	for _, id := range ids {
		s, err := resolveService("", id)
		if err != nil {
			continue
		}
		if err := writeConfAndReload(s); err != nil {
			failed = append(failed, s.Name+"："+err.Error())
			continue
		}
		done = append(done, s.Name)
	}
	clearDomainRouteDirty()
	db.Syslog("admin", "应用域名分流", strings.Join(done, ",")+" 已重载", clientIP(r))
	if len(failed) > 0 {
		util.Fail(w, "以下实例重载失败："+strings.Join(failed, "；"))
		return
	}
	util.OKMsg(w, "已重载："+strings.Join(done, "、"), map[string]any{"services": done})
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func atoi64(s string) int64 {
	var n int64
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
