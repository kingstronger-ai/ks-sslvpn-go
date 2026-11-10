// OpenVPN 服务实例管理 + CCD + 分组
package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

func serviceByName(name string) (*vpn.Service, error) {
	var s vpn.Service
	err := db.DB.QueryRow(`SELECT id,name,port,proto,subnet,mask,push_routes,redirect_gw,
		client_to_client,duplicate_cn,max_clients,status FROM service WHERE name=?`, name).
		Scan(&s.ID, &s.Name, &s.Port, &s.Proto, &s.Subnet, &s.Mask, &s.PushRoutes,
			&s.RedirectGW, &s.ClientToClient, &s.DuplicateCN, &s.MaxClients, &s.Status)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func ServiceAdd(w http.ResponseWriter, r *http.Request) {
	var s vpn.Service
	if err := util.ReadJSON(r, &s); err != nil || !validName(s.Name) || s.Port <= 0 {
		util.Fail(w, "实例名或端口不合法")
		return
	}
	if s.Proto == "" {
		s.Proto = "udp"
	}
	if s.Subnet == "" {
		s.Subnet, s.Mask = "10.8.0.0", "255.255.255.0"
	}
	var exists int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM service WHERE name=? OR port=?`, s.Name, s.Port).Scan(&exists)
	if exists > 0 {
		util.Fail(w, "实例名或端口已存在")
		return
	}
	if err := vpn.InitPKI(); err != nil {
		util.Fail(w, "PKI 初始化失败: "+err.Error())
		return
	}
	if err := vpn.CreateInstance(&s); err != nil {
		util.Fail(w, "创建实例失败: "+err.Error())
		return
	}
	res, err := db.DB.Exec(`INSERT INTO service(name,port,proto,subnet,mask,push_routes,redirect_gw,
		client_to_client,duplicate_cn,max_clients,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,datetime('now','localtime'))`,
		s.Name, s.Port, s.Proto, s.Subnet, s.Mask, s.PushRoutes, s.RedirectGW,
		s.ClientToClient, s.DuplicateCN, s.MaxClients)
	if err != nil {
		_ = vpn.RemoveInstance(s.Name)
		util.Fail(w, "入库失败: "+err.Error())
		return
	}
	id, _ := res.LastInsertId()
	// 放行端口 + SNAT
	_ = fw.OpenPort(s.Port, s.Proto)
	_ = fw.EnableSNAT(s.Subnet+"/"+maskToCIDR(s.Mask), fw.OutInterface())
	db.Syslog("admin", "创建VPN服务实例", s.Name, clientIP(r))
	util.OK(w, map[string]int64{"id": id})
}

func ServiceList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id,name,port,proto,subnet,mask,push_routes,redirect_gw,
		client_to_client,duplicate_cn,max_clients,status FROM service ORDER BY id`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var s vpn.Service
		if rows.Scan(&s.ID, &s.Name, &s.Port, &s.Proto, &s.Subnet, &s.Mask, &s.PushRoutes,
			&s.RedirectGW, &s.ClientToClient, &s.DuplicateCN, &s.MaxClients, &s.Status) == nil {
			running := vpn.IsRunning(s.Name)
			if running {
				s.Status = 1
			} else {
				s.Status = 0
			}
			online := len(vpn.ParseStatusLog(s.Name))
			list = append(list, map[string]any{
				"id": s.ID, "name": s.Name, "port": s.Port, "proto": s.Proto,
				"subnet": s.Subnet + " " + s.Mask, "redirect_gw": s.RedirectGW,
				"push_routes": s.PushRoutes, "client_to_client": s.ClientToClient,
				"duplicate_cn": s.DuplicateCN,
				"max_clients":  s.MaxClients, "status": s.Status, "online": online,
			})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func ServiceStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		ID   int64  `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	if err := vpn.StartInstance(s); err != nil {
		util.Fail(w, "启动失败: "+err.Error())
		return
	}
	_, _ = db.DB.Exec(`UPDATE service SET status=1 WHERE id=?`, s.ID)
	refreshSNAT() // 确保该网段的 NAT 伪装存在（容器重建后规则会丢失）
	db.Syslog("admin", "启动VPN服务", s.Name, clientIP(r))
	util.OKMsg(w, "已启动", nil)
}

func ServiceStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		ID   int64  `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	_ = vpn.StopInstance(s.Name)
	_, _ = db.DB.Exec(`UPDATE service SET status=0 WHERE id=?`, s.ID)
	db.Syslog("admin", "停止VPN服务", s.Name, clientIP(r))
	util.OKMsg(w, "已停止", nil)
}

func resolveService(name string, id int64) (*vpn.Service, error) {
	if name != "" {
		return serviceByName(name)
	}
	var s vpn.Service
	err := db.DB.QueryRow(`SELECT id,name,port,proto,subnet,mask,push_routes,redirect_gw,
		client_to_client,duplicate_cn,max_clients,status FROM service WHERE id=?`, id).
		Scan(&s.ID, &s.Name, &s.Port, &s.Proto, &s.Subnet, &s.Mask, &s.PushRoutes,
			&s.RedirectGW, &s.ClientToClient, &s.DuplicateCN, &s.MaxClients, &s.Status)
	return &s, err
}

func ServiceAndGroups(w http.ResponseWriter, r *http.Request) {
	services := []map[string]any{}
	rows, err := db.DB.Query(`SELECT id,name,port FROM service ORDER BY id`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var name string
			var port int
			if rows.Scan(&id, &name, &port) == nil {
				services = append(services, map[string]any{"id": id, "name": name, "port": port})
			}
		}
	}
	groups := []map[string]any{}
	rows2, err := db.DB.Query(`SELECT id,name FROM "group" ORDER BY id`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id int64
			var name string
			if rows2.Scan(&id, &name) == nil {
				groups = append(groups, map[string]any{"id": id, "name": name})
			}
		}
	}
	attach := map[string][]int64{}
	rows3, err := db.DB.Query(`SELECT group_id, service_id FROM group_service`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var g, s int64
			if rows3.Scan(&g, &s) == nil {
				attach[fmt.Sprint(g)] = append(attach[fmt.Sprint(g)], s)
			}
		}
	}
	util.OK(w, map[string]any{"services": services, "groups": groups, "attach": attach})
}

// ServiceAttachGroup 提交分组关联（组 -> 服务列表）
func ServiceAttachGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID  int64   `json:"group_id"`
		Services []int64 `json:"service_ids"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.GroupID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM group_service WHERE group_id=?`, req.GroupID); err != nil {
		util.Fail(w, "更新失败")
		return
	}
	for _, sid := range req.Services {
		_, _ = db.DB.Exec(`INSERT OR IGNORE INTO group_service(group_id,service_id) VALUES(?,?)`, req.GroupID, sid)
	}
	util.OKMsg(w, "关联已保存", nil)
}

func ServiceCancelAttach(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID   int64 `json:"group_id"`
		ServiceID int64 `json:"service_id"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM group_service WHERE group_id=? AND service_id=?`, req.GroupID, req.ServiceID)
	util.OKMsg(w, "已取消关联", nil)
}

// ServiceAddRouter push 添加路由
func ServiceAddRouter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    int64  `json:"id"`
		Route string `json:"route"` // "10.1.0.0 255.255.255.0"
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 || req.Route == "" {
		util.Fail(w, "参数错误（route 格式：网段 掩码）")
		return
	}
	s, err := resolveService("", req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	s.PushRoutes = strings.TrimSpace(s.PushRoutes + "\n" + req.Route)
	if err := writeConfAndReload(s); err != nil {
		util.Fail(w, err.Error())
		return
	}
	_, _ = db.DB.Exec(`UPDATE service SET push_routes=? WHERE id=?`, s.PushRoutes, s.ID)
	util.OKMsg(w, "路由已添加（运行中的实例将自动重启生效）", nil)
}

func ServiceRemoveRouter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    int64  `json:"id"`
		Route string `json:"route"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 || req.Route == "" {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService("", req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	var kept []string
	for _, line := range strings.Split(s.PushRoutes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != req.Route {
			kept = append(kept, line)
		}
	}
	s.PushRoutes = strings.Join(kept, "\n")
	if err := writeConfAndReload(s); err != nil {
		util.Fail(w, err.Error())
		return
	}
	_, _ = db.DB.Exec(`UPDATE service SET push_routes=? WHERE id=?`, s.PushRoutes, s.ID)
	util.OKMsg(w, "路由已移除", nil)
}

// writeConfAndReload 重写配置；运行中则重启
func writeConfAndReload(s *vpn.Service) error {
	wasRunning := vpn.IsRunning(s.Name)
	if wasRunning {
		_ = vpn.StopInstance(s.Name)
	}
	if err := vpn.WriteInstanceConf(s); err != nil {
		return err
	}
	if wasRunning {
		return vpn.StartInstance(s)
	}
	return nil
}

func ServiceRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	_ = vpn.StopInstance(s.Name)
	_ = vpn.RevokeUserCert(s.Name)
	_ = vpn.RemoveInstance(s.Name)
	_, _ = db.DB.Exec(`DELETE FROM service WHERE id=?`, s.ID)
	_, _ = db.DB.Exec(`DELETE FROM group_service WHERE service_id=?`, s.ID)
	_, _ = db.DB.Exec(`DELETE FROM ccd WHERE service_id=?`, s.ID)
	_ = fw.ClosePort(s.Port, s.Proto)
	db.Syslog("admin", "删除VPN服务实例", s.Name, clientIP(r))
	util.OKMsg(w, "实例已删除", nil)
}

func ServiceEdit(w http.ResponseWriter, r *http.Request) {
	var s vpn.Service
	if err := util.ReadJSON(r, &s); err != nil || s.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	old, err := resolveService("", s.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	// 端口允许修改：校验范围与占用，改后同步防火墙放行规则
	if s.Port == 0 {
		s.Port = old.Port // 未提交端口时保持原值
	}
	portChanged := s.Port > 0 && s.Port != old.Port
	if portChanged {
		if s.Port < 1 || s.Port > 65535 {
			util.Fail(w, "端口不合法（1-65535）")
			return
		}
		var cnt int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM service WHERE port=? AND id<>?`, s.Port, s.ID).Scan(&cnt)
		if cnt > 0 {
			util.Fail(w, "端口已被其他实例占用")
			return
		}
	}
	// 未提交的字段保持原值（proto/subnet/mask 创建后不可改）
	if s.Proto == "" {
		s.Proto = old.Proto
	}
	if s.Subnet == "" {
		s.Subnet = old.Subnet
	}
	if s.Mask == "" {
		s.Mask = old.Mask
	}
	if _, err := db.DB.Exec(`UPDATE service SET port=?,proto=?,subnet=?,mask=?,push_routes=?,redirect_gw=?,
		client_to_client=?,duplicate_cn=?,max_clients=? WHERE id=?`,
		s.Port, s.Proto, s.Subnet, s.Mask, s.PushRoutes, s.RedirectGW, s.ClientToClient, s.DuplicateCN,
		s.MaxClients, s.ID); err != nil {
		util.Fail(w, "更新失败")
		return
	}
	ns, _ := resolveService("", s.ID)
	if ns.Proto == "" {
		ns.Proto = old.Proto
	}
	if ns.Subnet == "" {
		ns.Subnet, ns.Mask = old.Subnet, old.Mask
	}
	if err := writeConfAndReload(ns); err != nil {
		util.Fail(w, "实例重载失败: "+err.Error())
		return
	}
	if portChanged {
		_ = fw.ClosePort(old.Port, ns.Proto)
		_ = fw.OpenPort(ns.Port, ns.Proto)
		db.Syslog("admin", "修改实例端口", old.Name+": "+fmt.Sprint(old.Port)+" -> "+fmt.Sprint(ns.Port)+"（在线用户需重新下发客户端配置）", clientIP(r))
		util.OKMsg(w, "已更新并重载实例；端口已改为 "+fmt.Sprint(ns.Port)+"，请重新下发客户端配置", nil)
		return
	}
	util.OKMsg(w, "已更新", nil)
}

func ServiceClearLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	_ = os.Truncate(filepath.Join(vpn.BaseDir, "instance", s.Name, "openvpn.log"), 0)
	util.OKMsg(w, "日志已清空", nil)
}

func ServiceDownloadLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	data, _ := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", s.Name, "openvpn.log"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_openvpn.log"`, s.Name))
	_, _ = w.Write(data)
}

func ServiceStopAllInternal() error {
	rows, err := db.DB.Query(`SELECT name FROM service WHERE status=1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	for _, n := range names {
		_ = vpn.StopInstance(n)
	}
	_, _ = db.DB.Exec(`UPDATE service SET status=0`)
	return nil
}

func ServiceStopAll(w http.ResponseWriter, r *http.Request) {
	if err := ServiceStopAllInternal(); err != nil {
		util.Fail(w, "操作失败")
		return
	}
	util.OKMsg(w, "所有服务已停止", nil)
}

func ServiceConfiguration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService(req.Name, req.ID)
	if err != nil {
		util.Fail(w, "服务不存在")
		return
	}
	data, err := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", s.Name, "server.conf"))
	if err != nil {
		util.Fail(w, "配置文件读取失败")
		return
	}
	util.OK(w, map[string]string{"conf": string(data)})
}

func ServiceTemplateCfg(w http.ResponseWriter, r *http.Request) {
	tpl := db.GetSetting("server_template")
	if tpl == "" {
		b, _ := os.ReadFile(filepath.Join(vpn.BaseDir, "server", "template.conf"))
		tpl = string(b)
	}
	util.OK(w, map[string]string{"template": tpl})
}

func ServiceUpdateTemplateCfg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Template string `json:"template"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Template == "" {
		util.Fail(w, "模板内容不能为空")
		return
	}
	db.SetSetting("server_template", req.Template)
	util.OKMsg(w, "服务端模板已保存", nil)
}

func ServiceClientTemplateCfg(w http.ResponseWriter, r *http.Request) {
	tpl := db.GetSetting("client_template")
	if tpl == "" {
		tpl = "client\ndev tun\n# 客户端模板占位（重构版采用内联证书模式生成最终配置）"
	}
	util.OK(w, map[string]string{"template": tpl})
}

func ServiceUpdateClientTemplateCfg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Template string `json:"template"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	db.SetSetting("client_template", req.Template)
	util.OKMsg(w, "客户端模板已保存", nil)
}

// ---------- CCD ----------

func CcdList(w http.ResponseWriter, r *http.Request) {
	svcID := atoiSafe(r.URL.Query().Get("service_id"))
	rows, err := db.DB.Query(`SELECT id,service_id,username,ifconfig_push,iroutes,push_routes,
		COALESCE(dns,''),COALESCE(proxy_mode,0),COALESCE(raw,''),
		COALESCE(created_at,''),COALESCE(updated_at,'') FROM ccd
		WHERE (?=0 OR service_id=?) ORDER BY id DESC`, svcID, svcID)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, sid, pm int64
		var u, ip, ir, pr, dns, raw, ca, ua string
		if rows.Scan(&id, &sid, &u, &ip, &ir, &pr, &dns, &pm, &raw, &ca, &ua) == nil {
			c := vpn.Ccd{ServiceID: sid, Username: u, IfconfigPush: ip,
				Iroutes: ir, PushRoutes: pr, DNS: dns, ProxyMode: int(pm), Raw: raw}
			c.ExtraRoutes = vpn.DomainRouteForUser(db.DB, sid, u)
			list = append(list, map[string]any{
				"id": id, "service_id": sid, "username": u,
				"ifconfig_push": ip, "iroutes": ir, "push_routes": pr,
				"dns": dns, "proxy_mode": pm, "raw": raw,
				"content":    vpn.RenderCcd(&c),
				"created_at": dbTime(ca), "updated_at": dbTime(ua),
			})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func CcdUserList(w http.ResponseWriter, r *http.Request) { CcdList(w, r) }

func CcdAdd(w http.ResponseWriter, r *http.Request) {
	var c vpn.Ccd
	if err := util.ReadJSON(r, &c); err != nil || c.ServiceID == 0 || c.Username == "" {
		util.Fail(w, "参数错误")
		return
	}
	s, err := resolveService("", c.ServiceID)
	if err != nil {
		util.Fail(w, "服务实例不存在")
		return
	}
	var exists int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM ccd WHERE service_id=? AND username=?`, c.ServiceID, c.Username).Scan(&exists)
	if exists > 0 {
		util.Fail(w, "该用户在此实例已有 CCD 配置")
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO ccd(service_id,username,ifconfig_push,iroutes,push_routes,dns,proxy_mode,raw,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.ServiceID, c.Username, c.IfconfigPush, c.Iroutes, c.PushRoutes, c.DNS, c.ProxyMode, c.Raw, db.Now(), db.Now()); err != nil {
		util.Fail(w, "保存失败")
		return
	}
	_ = writeCcdFile(s, &c)
	util.OKMsg(w, "CCD 配置已创建，用户重新连接 VPN 后生效", nil)
}

func CcdRemove(w http.ResponseWriter, r *http.Request) {
	id := atoiSafe(r.URL.Query().Get("id"))
	var sid int64
	var username string
	if db.DB.QueryRow(`SELECT service_id,username FROM ccd WHERE id=?`, id).Scan(&sid, &username) != nil {
		util.Fail(w, "记录不存在")
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM ccd WHERE id=?`, id); err != nil {
		util.Fail(w, "删除失败")
		return
	}
	if s, err := resolveService("", sid); err == nil {
		removeCcdFile(s, sid, username)
	}
	util.OKMsg(w, "已删除", nil)
}

func CcdUpdate(w http.ResponseWriter, r *http.Request) {
	var c vpn.Ccd
	if err := util.ReadJSON(r, &c); err != nil || c.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	var sid int64
	var username string
	if db.DB.QueryRow(`SELECT service_id,username FROM ccd WHERE id=?`, c.ID).Scan(&sid, &username) != nil {
		util.Fail(w, "记录不存在")
		return
	}
	c.ServiceID, c.Username = sid, username
	if _, err := db.DB.Exec(`UPDATE ccd SET ifconfig_push=?,iroutes=?,push_routes=?,dns=?,proxy_mode=?,raw=?,updated_at=? WHERE id=?`,
		c.IfconfigPush, c.Iroutes, c.PushRoutes, c.DNS, c.ProxyMode, c.Raw, db.Now(), c.ID); err != nil {
		util.Fail(w, "更新失败")
		return
	}
	if s, err := resolveService("", c.ServiceID); err == nil {
		_ = writeCcdFile(s, &c)
	}
	util.OKMsg(w, "已更新，用户重新连接 VPN 后生效", nil)
}

func CcdAllUser(w http.ResponseWriter, r *http.Request) {
	list := scanAccounts(`WHERE status=1`)
	names := make([]string, 0, len(list))
	for _, a := range list {
		names = append(names, a.Username)
	}
	util.OK(w, map[string]any{"users": names})
}

func CcdCopy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     int64    `json:"id"`
		Target []string `json:"targets"` // 复制到这些用户
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 || len(req.Target) == 0 {
		util.Fail(w, "参数错误")
		return
	}
	var sid int64
	var ip, ir, pr, dns, raw string
	var pm int64
	if db.DB.QueryRow(`SELECT service_id,ifconfig_push,iroutes,push_routes,COALESCE(dns,''),COALESCE(proxy_mode,0),COALESCE(raw,'') FROM ccd WHERE id=?`,
		req.ID).Scan(&sid, &ip, &ir, &pr, &dns, &pm, &raw) != nil {
		util.Fail(w, "源配置不存在")
		return
	}
	n := 0
	for _, u := range req.Target {
		var exists int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM ccd WHERE service_id=? AND username=?`, sid, u).Scan(&exists)
		if exists > 0 {
			continue
		}
		if _, err := db.DB.Exec(`INSERT INTO ccd(service_id,username,ifconfig_push,iroutes,push_routes,dns,proxy_mode,raw,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, sid, u, ip, ir, pr, dns, pm, raw, db.Now(), db.Now()); err == nil {
			if s, err := resolveService("", sid); err == nil {
				_ = writeCcdFile(s, &vpn.Ccd{ServiceID: sid, Username: u, IfconfigPush: ip,
					Iroutes: ir, PushRoutes: pr, DNS: dns, ProxyMode: int(pm), Raw: raw})
			}
			n++
		}
	}
	util.OK(w, map[string]int{"copied": n})
}

func CcdBatchDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := util.ReadJSON(r, &req); err != nil || len(req.IDs) == 0 {
		util.Fail(w, "参数错误")
		return
	}
	n := 0
	for _, id := range req.IDs {
		var sid int64
		var username string
		if db.DB.QueryRow(`SELECT service_id,username FROM ccd WHERE id=?`, id).Scan(&sid, &username) == nil {
			if _, err := db.DB.Exec(`DELETE FROM ccd WHERE id=?`, id); err == nil {
				if s, err := resolveService("", sid); err == nil {
					removeCcdFile(s, sid, username)
				}
				n++
			}
		}
	}
	util.OK(w, map[string]int{"deleted": n})
}

func CcdServiceIn(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "参数错误")
		return
	}
	rows, err := db.DB.Query(`SELECT s.id,s.name,c.ifconfig_push,c.iroutes,c.push_routes
		FROM service s LEFT JOIN ccd c ON c.service_id=s.id AND c.username=?
		ORDER BY s.id`, req.Username)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int64
		var name string
		var ip, ir, pr *string
		if rows.Scan(&id, &name, &ip, &ir, &pr) == nil {
			m := map[string]any{"id": id, "name": name}
			if ip != nil {
				m["ifconfig_push"] = *ip
				m["iroutes"] = *ir
				m["push_routes"] = *pr
			}
			list = append(list, m)
		}
	}
	util.OK(w, map[string]any{"list": list})
}

// ---------- 分组 ----------

func GroupList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT g.id,g.name,g.note,
		(SELECT COUNT(*) FROM account a WHERE a.group_id=g.id),
		(SELECT COUNT(*) FROM group_service gs WHERE gs.group_id=g.id)
		FROM "group" g ORDER BY g.id`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, users, svcs int64
		var name, note string
		if rows.Scan(&id, &name, &note, &users, &svcs) == nil {
			list = append(list, map[string]any{"id": id, "name": name, "note": note, "users": users, "services": svcs})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func GroupAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Name == "" {
		util.Fail(w, "分组名不能为空")
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO "group"(name,note,created_at) VALUES(?,?,datetime('now','localtime'))`, req.Name, req.Note); err != nil {
		util.Fail(w, "创建失败（可能重名）")
		return
	}
	util.OKMsg(w, "分组已创建", nil)
}

func GroupRemove(w http.ResponseWriter, r *http.Request) {
	id := atoiSafe(r.URL.Query().Get("id"))
	if _, err := db.DB.Exec(`DELETE FROM "group" WHERE id=?`, id); err != nil {
		util.Fail(w, "删除失败")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM group_service WHERE group_id=?`, id)
	_, _ = db.DB.Exec(`UPDATE account SET group_id=0 WHERE group_id=?`, id)
	util.OKMsg(w, "分组已删除", nil)
}

func GroupUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 || req.Name == "" {
		util.Fail(w, "参数错误")
		return
	}
	if _, err := db.DB.Exec(`UPDATE "group" SET name=?,note=? WHERE id=?`, req.Name, req.Note, req.ID); err != nil {
		util.Fail(w, "更新失败")
		return
	}
	util.OKMsg(w, "已更新", nil)
}

// writeCcdFile 写 CCD 文件时，把「按用户的域名分流」路由一并带上。
// CCD 在客户端连接时读取，所以这里改完只需用户重连，不触发实例重启。
func writeCcdFile(s *vpn.Service, c *vpn.Ccd) error {
	c.ExtraRoutes = vpn.DomainRouteForUser(db.DB, c.ServiceID, c.Username)
	return vpn.WriteCcd(s.Name, c)
}

// removeCcdFile 删除 CCD 文件；若该用户仍有域名分流规则，则保留一个只含路由的文件，
// 避免「删掉 CCD 配置」把域名分流一起弄丢。
func removeCcdFile(s *vpn.Service, serviceID int64, username string) {
	if routes := vpn.DomainRouteForUser(db.DB, serviceID, username); len(routes) > 0 {
		_ = vpn.WriteCcd(s.Name, &vpn.Ccd{ServiceID: serviceID, Username: username, ExtraRoutes: routes})
		return
	}
	_ = vpn.RemoveCcd(s.Name, username)
}
