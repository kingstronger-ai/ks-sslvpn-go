// 防火墙端口规则删除（骨架补齐）：先撤 iptables 规则，再删数据库记录。
package handler

import (
	"fmt"
	"net/http"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/util"
)

// PortRuleDelete POST /system/delPortRule
// 顺序：iptables 成功才删记录；任一步失败返回 500 且不删记录，避免界面显示已删但规则仍在生效。
func PortRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID <= 0 {
		util.Fail(w, "参数错误")
		return
	}
	var port int
	var proto, action, source string
	if err := db.DB.QueryRow(`SELECT port,proto,action,source FROM port_rule WHERE id=?`, req.ID).
		Scan(&port, &proto, &action, &source); err != nil {
		util.Fail(w, "规则不存在")
		return
	}
	if err := fw.DeleteRule(port, proto, action, source); err != nil {
		util.FailCode(w, http.StatusInternalServerError, "iptables 规则删除失败: "+err.Error())
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM port_rule WHERE id=?`, req.ID); err != nil {
		util.FailCode(w, http.StatusInternalServerError, "数据库记录删除失败: "+err.Error())
		return
	}
	syslogFromRequest(r, "删除防火墙规则", fmt.Sprintf("#%d %d/%s %s source=%s", req.ID, port, proto, action, source))
	util.OKMsg(w, "规则已删除", nil)
}
