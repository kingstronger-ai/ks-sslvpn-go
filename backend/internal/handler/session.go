// 管理员会话管理（B1-1）：列出会话、吊销指定 jti、吊销自己全部会话。
package handler

import (
	"net/http"

	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
)

// AdminSessions GET：列出全部管理员会话（含吊销状态、IP/UA）
func AdminSessions(w http.ResponseWriter, r *http.Request) {
	list, err := middleware.ListSessions()
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	util.OK(w, map[string]any{"list": list})
}

// AdminSessionRevoke POST：吊销指定 jti。普通管理员只能吊销自己的会话，super 可吊销任意会话。
func AdminSessionRevoke(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		if _, isToken := middleware.TokenInfoFromContext(r.Context()); isToken {
			util.Fail(w, "API Token 没有管理员会话身份，不支持吊销管理员会话；请在管理页操作")
			return
		}
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	var req struct {
		JTI string `json:"jti"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.JTI == "" {
		util.Fail(w, "参数错误")
		return
	}
	if !caller.Super {
		owner, found := sessionOwner(req.JTI)
		if !found || owner != caller.ID {
			syslogFromRequest(r, "越权尝试", "普通管理员试图吊销他人会话")
			util.FailCode(w, 403, "普通管理员只能吊销自己的会话")
			return
		}
	}
	middleware.RevokeJTI(req.JTI)
	syslogFromRequest(r, "吊销会话", req.JTI)
	util.OKMsg(w, "会话已吊销", nil)
}

// AdminSessionRevokeAll POST：吊销自己的全部会话（含当前会话，操作后需重新登录）
func AdminSessionRevokeAll(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	middleware.RevokeAdmin(caller.ID)
	syslogFromRequest(r, "吊销本人全部会话", "")
	util.OKMsg(w, "已吊销全部会话，请重新登录", nil)
}

func sessionOwner(jti string) (int64, bool) {
	list, err := middleware.ListSessions()
	if err != nil {
		return 0, false
	}
	for _, s := range list {
		if s.JTI == jti {
			return s.AdminID, true
		}
	}
	return 0, false
}
