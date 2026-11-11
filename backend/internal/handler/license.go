// 授权管理 API：查询状态 / 激活许可 / 清除许可
package handler

import (
	"net/http"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
	"sslvpn/internal/util"
)

// LicenseInfo 当前授权状态（公开给登录后的任何角色，授权过期时也要能打开）
// 用户配额按实时账号数覆盖，避免 Check() 的 30s 缓存让页面显示的用量滞后。
func LicenseInfo(w http.ResponseWriter, r *http.Request) {
	st := license.Check()
	license.RefreshUserUsage(&st)
	util.OK(w, st)
}

// LicenseActivate 激活许可串
func LicenseActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Token == "" {
		util.Fail(w, "请粘贴许可内容")
		return
	}
	if _, err := license.Activate(req.Token); err != nil {
		util.Fail(w, err.Error())
		return
	}
	st := license.Check()
	db.Syslog("admin", "激活许可", st.Describe(), clientIP(r))
	util.OKMsg(w, "授权已激活", st)
}

// LicenseClear 解除激活（回到试用/过期状态，用于换机或重新授权）
func LicenseClear(w http.ResponseWriter, r *http.Request) {
	license.ReleaseSeat()
	license.Clear()
	license.Invalidate()
	db.Syslog("admin", "解除激活", "", clientIP(r))
	util.OKMsg(w, "已解除激活", license.Check())
}
