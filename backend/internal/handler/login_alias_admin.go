package handler

import (
	"net/http"
	"strings"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// normalizeLoginAliases 规范管理员填写的 UPN/DN 登录别名：
// 逗号/分号/空白分隔、小写去重、只保留含 @ 且字符合法的值。
// 短账号与 DN 常无字符串对应关系（如 zhangsan ↔ zhangsan@example.com），
// 因此别名一律显式配置，不做任何前缀推导。
func normalizeLoginAliases(s string) string {
	seen := map[string]bool{}
	out := []string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		a := strings.ToLower(strings.TrimSpace(part))
		if a == "" || !strings.Contains(a, "@") || !validName(a) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return strings.Join(out, ",")
}

// LoginAliasGet GET /system/loginAlias/get —— 短账号固定开启，另两种方式可开关。
func LoginAliasGet(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]any{
		"short": true,
		"mail":  db.GetSetting(vpn.SetAliasMail) == "1",
		"upn":   db.GetSetting(vpn.SetAliasUPN) == "1",
	})
}

// LoginAliasSave POST /system/loginAlias/save
func LoginAliasSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mail bool `json:"mail"`
		UPN  bool `json:"upn"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	db.SetSetting(vpn.SetAliasMail, flag(req.Mail))
	db.SetSetting(vpn.SetAliasUPN, flag(req.UPN))
	db.Syslog("admin", "登录方式设置",
		"邮箱别名="+flag(req.Mail)+"，UPN/DN别名="+flag(req.UPN), clientIP(r))
	util.OKMsg(w, "登录方式已保存", nil)
}
