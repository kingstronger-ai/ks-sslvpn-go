// VPN 用户管理
package handler

import (
	"archive/zip"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/license"
	"sslvpn/internal/mail"
	"sslvpn/internal/util"
	"sslvpn/internal/version"
	"sslvpn/internal/vpn"
)

type Account struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthType   string `json:"auth_type"`
	TOTPSecret string `json:"totp_secret,omitempty"`
	Email      string `json:"email"`
	// LoginAliases 逗号分隔的 UPN/DN 登录别名，需管理员在「LDAP 目录 → 登录方式」开启后生效。
	LoginAliases string `json:"login_aliases"`
	ExpireDate   string `json:"expire_date"`
	GroupID      int64  `json:"group_id"`
	Status       int    `json:"status"`
	Online       int    `json:"online"`
	VirtualIP    string `json:"virtual_ip"`
	RealIP       string `json:"real_ip"`
	ConnectedS   int64  `json:"connected_since"`
	Note         string `json:"note"`
	CreatedAt    string `json:"created_at"`
}

func scanAccounts(where string, args ...any) []Account {
	rows, err := db.DB.Query(`SELECT id,username,password,auth_type,email,
		COALESCE(login_aliases,''),COALESCE(expire_date,''),group_id,status,0,note,
		COALESCE(created_at,'') FROM account `+where+` ORDER BY id DESC`, args...)
	if err != nil {
		return []Account{}
	}
	defer rows.Close()
	list := []Account{}
	onlineMap := map[string]vpn.OnlineUser{}
	for _, u := range vpn.AllOnlineUsers() {
		onlineMap[u.Username] = u
	}
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Username, &a.Password, &a.AuthType, &a.Email,
			&a.LoginAliases, &a.ExpireDate, &a.GroupID, &a.Status, &a.Online, &a.Note, &a.CreatedAt); err == nil {
			a.CreatedAt = dbTime(a.CreatedAt)
			if u, ok := onlineMap[a.Username]; ok {
				a.Online = 1
				a.VirtualIP = u.VirtualIP
				a.RealIP = u.RealIP
				a.ConnectedS = u.ConnectedS
			}
			list = append(list, a)
		}
	}
	return list
}

func AccountList(w http.ResponseWriter, r *http.Request) {
	kw := strings.TrimSpace(r.URL.Query().Get("keyword"))
	list := scanAccounts(`WHERE username LIKE '%'||?||'%'`, kw)
	util.OK(w, map[string]any{"list": list, "total": len(list)})
}

func AccountAdd(w http.ResponseWriter, r *http.Request) {
	var a Account
	if err := util.ReadJSON(r, &a); err != nil || !validName(a.Username) {
		util.Fail(w, "用户名不合法")
		return
	}
	if a.AuthType == "" {
		a.AuthType = "local"
	}
	if authTypeNoLocalPassword(a.AuthType) {
		// LDAP 密码由域服务校验；扫码类账号走一次性口令，本地都不保存密码
		a.Password = "-"
	} else if a.Password == "" {
		a.Password = util.RandomPassword(12) // 12 位强随机：大小写 + 数字
	}
	if a.AuthType == "totp" {
		a.TOTPSecret = util.TOTPSecret()
	}
	a.LoginAliases = normalizeLoginAliases(a.LoginAliases)
	var exists int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, a.Username).Scan(&exists)
	if exists > 0 {
		util.Fail(w, "用户名已存在")
		return
	}
	// 许可用户数上限（不带 -max-users 签发的许可无限制）
	if err := license.CanAddUsers(1); err != nil {
		util.FailCode(w, 403, err.Error())
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,totp_secret,email,login_aliases,expire_date,group_id,status,note,created_at)
		VALUES(?,?,?,?,?,?,?,?,1,?,datetime('now','localtime'))`,
		a.Username, a.Password, a.AuthType, a.TOTPSecret, a.Email, a.LoginAliases,
		a.ExpireDate, a.GroupID, a.Note); err != nil {
		util.Fail(w, "创建失败: "+err.Error())
		return
	}
	license.Invalidate()
	if err := vpn.IssueUserCert(a.Username); err != nil {
		util.OKMsg(w, "用户已创建，但证书签发失败: "+err.Error(), nil)
		return
	}
	syncAuthFiles()
	sendAccountMail(&a)
	db.Syslog("admin", "添加VPN用户", a.Username, clientIP(r))
	util.OKMsg(w, "创建成功", map[string]any{"username": a.Username, "password": a.Password})
}

func sendAccountMail(a *Account) {
	if a.Email == "" {
		return
	}
	subject, body := renderMailTemplate(a)
	atts := accountMailAtts(a)
	_ = mail.SendWithAttachments(loadSMTP(), a.Email, subject, body, atts)
}

// accountMailAtts 按后台开关组装账号邮件附件。
// 开关关闭（默认）：只发 VPN 配置文件（历史行为）；开启后按勾选组合
// 配置文件 / Windows 客户端 / macOS 客户端——客户端发送可以不带配置文件。
func accountMailAtts(a *Account) []mail.Attachment {
	attach, useCfg, useWin, useMac := accountMailAttachMode()
	var atts []mail.Attachment
	if name, data := buildUserCfgTgz(a); name != "" && len(data) > 0 && (!attach || useCfg) {
		atts = append(atts, mail.Attachment{Name: name, Data: data})
	}
	if attach {
		var platforms []string
		if useWin {
			platforms = append(platforms, "windows")
		}
		if useMac {
			platforms = append(platforms, "macos")
		}
		atts = append(atts, clientInstallerAtts(platforms...)...)
	}
	return atts
}

// 默认邮件模板（HTML）—— 本地账号默认
const defMailSubject = "VPN 账号开通通知"
const defMailBody = `<div style="font-family:Arial,'Microsoft YaHei',sans-serif;max-width:560px;margin:0 auto">
  <h2 style="color:#409eff;border-bottom:2px solid #409eff;padding-bottom:8px">VPN 账号开通通知</h2>
  <p>您好，您的 VPN 账号已开通，信息如下：</p>
  <table style="border-collapse:collapse;width:100%;font-size:14px">
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc;width:120px">VPN 账号</td><td style="padding:8px;border:1px solid #ebeef5"><b>{username}</b></td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">密码</td><td style="padding:8px;border:1px solid #ebeef5"><b style="color:#f56c6c">{password}</b></td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">到期时间</td><td style="padding:8px;border:1px solid #ebeef5">{expire}</td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">客户端下载</td><td style="padding:8px;border:1px solid #ebeef5">{download_url}</td></tr>
  </table>
  <p style="color:#000000;font-weight:bold;font-size:14px;margin-top:14px;line-height:1.7">{auth_note}</p>
  <p style="color:#000000;font-weight:bold;font-size:14px;margin-top:14px;line-height:1.7">请勿泄露账号密码。使用中如有问题请联系管理员。</p>
</div>`

// LDAP 账号默认邮件模板（密码由域/LDAP 校验，按公司飞书邮件发放，此处给出指引）
const defMailSubjectLDAP = "VPN 账号开通通知"
const defMailBodyLDAP = `<div style="font-family:Arial,'Microsoft YaHei',sans-serif;max-width:560px;margin:0 auto">
  <h2 style="color:#409eff;border-bottom:2px solid #409eff;padding-bottom:8px">VPN 账号开通通知</h2>
  <p>您好，您的 VPN 账号已开通，信息如下：</p>
  <table style="border-collapse:collapse;width:100%;font-size:14px">
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc;width:120px">VPN 账号</td><td style="padding:8px;border:1px solid #ebeef5"><b>{username}</b></td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">密码</td><td style="padding:8px;border:1px solid #ebeef5"><b style="color:#f56c6c">账号密码信息请在飞书邮件中搜索，入职当天收到的LDAP账号和密码邮件。</b></td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">到期时间</td><td style="padding:8px;border:1px solid #ebeef5">{expire}</td></tr>
    <tr><td style="padding:8px;border:1px solid #ebeef5;background:#fafbfc">客户端下载</td><td style="padding:8px;border:1px solid #ebeef5">{download_url}</td></tr>
  </table>
  <p style="color:#000000;font-weight:bold;font-size:14px;margin-top:14px;line-height:1.7">{auth_note}</p>
</div>`

// renderMailTemplate 渲染邮件主题与正文
// 占位符：{username} {password} {expire} {download_url} {sys_name} {auth_note}
// 本地账号用 mail_subject/mail_body；LDAP 账号优先用 mail_subject_ldap/mail_body_ldap（留空回落到 LDAP 默认模板）。
func renderMailTemplate(a *Account) (string, string) {
	suffix := ""
	if a.AuthType == "ldap" {
		suffix = "_ldap"
	}
	subject := db.GetSetting("mail_subject" + suffix)
	body := db.GetSetting("mail_body" + suffix)
	if strings.TrimSpace(subject) == "" {
		if suffix == "_ldap" {
			subject = defMailSubjectLDAP
		} else {
			subject = defMailSubject
		}
	}
	if strings.TrimSpace(body) == "" {
		if suffix == "_ldap" {
			body = defMailBodyLDAP
		} else {
			body = defMailBody
		}
	}
	expire := a.ExpireDate
	if expire == "" {
		expire = "永久"
	}
	r := strings.NewReplacer(
		"{username}", a.Username,
		"{password}", pwdDisplay(a),
		"{expire}", expire,
		"{download_url}", db.GetSetting("download_url"),
		"{sys_name}", db.GetSetting("sys_name"),
		"{auth_note}", authNote(a),
	)
	return r.Replace(subject), polishMailBody(r.Replace(body))
}

// polishMailBody 对渲染后的正文做兼容处理：
//  1. 老版本模板（含管理员保存过的自定义模板）里的提示用 #909399 灰色小字，看不清，
//     统一升为加粗纯黑；
//  2. 自定义 LDAP 模板可能把“解压导入配置文件”写死在正文里——开启附带客户端后
//     替换为“直接安装客户端登录”的指引，避免与附件内容自相矛盾。
func polishMailBody(body string) string {
	if strings.Contains(body, "#909399") {
		body = strings.ReplaceAll(body, "#909399", "#000000;font-weight:bold")
	}
	if h := installHint(); h != "" {
		for _, old := range []string{
			`请下载附件中的tgz 文件，解压后双击导入VPN客户端。`,
			`请下载附件中的tgz文件，解压后双击导入VPN客户端。`,
			`附件为该账号的 VPN 客户端配置文件，解压后导入 VPN 客户端即可使用。`,
		} {
			body = strings.ReplaceAll(body, old, h)
		}
	}
	return body
}

// MailTemplateGet 获取邮件模板（本地 + LDAP 两套，LDAP 为空表示使用 LDAP 默认模板）
func MailTemplateGet(w http.ResponseWriter, r *http.Request) {
	subject := db.GetSetting("mail_subject")
	body := db.GetSetting("mail_body")
	if strings.TrimSpace(subject) == "" {
		subject = defMailSubject
	}
	if strings.TrimSpace(body) == "" {
		body = defMailBody
	}
	ldapSubject := db.GetSetting("mail_subject_ldap")
	if strings.TrimSpace(ldapSubject) == "" {
		ldapSubject = defMailSubjectLDAP
	}
	ldapBody := db.GetSetting("mail_body_ldap")
	if strings.TrimSpace(ldapBody) == "" {
		ldapBody = defMailBodyLDAP
	}
	util.OK(w, map[string]string{
		"subject": subject, "body": body,
		"subject_ldap": ldapSubject,
		"body_ldap":    ldapBody,
	})
}

// MailTemplateUpdate 保存邮件模板（传空恢复默认；LDAP 模板留空表示使用 LDAP 默认模板）
func MailTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject     string `json:"subject"`
		Body        string `json:"body"`
		SubjectLDAP string `json:"subject_ldap"`
		BodyLDAP    string `json:"body_ldap"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	db.SetSetting("mail_subject", strings.TrimSpace(req.Subject))
	db.SetSetting("mail_body", strings.TrimSpace(req.Body))
	db.SetSetting("mail_subject_ldap", strings.TrimSpace(req.SubjectLDAP))
	db.SetSetting("mail_body_ldap", strings.TrimSpace(req.BodyLDAP))
	db.Syslog("admin", "修改邮件模板", "", clientIP(r))
	util.OKMsg(w, "邮件模板已保存", nil)
}

func AccountDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || (req.ID == 0 && req.Username == "") {
		util.Fail(w, "参数错误")
		return
	}
	if req.ID == 0 {
		_ = db.DB.QueryRow(`SELECT id FROM account WHERE username=?`, req.Username).Scan(&req.ID)
	}
	var username string
	if err := db.DB.QueryRow(`SELECT username FROM account WHERE id=?`, req.ID).Scan(&username); err != nil {
		util.Fail(w, "用户不存在")
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM account WHERE id=?`, req.ID); err != nil {
		util.Fail(w, "删除失败")
		return
	}
	license.Invalidate()
	_ = vpn.RevokeUserCert(username)
	// 清理各实例 CCD
	if rows, err := db.DB.Query(`SELECT name FROM service`); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				_ = vpn.RemoveCcd(n, username)
			}
		}
		rows.Close()
	}
	syncAuthFiles()
	db.Syslog("admin", "删除VPN用户", username, clientIP(r))
	util.OKMsg(w, "删除成功（证书已吊销）", nil)
}

func AccountUpdate(w http.ResponseWriter, r *http.Request) {
	var a Account
	if err := util.ReadJSON(r, &a); err != nil || a.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	// LDAP 账号密码由域服务校验，本地不保存（忽略提交的密码）
	var curAuth string
	if err := db.DB.QueryRow(`SELECT auth_type FROM account WHERE id=?`, a.ID).Scan(&curAuth); err != nil {
		util.Fail(w, "用户不存在")
		return
	}
	if authTypeNoLocalPassword(curAuth) {
		a.Password = "-"
	}
	if _, err := db.DB.Exec(`UPDATE account SET password=?,email=?,login_aliases=?,expire_date=?,group_id=?,status=?,note=?,
		updated_at=datetime('now','localtime') WHERE id=?`,
		a.Password, a.Email, normalizeLoginAliases(a.LoginAliases),
		a.ExpireDate, a.GroupID, a.Status, a.Note, a.ID); err != nil {
		util.Fail(w, "更新失败")
		return
	}
	syncAuthFiles()
	db.Syslog("admin", "更新VPN用户", a.Username, clientIP(r))
	util.OKMsg(w, "更新成功", nil)
}

func SystemInfo(w http.ResponseWriter, r *http.Request) {
	util.OK(w, systemInfoMap())
}

func systemInfoMap() map[string]any {
	mi, _ := os.Hostname()
	m := map[string]any{
		"version":         version.Version,
		"hostname":        mi,
		"sys_name":        db.GetSetting("sys_name"),
		"now":             db.Now(),
		"pki_dir":         vpn.PKIDir,
		"base_dir":        vpn.BaseDir,
		"login_count":     db.GetSetting("login_count"),
		"uptime":          uptimeStr(),
		"openvpn_version": openvpnVersion(),
		"server_ip":       outboundIP(),
		"os_type":         runtime.GOOS,
	}
	m["mem_percent"], m["mem_total_mb"], m["mem_used_mb"] = memUsage()
	m["load1"] = loadAvg1()
	m["disk_percent"], m["disk_total_gb"], m["disk_free_gb"] = diskUsage()
	// 计数
	var uTotal, uEnabled int
	_ = db.DB.QueryRow(`SELECT COUNT(*),COALESCE(SUM(status=1),0) FROM account`).Scan(&uTotal, &uEnabled)
	var svcTotal, svcRunning int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM service`).Scan(&svcTotal)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM service WHERE status=1`).Scan(&svcRunning)
	var grpTotal int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM "group"`).Scan(&grpTotal)
	online := len(vpn.AllOnlineUsers())
	m["user_total"] = uTotal
	m["user_enabled"] = uEnabled
	m["user_disabled"] = uTotal - uEnabled
	m["user_online"] = online
	m["service_total"] = svcTotal
	m["service_running"] = svcRunning
	m["group_total"] = grpTotal
	return m
}

// uptimeStr 运行时长（读 /proc/uptime，非 Linux 返回占位）
func uptimeStr() string {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "-"
	}
	sec, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	d := int(sec) / 86400
	h := (int(sec) % 86400) / 3600
	min := (int(sec) % 3600) / 60
	return fmt.Sprintf("%d天 %d小时 %d分钟", d, h, min)
}

func loadAvg1() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "-"
	}
	return strings.Fields(string(b))[0]
}

func memUsage() (int, int, int) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	vals := map[string]int{}
	for _, line := range strings.Split(string(b), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 2 {
			n, _ := strconv.Atoi(fs[1])
			vals[strings.TrimSuffix(fs[0], ":")] = n
		}
	}
	total := vals["MemTotal"]
	avail := vals["MemAvailable"]
	if total <= 0 {
		return 0, 0, 0
	}
	used := total - avail
	return used * 100 / total, total / 1024, used / 1024
}

func diskUsage() (int, float64, float64) {
	// 便携实现：通过 df -kP 获取数据分区使用率
	var total, free uint64
	if out, err := exec.Command("df", "-kP", vpn.PKIDir).Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fs := strings.Fields(lines[len(lines)-1])
			if len(fs) >= 4 {
				t, _ := strconv.ParseUint(fs[1], 10, 64)
				a, _ := strconv.ParseUint(fs[3], 10, 64)
				total, free = t*1024, a*1024
			}
		}
	}
	if total == 0 {
		return 0, 0, 0
	}
	used := total - free
	return int(used * 100 / total), float64(total) / 1073741824, float64(free) / 1073741824
}

func openvpnVersion() string {
	out, err := exec.Command(vpn.BinOpenVPN, "--version").Output()
	if err != nil {
		return "-"
	}
	for _, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 2 && fs[0] == "OpenVPN" {
			return fs[1]
		}
	}
	return "-"
}

func outboundIP() string {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "-"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func AccountExport(w http.ResponseWriter, r *http.Request) {
	list := scanAccounts("")
	var sb strings.Builder
	sb.WriteString("ID,用户名,密码,认证类型,邮箱,到期时间,状态,备注,创建时间\n")
	for _, a := range list {
		status := "禁用"
		if a.Status == 1 {
			status = "启用"
		}
		sb.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%s\n",
			a.ID, csvCell(a.Username), csvCell(a.Password), a.AuthType, csvCell(a.Email),
			a.ExpireDate, status, csvCell(a.Note), a.CreatedAt))
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="vpn_users.csv"`)
	_, _ = w.Write([]byte("\xEF\xBB\xBF" + sb.String()))
}

func csvCell(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// CreateAuthorize 创建授权（开源重构版：直接返回成功，无捐赠限制）
func CreateAuthorize(w http.ResponseWriter, r *http.Request) {
	util.OKMsg(w, "授权已创建（社区版，无限制）", nil)
}

// DisableVPNServer 紧急停用所有 VPN 服务
func DisableVPNServer(w http.ResponseWriter, r *http.Request) {
	_ = ServiceStopAllInternal()
	util.OKMsg(w, "所有 VPN 服务已停止", nil)
}

func AccountBatchUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Users []struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			Email      string `json:"email"`
			ExpireDate string `json:"expire_date"`
			Note       string `json:"note"`
		} `json:"users"`
	}
	if err := util.ReadJSON(r, &req); err != nil || len(req.Users) == 0 {
		util.Fail(w, "请提供用户数组（username 必填）")
		return
	}
	okN, failN := 0, 0
	var fails []string
	// 许可用户数上限：预取额度并在导入过程中本地累减，超出的用户明确给出拒绝原因
	limit, used, _ := license.UserQuota()
	for _, u := range req.Users {
		if !validName(u.Username) {
			failN++
			fails = append(fails, u.Username+":用户名不合法")
			continue
		}
		if u.Password == "" {
			u.Password = util.RandomPassword(12) // 12 位强随机：大小写 + 数字
		}
		var exists int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, u.Username).Scan(&exists)
		if exists > 0 {
			failN++
			fails = append(fails, u.Username+":已存在")
			continue
		}
		if limit > 0 && used >= limit {
			failN++
			fails = append(fails, fmt.Sprintf("%s:已达授权用户数上限 %d 人", u.Username, limit))
			continue
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,email,expire_date,status,note,created_at)
			VALUES(?,?,?,?,1,?,datetime('now','localtime'))`, u.Username, u.Password, u.Email, u.ExpireDate, u.Note); err != nil {
			failN++
			continue
		}
		used++
		_ = vpn.IssueUserCert(u.Username)
		okN++
	}
	syncAuthFiles()
	license.Invalidate()
	util.OK(w, map[string]any{"ok": okN, "fail": failN, "fails": fails,
		"user_limit": limit, "user_used": used})
}

func AccountBatchDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := util.ReadJSON(r, &req); err != nil || len(req.IDs) == 0 {
		util.Fail(w, "参数错误")
		return
	}
	n := 0
	for _, id := range req.IDs {
		var username string
		if db.DB.QueryRow(`SELECT username FROM account WHERE id=?`, id).Scan(&username) == nil {
			if _, err := db.DB.Exec(`DELETE FROM account WHERE id=?`, id); err == nil {
				_ = vpn.RevokeUserCert(username)
				n++
			}
		}
	}
	syncAuthFiles()
	license.Invalidate()
	util.OK(w, map[string]int{"deleted": n})
}

func StartQueue(w http.ResponseWriter, r *http.Request) {
	PollingTask(w, r)
}

// DownloadUserCfg 下载用户 .ovpn（关联服务）
func DownloadUserCfg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Service  string `json:"service"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" || req.Service == "" {
		util.Fail(w, "参数错误")
		return
	}
	svc, err := serviceByName(req.Service)
	if err != nil {
		util.Fail(w, "服务实例不存在")
		return
	}
	host := vpnRemoteHost(db.GetSetting("public_host"))
	if host == "" {
		host = fw.OutInterfaceIP()
	}
	data, err := vpn.BuildClientConf(svc.Name, req.Username, vpn.ClientConfData{
		Host: host, Port: svc.Port, Proto: svc.Proto, ServerName: svc.Name,
	})
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s@%s.ovpn"`, url.PathEscape(req.Username), svc.Name))
	_, _ = w.Write(data)
}

// RebuildUserCfg 重建用户证书并重新生成配置
func RebuildUserCfg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Service  string `json:"service"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "参数错误")
		return
	}
	_ = vpn.RevokeUserCert(req.Username)
	if err := vpn.IssueUserCert(req.Username); err != nil {
		util.Fail(w, "证书重建失败: "+err.Error())
		return
	}
	util.OKMsg(w, "证书已重建，可重新下载配置文件", nil)
}

func SendUserMail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	list := scanAccounts(`WHERE id=?`, req.ID)
	if len(list) == 0 {
		util.Fail(w, "用户不存在")
		return
	}
	a := list[0]
	if a.Email == "" {
		util.Fail(w, "该用户未绑定邮箱")
		return
	}
	subject, body := renderMailTemplate(&a)
	atts := accountMailAtts(&a)
	if err := mail.SendWithAttachments(loadSMTP(), a.Email, subject, body, atts); err != nil {
		util.Fail(w, "发送失败: "+err.Error())
		return
	}
	names := make([]string, 0, len(atts))
	for _, at := range atts {
		names = append(names, at.Name)
	}
	attach := "无"
	if len(names) > 0 {
		attach = strings.Join(names, ", ")
	}
	util.OKMsg(w, fmt.Sprintf("邮件已发送（含 %d 个附件）", len(atts)), map[string]string{"attachment": attach})
}

func AccountDetail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	list := scanAccounts(`WHERE id=?`, req.ID)
	if len(list) == 0 {
		util.Fail(w, "用户不存在")
		return
	}
	a := list[0]
	// 补查 TOTP 密钥（列表查询不携带该列）
	if a.AuthType == "totp" {
		_ = db.DB.QueryRow(`SELECT totp_secret FROM account WHERE id=?`, req.ID).Scan(&a.TOTPSecret)
	}
	// 附加 TOTP 链接（如启用）
	resp := map[string]any{"user": a}
	if a.AuthType == "totp" && a.TOTPSecret != "" {
		resp["otpauth_url"] = util.OTPAuthURL(defaultBrandName, a.Username, a.TOTPSecret)
	}
	// 在线状态
	for _, u := range vpn.AllOnlineUsers() {
		if u.Username == a.Username {
			resp["online_info"] = u
		}
	}
	util.OK(w, resp)
}

func DownloadUserCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "参数错误")
		return
	}
	crt, err1 := os.ReadFile(vpn.PKIDir + "/issued/" + req.Username + ".crt")
	key, err2 := os.ReadFile(vpn.PKIDir + "/private/" + req.Username + ".key")
	if err1 != nil || err2 != nil {
		util.Fail(w, "证书不存在")
		return
	}
	buf := &bytesBuffer{}
	zw := zip.NewWriter(buf)
	f1, _ := zw.Create(req.Username + ".crt")
	_, _ = f1.Write(crt)
	f2, _ := zw.Create(req.Username + ".key")
	_, _ = f2.Write(key)
	_ = zw.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_cert.zip"`, url.PathEscape(req.Username)))
	_, _ = w.Write(buf.Bytes())
}

func GroupAttach(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "参数错误")
		return
	}
	var gid int64
	_ = db.DB.QueryRow(`SELECT group_id FROM account WHERE username=?`, req.Username).Scan(&gid)
	var services []map[string]any
	if gid > 0 {
		rows, err := db.DB.Query(`SELECT s.id,s.name FROM group_service gs
			JOIN service s ON s.id=gs.service_id WHERE gs.group_id=?`, gid)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				var name string
				if rows.Scan(&id, &name) == nil {
					services = append(services, map[string]any{"id": id, "name": name})
				}
			}
		}
	}
	util.OK(w, map[string]any{"group_id": gid, "services": services})
}

func BatchSendMail(w http.ResponseWriter, r *http.Request) {
	list := scanAccounts(`WHERE email != '' AND status=1`)
	n, withAtt := 0, 0
	for _, a := range list {
		subject, body := renderMailTemplate(&a)
		atts := accountMailAtts(&a)
		if len(atts) > 0 {
			withAtt++
		}
		if mail.SendWithAttachments(loadSMTP(), a.Email, subject, body, atts) == nil {
			n++
		}
	}
	util.OK(w, map[string]int{"sent": n, "total": len(list), "with_attachment": withAtt})
}

func BatchBuildUserFile(w http.ResponseWriter, r *http.Request) {
	list := scanAccounts(`WHERE status=1`)
	n := 0
	for _, a := range list {
		if vpn.IssueUserCert(a.Username) == nil {
			n++
		}
	}
	util.OK(w, map[string]int{"built": n, "total": len(list)})
}

// ---- 小工具 ----

type bytesBuffer struct{ b []byte }

func (x *bytesBuffer) Write(p []byte) (int, error) { x.b = append(x.b, p...); return len(p), nil }
func (x *bytesBuffer) Bytes() []byte               { return x.b }

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }

var _ = time.Now

// authTypeNoLocalPassword 该认证类型不在本地保存密码
// （LDAP 由域服务校验；feishu/sso/dingtalk/wecom 走扫码一次性口令）
func authTypeNoLocalPassword(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ldap", "feishu", "sso", "dingtalk", "wecom":
		return true
	}
	return false
}
