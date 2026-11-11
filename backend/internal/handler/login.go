// login / captcha / 找回密码 / 注册 / 轮询
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
	"sslvpn/internal/mail"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// ---------- 登录 ----------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Captcha  string `json:"captcha"`
	CodeID   string `json:"code_id"`
}

var loginAttempts = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

func LoginCheck(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	ip := clientIP(r)

	// 登录失败次数限制（防爆破）
	loginAttempts.Lock()
	if loginAttempts.m[ip] >= 10 {
		loginAttempts.Unlock()
		util.Fail(w, "失败次数过多，请 10 分钟后再试")
		return
	}
	loginAttempts.Unlock()

	// 图形验证码
	if !checkCaptcha(req.CodeID, req.Captcha) {
		util.Fail(w, "验证码错误")
		return
	}

	var hash string
	var status int
	err := db.DB.QueryRow(`SELECT password, status FROM admin WHERE username=?`, req.Username).
		Scan(&hash, &status)
	if err != nil || status != 1 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		loginAttempts.Lock()
		loginAttempts.m[ip]++
		loginAttempts.Unlock()
		db.Syslog(req.Username, "登录失败", "用户名或密码错误", ip)
		util.Fail(w, "用户名或密码错误")
		return
	}

	loginAttempts.Lock()
	delete(loginAttempts.m, ip)
	loginAttempts.Unlock()

	token := middleware.MakeSession()
	http.SetCookie(w, &http.Cookie{
		Name: "sslvpn_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	db.Syslog(req.Username, "登录成功", "", ip)
	if n, err := strconv.Atoi(db.GetSetting("login_count")); err == nil {
		db.SetSetting("login_count", strconv.Itoa(n+1))
	} else {
		db.SetSetting("login_count", "1")
	}
	util.OKMsg(w, "登录成功", map[string]string{"token": token})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sslvpn_session", Value: "", Path: "/", MaxAge: -1})
	util.OKMsg(w, "已退出", nil)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// ---------- 图形验证码（算术式，SVG 输出） ----------

var captchaStore = struct {
	sync.Mutex
	m       map[string]string
	expired map[string]time.Time
}{m: map[string]string{}, expired: map[string]time.Time{}}

func Captcha(w http.ResponseWriter, r *http.Request) {
	a, b := time.Now().Unix()%9+1, time.Now().UnixNano()%9+1
	ans := fmt.Sprint(a + b)
	id := util.RandomHex(8)
	captchaStore.Lock()
	// 清理过期项
	for k := range captchaStore.m {
		if len(k) > 0 && captchaStore.expired[k].Before(time.Now()) {
			delete(captchaStore.m, k)
			delete(captchaStore.expired, k)
		}
	}
	captchaStore.m[id] = ans
	captchaStore.expired[id] = time.Now().Add(5 * time.Minute)
	captchaStore.Unlock()

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40">
<rect width="120" height="40" fill="#f0f2f5"/>
<text x="60" y="27" font-size="22" text-anchor="middle" fill="#333">%d + %d = ?</text></svg>`, a, b)
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("X-Captcha-Id", id)
	util.OK(w, map[string]string{"code_id": id, "svg": svg})
}

func checkCaptcha(id, input string) bool {
	// 管理登录始终需要验证码：留空、缺 code_id 一律拒绝，防止脚本不带 captcha 字段绕过
	if strings.TrimSpace(id) == "" || strings.TrimSpace(input) == "" {
		return false
	}
	captchaStore.Lock()
	defer captchaStore.Unlock()
	ans, ok := captchaStore.m[id]
	if !ok {
		return false
	}
	delete(captchaStore.m, id)
	return ans == strings.TrimSpace(input)
}

// ---------- VPN 用户自助注册 / 找回 ----------

func smtpCfg() *mail.Config { return loadSMTP() }

func GetFlag(w http.ResponseWriter, r *http.Request) {
	// 返回系统标识信息（原系统用于前端初始化判断）
	util.OK(w, map[string]any{
		"flag":          "sslvpn-go",
		"register":      db.GetSetting("register_user_status") == "1",
		"sys_name":      db.GetSetting("sys_name"),
		"download_url":  db.GetSetting("download_url"),
		"copyright":     db.GetSetting("copyright"),
		"copyright_url": db.GetSetting("copyright_url"),
	})
}

func GetSafeCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Email == "" {
		util.Fail(w, "请输入管理员邮箱")
		return
	}
	var username string
	err := db.DB.QueryRow(`SELECT username FROM admin WHERE email=?`, req.Email).Scan(&username)
	if err != nil {
		util.Fail(w, "邮箱未绑定任何管理员")
		return
	}
	code := util.RandomCode(6)
	_, _ = db.DB.Exec(`INSERT INTO secure_code(target,code,expire_at) VALUES(?,?,?)`,
		req.Email, code, time.Now().Add(10*time.Minute).Format("2006-01-02 15:04:05"))
	c := loadSMTP()
	if err := mail.Send(c, req.Email, "SSLVPN 管理密码找回",
		"<p>您的安全验证码是：<b>"+code+"</b>，10 分钟内有效。</p>"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "安全码已发送至邮箱", nil)
}

func CheckCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
		Pass  string `json:"password"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	var id int64
	err := db.DB.QueryRow(`SELECT id FROM secure_code WHERE target=? AND code=? AND expire_at>datetime('now','localtime')`,
		req.Email, req.Code).Scan(&id)
	if err != nil {
		util.Fail(w, "安全码无效或已过期")
		return
	}
	if len(req.Pass) < 8 {
		util.Fail(w, "新密码长度至少 8 位")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Pass), bcrypt.DefaultCost)
	if _, err := db.DB.Exec(`UPDATE admin SET password=?, updated_at=datetime('now','localtime') WHERE email=?`, hash, req.Email); err != nil {
		util.Fail(w, "重置失败")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE id=?`, id)
	util.OKMsg(w, "密码已重置，请使用新密码登录", nil)
}

func GetCodeByVpnUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "请输入 VPN 用户名")
		return
	}
	var email string
	err := db.DB.QueryRow(`SELECT email FROM account WHERE username=? AND status=1`, req.Username).Scan(&email)
	if err != nil || email == "" {
		util.Fail(w, "用户不存在或未绑定邮箱")
		return
	}
	code := util.RandomCode(6)
	_, _ = db.DB.Exec(`INSERT INTO secure_code(target,code,expire_at) VALUES(?,?,?)`,
		req.Username, code, time.Now().Add(10*time.Minute).Format("2006-01-02 15:04:05"))
	if err := mail.Send(loadSMTP(), email, "VPN 密码找回",
		"<p>您的安全验证码是：<b>"+code+"</b>，10 分钟内有效。</p>"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "安全码已发送至绑定邮箱", nil)
}

func FindVpnUserPasswd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Code     string `json:"code"`
		Pass     string `json:"password"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	var id int64
	err := db.DB.QueryRow(`SELECT id FROM secure_code WHERE target=? AND code=? AND expire_at>datetime('now','localtime')`,
		req.Username, req.Code).Scan(&id)
	if err != nil {
		util.Fail(w, "安全码无效或已过期")
		return
	}
	if len(req.Pass) < 6 {
		util.Fail(w, "新密码长度至少 6 位")
		return
	}
	if _, err := db.DB.Exec(`UPDATE account SET password=?, updated_at=datetime('now','localtime') WHERE username=?`,
		req.Pass, req.Username); err != nil {
		util.Fail(w, "重置失败")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE id=?`, id)
	syncAuthFiles()
	util.OKMsg(w, "VPN 密码已重置", nil)
}

func GetRegisterVpnUserCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Email == "" {
		util.Fail(w, "请输入邮箱")
		return
	}
	if db.GetSetting("register_user_status") != "1" {
		util.Fail(w, "系统未开放 VPN 用户自助注册")
		return
	}
	code := util.RandomCode(6)
	_, _ = db.DB.Exec(`INSERT INTO secure_code(target,code,expire_at) VALUES(?,?,?)`,
		req.Email, code, time.Now().Add(10*time.Minute).Format("2006-01-02 15:04:05"))
	if err := mail.Send(loadSMTP(), req.Email, "VPN 注册验证码",
		"<p>您的注册验证码是：<b>"+code+"</b>，10 分钟内有效。</p>"); err != nil {
		util.Fail(w, "邮件发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "验证码已发送", nil)
}

func RegisterVpnUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Code     string `json:"code"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if db.GetSetting("register_user_status") != "1" {
		util.Fail(w, "系统未开放注册")
		return
	}
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM secure_code WHERE target=? AND code=? AND expire_at>datetime('now','localtime')`,
		req.Email, req.Code).Scan(&id); err != nil {
		util.Fail(w, "验证码无效或已过期")
		return
	}
	if !validName(req.Username) || len(req.Password) < 6 {
		util.Fail(w, "用户名或密码不符合要求（用户名：字母数字下划线；密码≥6位）")
		return
	}
	var exists int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, req.Username).Scan(&exists)
	if exists > 0 {
		util.Fail(w, "用户名已存在")
		return
	}
	// 自助注册同样受许可用户数上限约束，避免绕过后台限制
	if err := license.CanAddUsers(1); err != nil {
		util.FailCode(w, 403, err.Error())
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO account(username,password,email,status,created_at) VALUES(?,?,?,1,datetime('now','localtime'))`,
		req.Username, req.Password, req.Email); err != nil {
		util.Fail(w, "注册失败")
		return
	}
	license.Invalidate()
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE id=?`, id)
	if err := vpn.IssueUserCert(req.Username); err != nil {
		util.OKMsg(w, "注册成功（证书签发失败，请联系管理员重建配置）", nil)
		return
	}
	syncAuthFiles()
	util.OKMsg(w, "注册成功，请使用账号密码连接 VPN", nil)
}

func GetRegisterCode(w http.ResponseWriter, r *http.Request) {
	// 管理员注册码（与 VPN 用户注册同一机制）
	GetRegisterVpnUserCode(w, r)
}

func RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Code     string `json:"code"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if db.GetSetting("register_admin_status") != "1" {
		util.Fail(w, "系统未开放管理员注册")
		return
	}
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM secure_code WHERE target=? AND code=? AND expire_at>datetime('now','localtime')`,
		req.Email, req.Code).Scan(&id); err != nil {
		util.Fail(w, "验证码无效或已过期")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,email,status,created_at) VALUES(?,?,?,1,datetime('now','localtime'))`,
		req.Username, hash, req.Email); err != nil {
		util.Fail(w, "注册失败（用户名可能已存在）")
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE id=?`, id)
	util.OKMsg(w, "管理员注册成功", nil)
}

// 允许 '@'：LDAP/AD 支持邮箱形态账号（filter 配成 (mail=%s) 或 (userPrincipalName=%s)）。
// 其余特殊字符仍禁止，避免进入 LDAP filter、证书 CN 与 .ovpn 文件名。
func validName(s string) bool {
	if s == "" || len(s) > 64 { // 上限 64：与 X.509 CN 长度上限一致（证书/SQL 均安全）
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '@') {
			return false
		}
	}
	return true
}

// ---------- 轮询与在线状态 ----------

func PollingTask(w http.ResponseWriter, r *http.Request) {
	// 检查过期用户并禁用
	res, err := db.DB.Exec(`UPDATE account SET status=0 WHERE status=1 AND expire_date != ''
		AND date(expire_date, '+1 day') < date('now')`)
	affected := int64(0)
	if err == nil {
		affected, _ = res.RowsAffected()
	}
	// 同步认证文件与在线状态
	syncAuthFiles()
	util.OK(w, map[string]any{"disabled": affected, "time": db.Now()})
}

func CheckOnlineStatus(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	online := false
	for _, u := range vpn.AllOnlineUsers() {
		if u.Username == username {
			online = true
			break
		}
	}
	util.OK(w, map[string]bool{"online": online})
}

func DownloadCA(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(vpn.PKIDir, "ca.crt"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
	_, _ = w.Write(data)
}

func sha256s(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
