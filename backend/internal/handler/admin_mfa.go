// 管理员 TOTP（B1-2）：设置/启用/关闭/恢复码。util 已有 TOTPSecret/VerifyTOTP/OTPAuthURL。
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
)

// setup 阶段密钥只在内存暂存，enable 校验通过后才落库（不落库直到启用）。
type pendingMFASecret struct {
	secret  string
	expires time.Time
}

var mfaPending = struct {
	sync.Mutex
	m map[int64]pendingMFASecret
}{m: map[int64]pendingMFASecret{}}

// AdminMFAStatus GET：是否启用、是否已设置密钥（绝不回显密钥明文）
func AdminMFAStatus(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	var enabled int
	var secret string
	if err := db.DB.QueryRow(`SELECT COALESCE(totp_enabled,0),COALESCE(totp_secret,'') FROM admin WHERE id=?`, caller.ID).
		Scan(&enabled, &secret); err != nil {
		util.Fail(w, "查询失败")
		return
	}
	util.OK(w, map[string]any{"enabled": enabled == 1, "secret_set": strings.TrimSpace(secret) != ""})
}

// AdminMFASetup POST：生成新密钥并暂存，仅通过 otpauth URI 返回（secret 只在 URI 内）
func AdminMFASetup(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	secret := util.TOTPSecret()
	mfaPending.Lock()
	mfaPending.m[caller.ID] = pendingMFASecret{secret: secret, expires: time.Now().Add(10 * time.Minute)}
	mfaPending.Unlock()
	util.OK(w, map[string]any{
		"otpauth_url": util.OTPAuthURL(defaultBrandName, caller.Username, secret),
		"expires_in":  600,
	})
}

// AdminMFAEnable POST：验证一次性 6 位码通过后才把密钥与恢复码落库启用
func AdminMFAEnable(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	var req struct {
		OTP string `json:"otp"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	mfaPending.Lock()
	pending, ok := mfaPending.m[caller.ID]
	if ok && time.Now().After(pending.expires) {
		delete(mfaPending.m, caller.ID)
		ok = false
	}
	mfaPending.Unlock()
	if !ok || !util.VerifyTOTP(pending.secret, strings.TrimSpace(req.OTP)) {
		util.Fail(w, "动态码错误或设置已过期，请重新获取密钥")
		return
	}
	codes, hashes := generateRecoveryCodes()
	if _, err := db.DB.Exec(`UPDATE admin SET totp_secret=?,totp_enabled=1,totp_recovery=? WHERE id=?`,
		pending.secret, hashes, caller.ID); err != nil {
		util.Fail(w, "启用失败")
		return
	}
	mfaPending.Lock()
	delete(mfaPending.m, caller.ID)
	mfaPending.Unlock()
	syslogFromRequest(r, "启用管理员MFA", "")
	util.OKMsg(w, "MFA 已启用，请妥善保存恢复码", map[string]any{"recovery_codes": codes})
}

// AdminMFADisable POST：校验当前密码 + TOTP 后关闭（恢复码不用于关闭）
func AdminMFADisable(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	var req struct {
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if !verifyAdminPasswordAndTOTP(caller.ID, req.Password, req.OTP) {
		syslogFromRequest(r, "关闭管理员MFA失败", "当前密码或动态码错误")
		util.Fail(w, "当前密码或动态码错误")
		return
	}
	if _, err := db.DB.Exec(`UPDATE admin SET totp_enabled=0,totp_secret='',totp_recovery='' WHERE id=?`, caller.ID); err != nil {
		util.Fail(w, "关闭失败")
		return
	}
	mfaPending.Lock()
	delete(mfaPending.m, caller.ID)
	mfaPending.Unlock()
	syslogFromRequest(r, "关闭管理员MFA", "")
	util.OKMsg(w, "MFA 已关闭", nil)
}

// AdminMFARecovery POST：重置恢复码（同样要求当前密码 + TOTP），旧码立即作废
func AdminMFARecovery(w http.ResponseWriter, r *http.Request) {
	caller, ok := currentAdmin(r)
	if !ok {
		util.Fail(w, "登录状态缺少身份信息，请重新登录后再操作")
		return
	}
	var req struct {
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if !verifyAdminPasswordAndTOTP(caller.ID, req.Password, req.OTP) {
		syslogFromRequest(r, "重置MFA恢复码失败", "当前密码或动态码错误")
		util.Fail(w, "当前密码或动态码错误")
		return
	}
	codes, hashes := generateRecoveryCodes()
	if _, err := db.DB.Exec(`UPDATE admin SET totp_recovery=? WHERE id=?`, hashes, caller.ID); err != nil {
		util.Fail(w, "重置失败")
		return
	}
	syslogFromRequest(r, "重置MFA恢复码", "")
	util.OKMsg(w, "恢复码已重置，旧码已作废", map[string]any{"recovery_codes": codes})
}

// verifyAdminPasswordAndTOTP 当前密码 + 动态码双因子校验（用于关闭 MFA / 重置恢复码）
func verifyAdminPasswordAndTOTP(adminID int64, password, otp string) bool {
	var hash, secret string
	var enabled int
	if err := db.DB.QueryRow(`SELECT password,COALESCE(totp_secret,''),COALESCE(totp_enabled,0) FROM admin WHERE id=?`, adminID).
		Scan(&hash, &secret, &enabled); err != nil || enabled != 1 || secret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil &&
		util.VerifyTOTP(secret, strings.TrimSpace(otp))
}

// generateRecoveryCodes 生成 10 个一次性恢复码；库内只存 sha256 摘要（不存明文）
func generateRecoveryCodes() ([]string, string) {
	const n = 10
	codes := make([]string, n)
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		codes[i] = util.RandomAlnumCode(10)
		hashes[i] = sha256s(codes[i])
	}
	b, _ := json.Marshal(hashes)
	return codes, string(b)
}
