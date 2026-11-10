// Package license 离线授权：Ed25519 签名许可 + 机器码绑定 + 默认 7 天试用
//
// 许可串格式：<base64url(payloadJSON)>.<base64url(signature)>
// payload 形如 {"m":"A1B2-C3D4-E5F6-7890","c":"客户名","e":"2027-12-31","i":"2026-11-03"}
//
// 校验只用内嵌公钥（pub.pem），私钥仅在签发端（deploy/keys/license-private.pem）离线保存。
package license

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
)

//go:embed pub.pem
var pubPEM []byte

// 授权状态
const (
	StateLicensed = "licensed" // 已激活（有效许可）
	StateTrial    = "trial"    // 试用中
	StateExpired  = "expired"  // 已过期（试用到期且无有效许可）
)

const defaultTrialDays = 15

// 绑定模式
const (
	BindMachine = "machine" // 绑定指定机器码（客户需先回传机器码）
	BindNone    = "none"    // 浮动许可：不绑定机器，仅限 1 台同时使用
)

// Payload 许可负载
type Payload struct {
	ID       string `json:"id,omitempty"` // 许可唯一编号（浮动许可用于在线登记）
	Machine  string `json:"m,omitempty"`  // 机器码（BindMachine 时必填）
	Customer string `json:"c,omitempty"`  // 客户名称（公司名）
	Company  string `json:"co,omitempty"` // 公司名称（浮动许可必填）
	Email    string `json:"u,omitempty"`  // 授权邮箱（浮动许可必填）
	Bind     string `json:"b,omitempty"`  // 绑定模式：machine / none（空视为 machine）
	Expire   string `json:"e"`            // 到期日 YYYY-MM-DD（含当日）
	Issued   string `json:"i,omitempty"`  // 签发日
	Edition  string `json:"ed,omitempty"` // 版本标识（可选，如 standard/pro）
	Nodes    int    `json:"n,omitempty"`  // 授权台数上限（0=不限）
}

// Unbound 是否为浮动许可（不绑定机器码）
func (p Payload) Unbound() bool {
	return p.Bind == BindNone || Normalize(p.Machine) == ""
}

// Display 客户展示名（优先公司名，再退回 Customer）
func (p Payload) Display() string {
	if strings.TrimSpace(p.Company) != "" {
		return p.Company
	}
	return p.Customer
}

// Status 授权状态（前端展示用）
type Status struct {
	State       string `json:"state"`
	Machine     string `json:"machine"`
	Customer    string `json:"customer"`
	Company     string `json:"company,omitempty"`
	Email       string `json:"email,omitempty"`
	Bind        string `json:"bind,omitempty"`         // machine / none
	Unbound     bool   `json:"unbound"`                // 是否浮动许可（未绑定机器）
	Nodes       int    `json:"nodes,omitempty"`        // 授权台数
	LicID       string `json:"lic_id,omitempty"`       // 许可编号
	LockMachine string `json:"lock_machine,omitempty"` // 浮动许可首次激活的机器码
	LockTime    string `json:"lock_time,omitempty"`    // 浮动许可首次激活时间
	Registry    bool   `json:"registry"`               // 是否启用了在线登记（硬约束）
	Expire      string `json:"expire"`
	DaysLeft    int    `json:"days_left"`
	TrialDays   int    `json:"trial_days"`
	TrialEnd    string `json:"trial_end"`
	Edition     string `json:"edition"`
	TokenErr    string `json:"token_error,omitempty"`
	ServerTime  string `json:"server_time"`
}

// Expired 是否处于未授权且试用过期状态
func (s Status) Expired() bool { return s.State == StateExpired }

// ---------------- 机器码 ----------------

// Machine 返回本机机器码（首次生成后持久化在 DB，容器重建不变化）
func Machine() string {
	m := db.GetSetting("license_machine")
	if m == "" {
		m = strings.ToUpper(util.RandomHex(8))
		db.SetSetting("license_machine", m)
	}
	return Group(m)
}

// Group 把 16 位机器码格式化为 XXXX-XXXX-XXXX-XXXX
func Group(m string) string {
	m = Normalize(m)
	if len(m) != 16 {
		return m
	}
	return m[0:4] + "-" + m[4:8] + "-" + m[8:12] + "-" + m[12:16]
}

// Normalize 去掉分隔符并大写
func Normalize(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	return strings.NewReplacer("-", "", " ", "", "_", "").Replace(m)
}

// ---------------- 试用期 ----------------

func trialDays() int {
	if v := os.Getenv("SSLVPN_TRIAL_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultTrialDays
}

// trialStart 首次启动时间（写入 DB 后不再变化）
func trialStart() time.Time {
	v := db.GetSetting("license_trial_start")
	if v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0)
		}
	}
	now := time.Now()
	db.SetSetting("license_trial_start", strconv.FormatInt(now.Unix(), 10))
	return now
}

// ---------------- 许可校验 ----------------

func publicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("内嵌公钥解析失败")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("公钥类型不是 Ed25519")
	}
	return ed, nil
}

// Parse 只校验签名并解析负载（不校验机器码与到期），供签发端自检
func Parse(token string) (*Payload, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("许可格式不正确")
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("许可内容解码失败")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("许可签名解码失败")
	}
	pub, err := publicKey()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, rawPayload, sig) {
		return nil, errors.New("许可签名无效（可能被篡改或非本系统签发）")
	}
	var p Payload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return nil, errors.New("许可内容解析失败")
	}
	return &p, nil
}

// Verify 校验许可串：签名有效 + 机器码匹配 + 未过期
func Verify(token, machine string) (*Payload, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("许可格式不正确")
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("许可内容解码失败")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("许可签名解码失败")
	}
	pub, err := publicKey()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, rawPayload, sig) {
		return nil, errors.New("许可签名无效（可能被篡改或非本系统签发）")
	}
	var p Payload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return nil, errors.New("许可内容解析失败")
	}
	// 浮动许可必须带邮箱 + 公司名（用于归属追溯）
	if p.Unbound() {
		if strings.TrimSpace(p.Email) == "" {
			return nil, errors.New("浮动许可缺少授权邮箱（签发时加 -email）")
		}
		if strings.TrimSpace(p.Company) == "" && strings.TrimSpace(p.Customer) == "" {
			return nil, errors.New("浮动许可缺少公司名称（签发时加 -company）")
		}
	} else if Normalize(p.Machine) != Normalize(machine) {
		return nil, errors.New("许可与本机机器码不匹配（许可属于 " + Group(p.Machine) + "）")
	}
	// 到期日含当日 23:59:59
	exp, err := time.ParseInLocation("2006-01-02", p.Expire, time.Local)
	if err != nil {
		return nil, errors.New("许可到期日格式错误")
	}
	if time.Now().After(exp.Add(24 * time.Hour)) {
		return nil, errors.New("许可已于 " + p.Expire + " 到期")
	}
	return &p, nil
}

// Save 保存许可串（不校验）
func Save(token string) { db.SetSetting("license_token", strings.TrimSpace(token)) }

// Clear 移除许可（回到试用/过期状态）
func Clear() {
	db.SetSetting("license_token", "")
	db.SetSetting("license_lock_machine", "")
	db.SetSetting("license_lock_id", "")
	db.SetSetting("license_lock_time", "")
}

// Activate 激活许可：校验 -> （浮动许可）占用授权台数 -> 落库
//
// 浮动许可（Bind=none）的"同时一台"由两种手段保证：
//  1. 配置了 SSLVPN_LICENSE_REGISTER 登记服务时：在线登记，同一许可编号只允许一台机器占用（硬约束）；
//  2. 未配置时：纯离线，首次激活记录本机（软约束），换机需在原机「解除激活」。
func Activate(token string) (*Payload, error) {
	m := Machine()
	p, err := Verify(token, m)
	if err != nil {
		return nil, err
	}
	if p.Unbound() {
		if err := claimSeat(p, m); err != nil {
			return nil, err
		}
		if db.GetSetting("license_lock_machine") == "" {
			db.SetSetting("license_lock_time", time.Now().Format("2006-01-02 15:04:05"))
		}
		db.SetSetting("license_lock_machine", Group(m))
		db.SetSetting("license_lock_id", p.ID)
	}
	Save(token)
	Invalidate()
	return p, nil
}

// LockMachine 本机上次激活浮动许可时登记的机器码（未激活为空）
func LockMachine() string { return db.GetSetting("license_lock_machine") }

// LockTime 首次激活时间
func LockTime() string { return db.GetSetting("license_lock_time") }

// ---------------- 状态查询（带 30s 缓存） ----------------

var (
	cacheMu   sync.Mutex
	cacheVal  Status
	cacheTime time.Time
)

// Check 返回当前授权状态。
// 计算过程（多次 DB 查询）不持锁：先双重检查缓存，再在锁外 compute，
// 避免个别慢查询把所有 API 请求都串行卡在全局锁上。
func Check() Status {
	cacheMu.Lock()
	if !cacheTime.IsZero() && time.Since(cacheTime) < 30*time.Second {
		v := cacheVal
		cacheMu.Unlock()
		return v
	}
	cacheMu.Unlock()

	v := compute()

	cacheMu.Lock()
	// 并发下可能已有更近的结果，只保留较新的缓存
	if cacheTime.IsZero() || time.Since(cacheTime) >= 30*time.Second {
		cacheVal = v
		cacheTime = time.Now()
	} else {
		v = cacheVal
	}
	cacheMu.Unlock()
	return v
}

// Invalidate 清除状态缓存（激活/清除许可后调用）
func Invalidate() {
	cacheMu.Lock()
	cacheTime = time.Time{}
	cacheMu.Unlock()
}

func compute() Status {
	m := Machine()
	days := trialDays()
	start := trialStart()
	trialEnd := start.AddDate(0, 0, days)
	st := Status{
		Machine:    m,
		TrialDays:  days,
		TrialEnd:   trialEnd.Format("2006-01-02 15:04"),
		ServerTime: time.Now().Format("2006-01-02 15:04:05"),
		Registry:   registryEnabled(),
	}

	// 1) 优先看正式许可
	if tok := db.GetSetting("license_token"); tok != "" {
		p, err := Verify(tok, m)
		if err == nil {
			exp, _ := time.ParseInLocation("2006-01-02", p.Expire, time.Local)
			st.State = StateLicensed
			st.Customer = p.Display()
			st.Company = p.Company
			st.Email = p.Email
			st.Bind = p.Bind
			st.Unbound = p.Unbound()
			st.Nodes = p.Nodes
			st.LicID = p.ID
			if st.Bind == "" && !st.Unbound {
				st.Bind = BindMachine
			}
			st.Expire = p.Expire
			st.Edition = p.Edition
			st.DaysLeft = int(time.Until(exp.Add(24*time.Hour)).Hours() / 24)
			if st.DaysLeft < 0 {
				st.DaysLeft = 0
			}
			st.LockMachine = LockMachine()
			st.LockTime = LockTime()
			return st
		}
		st.TokenErr = err.Error()
	}

	// 2) 试用期
	left := time.Until(trialEnd)
	if left <= 0 {
		st.State = StateExpired
		st.DaysLeft = 0
		return st
	}
	st.State = StateTrial
	// 向上取整到天：剩 0.3 天也算 1 天
	st.DaysLeft = int((left + 24*time.Hour - time.Second) / (24 * time.Hour))
	if st.DaysLeft < 1 {
		st.DaysLeft = 1
	}
	return st
}

// ---------------- 签发（仅签发端使用） ----------------

// Sign 用私钥 PEM 签发许可串
func Sign(p Payload, privatePEM []byte) (string, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return "", errors.New("私钥解析失败")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("私钥类型不是 Ed25519")
	}
	if p.Issued == "" {
		p.Issued = time.Now().Format("2006-01-02")
	}
	if Normalize(p.Machine) != "" {
		p.Machine = Group(p.Machine)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Describe 状态中文描述（CLI 输出用）
func (s Status) Describe() string {
	switch s.State {
	case StateLicensed:
		bind := "绑定机器"
		if s.Unbound {
			bind = "不绑机器"
		}
		return fmt.Sprintf("已授权｜%s｜%s｜到期：%s（剩 %d 天）", s.Customer, bind, s.Expire, s.DaysLeft)
	case StateTrial:
		return fmt.Sprintf("试用中｜剩 %d 天（试用截止 %s）", s.DaysLeft, s.TrialEnd)
	default:
		return fmt.Sprintf("未授权｜试用已于 %s 到期", s.TrialEnd)
	}
}
