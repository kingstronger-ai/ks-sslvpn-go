// Package acme 证书自动签发/续签（Let's Encrypt DNS-01，阿里云 / 腾讯云 DNS）
package acme

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"sslvpn/internal/db"
)

// BaseDir 数据目录（main 启动时注入，与主程序一致）
var BaseDir = "/var/lib/sslvpn"

// ReloadTLS 证书更新后的热加载钩子（由 main 注入 handler.ApplyTLSCertPEM）
var ReloadTLS func(certPEM, keyPEM []byte) error

// Notify 发送系统邮件（由 main 注入 handler.SendSystemMail）
var Notify func(subject, html string) error

// Config 自动续签配置（凭证加密存储）
type Config struct {
	Enabled   bool     `json:"enabled"`
	Domains   []string `json:"domains"`
	Email     string   `json:"email"`
	Provider  string   `json:"provider"` // aliyun | tencent
	AccessKey string   `json:"access_key"`
	SecretKey string   `json:"secret_key"`
	Days      int      `json:"days"`    // 到期前多少天开始续签，默认 30
	Staging   bool     `json:"staging"` // 使用 LE 测试环境（不计入签发配额）
}

// Status 运行状态（内存 + 最近一次结果落库）
type Status struct {
	Running    bool   `json:"running"`
	Message    string `json:"message"`
	LastError  string `json:"last_error"`
	LastAt     string `json:"last_at"`
	LastOK     bool   `json:"last_ok"`
	NextCheck  string `json:"next_check"`
	Source     string `json:"source"` // acme | upload | self-signed
	Subject    string `json:"subject"`
	NotAfter   string `json:"not_after"`
	DaysLeft   int    `json:"days_left"`
	DomainList string `json:"domains"`
}

var (
	runMu     sync.Mutex
	running   bool
	lastMsg   string
	lastErr   string
	lastOK    bool
	lastRunAt time.Time
)

const (
	setEnabled  = "cert_auto_enabled"
	setDomains  = "cert_auto_domains"
	setEmail    = "cert_auto_email"
	setProvider = "cert_auto_provider"
	setAK       = "cert_auto_ak"
	setSK       = "cert_auto_sk"
	setDays     = "cert_auto_days"
	setStaging  = "cert_auto_staging"
	setLastRes  = "cert_auto_last"
	setSource   = "cert_source"
	setNotified = "cert_notified"
)

// ---------- 配置读写 ----------

// setting/setSetting 包一层：单测可能没有初始化 DB，避免 nil panic
func setting(k string) string {
	if db.DB == nil {
		return ""
	}
	return db.GetSetting(k)
}

func setSetting(k, v string) {
	if db.DB == nil {
		return
	}
	db.SetSetting(k, v)
}

// Load 读取配置（空凭证时返回默认值）
func Load() Config {
	c := Config{
		Enabled:   setting(setEnabled) == "1",
		Email:     setting(setEmail),
		Provider:  setting(setProvider),
		AccessKey: openSecret(setting(setAK)),
		SecretKey: openSecret(setting(setSK)),
		Days:      atoiDefault(setting(setDays), 30),
		Staging:   setting(setStaging) == "1",
	}
	if c.Provider == "" {
		c.Provider = "aliyun"
	}
	for _, d := range strings.Split(setting(setDomains), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.Domains = append(c.Domains, d)
		}
	}
	return c
}

// Save 保存配置（凭证 AES-GCM 加密后入库）
func Save(c Config) error {
	c.Domains = normalizeDomains(c.Domains)
	if c.Days <= 0 {
		c.Days = 30
	}
	if c.Days > 90 {
		c.Days = 90
	}
	setSetting(setEnabled, boolStr(c.Enabled))
	setSetting(setDomains, strings.Join(c.Domains, ","))
	setSetting(setEmail, strings.TrimSpace(c.Email))
	setSetting(setProvider, c.Provider)
	setSetting(setAK, sealSecret(c.AccessKey))
	setSetting(setSK, sealSecret(c.SecretKey))
	setSetting(setDays, strconv.Itoa(c.Days))
	setSetting(setStaging, boolStr(c.Staging))
	return nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}

func normalizeDomains(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		// 保留 *. 前缀：泛域名靠 DNS-01 签发（通配符只允许出现在最左侧一级）
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ---------- 凭证加密（密钥由 session_secret 派生） ----------

func secretKey() []byte {
	sum := sha256.Sum256([]byte("sslvpn-cert-auto:" + setting("session_secret")))
	return sum[:]
}

func sealSecret(plain string) string {
	if plain == "" {
		return ""
	}
	block, err := aes.NewCipher(secretKey())
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plain
	}
	// 以 nonce 为前缀，整体 base64
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return "enc1:" + base64.StdEncoding.EncodeToString(sealed)
}

func openSecret(stored string) string {
	if !strings.HasPrefix(stored, "enc1:") {
		return stored
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "enc1:"))
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(secretKey())
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return ""
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

// Mask 凭证打码回显（前 4 后 2）
func Mask(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// ---------- 证书状态 ----------

func sslDir() string {
	if d := os.Getenv("SSLVPN_SSL_DIR"); d != "" {
		return d
	}
	return filepath.Join(BaseDir, "ssl")
}

func acmeDir() string { return filepath.Join(BaseDir, "acme") }

// CertInfo 读取当前 Web 证书信息
func CertInfo() Status {
	st := Status{Source: "self-signed"}
	data, err := os.ReadFile(filepath.Join(sslDir(), "server.crt"))
	if err != nil {
		return st
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return st
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return st
	}
	st.Subject = c.Subject.CommonName
	if st.Subject == "" && len(c.DNSNames) > 0 {
		st.Subject = c.DNSNames[0]
	}
	// x509 解析出的时间是 UTC，转成容器本地时区（镜像已设 TZ=Asia/Shanghai），
	// 否则管理页显示的到期时间会比浏览器证书查看器少 8 小时。
	st.NotAfter = c.NotAfter.Local().Format("2006-01-02 15:04:05")
	st.DaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
	st.DomainList = strings.Join(c.DNSNames, ",")
	st.Source = certSource(c, setting(setSource))
	return st
}

// certSource 判定证书来源。
// marked 是签发/上传时写入 settings 的 cert_source，优先信任：Let's Encrypt 的中间证书 CN
// 会轮换（R3/R10/E5/E6 → E7/E8/R11/R12…），只靠 CN 白名单必然漏判，导致签发出去的
// 证书被错标成「手工上传」。
func certSource(c *x509.Certificate, marked string) string {
	if marked == "acme" || marked == "upload" {
		return marked
	}
	issuerCN := c.Issuer.CommonName
	issuerOrg := strings.Join(c.Issuer.Organization, " ")
	// 无标记时先看是不是本系统自签证书
	if c.Issuer.String() == c.Subject.String() || strings.Contains(issuerCN, "SSLVPN-Go") {
		return "self-signed"
	}
	// 兜底：从签发者识别，覆盖 LE 新旧中间证书体系
	if strings.Contains(issuerOrg, "Let's Encrypt") ||
		strings.Contains(issuerCN, "Let's Encrypt") || isLEIntermediate(issuerCN) {
		return "acme"
	}
	if c.Subject.CommonName != "" {
		return "upload"
	}
	return "self-signed"
}

// isLEIntermediate 匹配 LE 中间证书 CN：R3/R10、E5/E6/E7/E8，以及 2025 年后的
// YE1/YE2/XR1…（形如「1~2 个大写字母 + 1~2 位数字」）。CN 会不断轮换，
// 因此机构名含 Let's Encrypt 时也会直接判定，这里只作无机构信息时的兜底。
func isLEIntermediate(cn string) bool {
	if len(cn) < 2 || len(cn) > 4 {
		return false
	}
	i := 0
	for i < len(cn) && cn[i] >= 'A' && cn[i] <= 'Z' {
		i++
	}
	if i == 0 || i > 2 || i == len(cn) {
		return false
	}
	for ; i < len(cn); i++ {
		if cn[i] < '0' || cn[i] > '9' {
			return false
		}
	}
	return true
}

// NeedsRenew 当前证书是否需要在 days 天内续签
func NeedsRenew(days int) bool {
	st := CertInfo()
	if st.NotAfter == "" {
		return true
	}
	return st.DaysLeft <= days
}

func setLastResult(ok bool, msg string) {
	lastOK, lastMsg = ok, msg
	lastRunAt = time.Now()
	tag := "失败"
	if ok {
		tag = "成功"
	}
	setSetting(setLastRes, time.Now().Format("2006-01-02 15:04:05")+" "+tag+"："+msg)
}

// CurrentStatus 汇总当前状态供界面展示
func CurrentStatus() Status {
	runMu.Lock()
	st := CertInfo()
	st.Running = running
	st.Message = lastMsg
	st.LastError = lastErr
	st.LastOK = lastOK
	if !lastRunAt.IsZero() {
		st.LastAt = lastRunAt.Format("2006-01-02 15:04:05")
	}
	runMu.Unlock()
	if st.LastAt == "" {
		st.Message = setting(setLastRes)
	}
	return st
}

// ---------- ACME 账号 ----------

type legoUser struct {
	Email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *legoUser) GetEmail() string                         { return u.Email }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey         { return u.key }
func (u *legoUser) GetRegistration() *registration.Resource  { return u.reg }
func (u *legoUser) SetRegistration(r *registration.Resource) { u.reg = r }

func loadOrCreateUser(email string) (*legoUser, error) {
	if err := os.MkdirAll(acmeDir(), 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(acmeDir(), "account.key")
	regPath := filepath.Join(acmeDir(), "account.json")
	var key crypto.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			switch block.Type {
			case "EC PRIVATE KEY":
				key, _ = x509.ParseECPrivateKey(block.Bytes)
			case "RSA PRIVATE KEY":
				key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
			case "PRIVATE KEY":
				key, _ = x509.ParsePKCS8PrivateKey(block.Bytes)
			}
		}
	}
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
		key = k
	}
	u := &legoUser{Email: email, key: key}
	if data, err := os.ReadFile(regPath); err == nil {
		var reg registration.Resource
		if json.Unmarshal(data, &reg) == nil {
			u.reg = &reg
		}
	}
	return u, nil
}

func saveRegistration(u *legoUser, reg *registration.Resource) {
	u.reg = reg
	if reg == nil {
		return
	}
	if data, err := json.Marshal(reg); err == nil {
		_ = os.WriteFile(filepath.Join(acmeDir(), "account.json"), data, 0o600)
	}
}

// ---------- DNS 提供商 ----------

func newProvider(c Config) (challenge.Provider, error) {
	if c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("未配置云 DNS 凭证（AccessKey / SecretKey）")
	}
	switch strings.ToLower(c.Provider) {
	case "", "aliyun", "alidns", "ali":
		return newAliyun(c)
	case "tencent", "tencentcloud", "dnspod", "qcloud":
		return newTencent(c)
	}
	return nil, fmt.Errorf("不支持的 DNS 服务商: %s", c.Provider)
}

// TestDNS 校验凭证是否可读写解析记录（临时 TXT，验证后立即删除）
func TestDNS(c Config) error {
	if len(c.Domains) == 0 {
		return errors.New("请先填写域名")
	}
	p, err := newProvider(c)
	if err != nil {
		return err
	}
	// 泛域名（*.example.com）用其主域做测试记录，避免在 DNS 里写入非法的 * 主机记录
	domain := strings.TrimPrefix(c.Domains[0], "*.")
	if err := p.Present(domain, "sslvpn-credential-test", "sslvpn-credential-test"); err != nil {
		return fmt.Errorf("写入 TXT 记录失败（检查凭证权限与域名是否在该账号下）: %w", err)
	}
	if err := p.CleanUp(domain, "sslvpn-credential-test", "sslvpn-credential-test"); err != nil {
		return fmt.Errorf("清理测试记录失败: %w", err)
	}
	return nil
}

// ---------- 签发 / 续签 ----------

// Issue 执行一次签发（DNS-01），成功后写盘并热加载
func Issue(c Config) (*Status, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("请先填写要签发证书的域名")
	}
	if strings.TrimSpace(c.Email) == "" {
		return nil, errors.New("请填写 ACME 注册邮箱（到期通知用）")
	}
	runMu.Lock()
	if running {
		runMu.Unlock()
		return nil, errors.New("已有签发任务在执行，请稍候")
	}
	running, lastErr, lastMsg = true, "", "正在申请证书（DNS-01，等待解析生效，约 1-3 分钟）"
	runMu.Unlock()
	defer func() {
		runMu.Lock()
		running = false
		runMu.Unlock()
	}()

	user, err := loadOrCreateUser(c.Email)
	if err != nil {
		setLastResult(false, "读取 ACME 账号失败: "+err.Error())
		return nil, err
	}
	lc := lego.NewConfig(user)
	lc.Certificate.KeyType = certcrypto.EC256
	lc.Certificate.Timeout = 60 * time.Second
	if c.Staging {
		lc.CADirURL = lego.LEDirectoryStaging
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		setLastResult(false, "创建 ACME 客户端失败: "+err.Error())
		return nil, err
	}
	prov, err := newProvider(c)
	if err != nil {
		setLastResult(false, err.Error())
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(prov); err != nil {
		setLastResult(false, "设置 DNS-01 校验失败: "+err.Error())
		return nil, err
	}
	// 已有账号直接复用，避免 409 已注册
	reg, err := client.Registration.QueryRegistration()
	if err != nil || reg == nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			setLastResult(false, "ACME 账号注册失败: "+err.Error())
			return nil, fmt.Errorf("ACME 账号注册失败: %w", err)
		}
	}
	saveRegistration(user, reg)

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: c.Domains,
		Bundle:  true,
	})
	if err != nil {
		setLastResult(false, "签发失败: "+err.Error())
		return nil, fmt.Errorf("签发失败: %w", err)
	}
	if err := installCert(res.Certificate, res.PrivateKey); err != nil {
		setLastResult(false, "写入证书失败: "+err.Error())
		return nil, err
	}
	setSetting(setSource, "acme")
	_ = os.WriteFile(filepath.Join(acmeDir(), "last-cert.pem"), res.Certificate, 0o600)
	st := CertInfo()
	setLastResult(true, fmt.Sprintf("签发成功（%s，有效期至 %s）", strings.Join(c.Domains, ","), st.NotAfter))
	out := CurrentStatus()
	return &out, nil
}

// installCert 备份旧证书 → 原子写入 → 热加载
func installCert(certPEM, keyPEM []byte) error {
	dir := sslDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	crtPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if old, err := os.ReadFile(crtPath); err == nil {
		_ = os.WriteFile(crtPath+".bak", old, 0o644)
	}
	if old, err := os.ReadFile(keyPath); err == nil {
		_ = os.WriteFile(keyPath+".bak", old, 0o600)
	}
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if ReloadTLS != nil {
		if err := ReloadTLS(certPEM, keyPEM); err != nil {
			return fmt.Errorf("证书已写入但热加载失败（重启容器后生效）: %w", err)
		}
	}
	return nil
}

// RenewIfNeeded 到期前自动续签，返回是否执行了签发
func RenewIfNeeded(c Config, force bool) (bool, error) {
	if !c.Enabled && !force {
		return false, nil
	}
	days := c.Days
	if days <= 0 {
		days = 30
	}
	if !force && !NeedsRenew(days) {
		return false, nil
	}
	if _, err := Issue(c); err != nil {
		return true, err
	}
	return true, nil
}

// ---------- 到期提醒（导入的商业证书也适用） ----------

var notifyDays = []int{15, 7, 3, 1}

func maybeNotify() {
	st := CertInfo()
	if st.NotAfter == "" {
		return
	}
	left := st.DaysLeft
	hit := false
	for _, d := range notifyDays {
		if left == d {
			hit = true
			break
		}
	}
	if !hit {
		return
	}
	tag := fmt.Sprintf("%s#%d", time.Now().Format("2006-01-02"), left)
	if setting(setNotified) == tag {
		return
	}
	if Notify == nil {
		return
	}
	subject := fmt.Sprintf("【VPN 证书提醒】HTTPS 证书还有 %d 天到期", left)
	body := fmt.Sprintf(`<p>当前 HTTPS 证书 <b>%s</b> 将于 <b>%s</b> 到期（剩余 %d 天）。</p>
<p>证书来源：%s。若已开启「自动续签」并配置了云 DNS 凭证，系统会在到期前自动换新；
否则请尽快上传新证书，或在证书管理中开启自动续签。</p>`, st.Subject, st.NotAfter, left, sourceName(st.Source))
	if err := Notify(subject, body); err != nil {
		log.Printf("证书到期提醒发送失败: %v", err)
		return
	}
	setSetting(setNotified, tag)
	log.Printf("证书到期提醒已发送（剩余 %d 天）", left)
}

func sourceName(s string) string {
	switch s {
	case "acme":
		return "Let's Encrypt 自动签发"
	case "upload":
		return "手工上传"
	default:
		return "内置自签证书"
	}
}

// ---------- 定时任务 ----------

// StartLoop 启动后台巡检（启动 1 分钟后首检，之后每 6 小时）
func StartLoop() {
	go func() {
		time.Sleep(time.Minute)
		for {
			c := Load()
			if c.Enabled {
				if days := c.Days; days > 0 && NeedsRenew(days) {
					log.Printf("证书自动续签：当前剩余 %d 天，开始签发 %v", CertInfo().DaysLeft, c.Domains)
					if _, err := Issue(c); err != nil {
						log.Printf("证书自动续签失败: %v", err)
					} else {
						log.Printf("证书自动续签成功")
					}
				}
			}
			maybeNotify()
			time.Sleep(6 * time.Hour)
		}
	}()
}
