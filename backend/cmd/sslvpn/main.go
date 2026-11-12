// SSLVPN-Go 管理系统主程序
// 用法:
//
//	sslvpn                      启动 Web/API 服务
//	sslvpn auth-verify <file>   OpenVPN auth-user-pass-verify 回调（via-file）
//	sslvpn init                 初始化数据库与管理员（幂等）
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/acme"
	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/handler"
	"sslvpn/internal/license"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
	"sslvpn/webfs"
)

const defaultDataDir = "/var/lib/sslvpn"

func dataDir() string {
	if d := os.Getenv("SSLVPN_DATA_DIR"); d != "" {
		return d
	}
	return defaultDataDir
}

// maxUsersDesc 许可里 VPN 用户数上限的中文展示；0 或负值表示不限制。
func maxUsersDesc(n int) string {
	if n <= 0 {
		return "不限制"
	}
	return fmt.Sprintf("%d 人", n)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// OpenVPN 认证回调子命令（via-file 模式，最后一个参数为临时文件路径）
	if len(os.Args) >= 3 && os.Args[1] == "auth-verify" {
		viaFile := os.Args[2]
		if err := db.Open(dataDir()); err != nil {
			log.Fatal("db open: ", err)
		}
		// 关键：子命令进程必须单独注入 LDAP 校验器，否则 LDAP 账号一律认证失败
		registerLDAPVerifier()
		os.Exit(vpn.VerifyVPNCredentials(viaFile))
	}

	// client-connect 钩子登记虚拟 IP 绑定：record-ip <username> <vip>
	if len(os.Args) >= 4 && os.Args[1] == "record-ip" {
		if err := db.Open(dataDir()); err != nil {
			os.Exit(0) // 登记失败不阻断用户连接
		}
		vpn.RecordIPBinding(os.Args[2], os.Args[3])
		os.Exit(0)
	}

	// license-info：查看本机机器码与授权状态
	if len(os.Args) >= 2 && os.Args[1] == "license-info" {
		if err := db.Open(dataDir()); err != nil {
			log.Fatal("db open: ", err)
		}
		st := license.Check()
		fmt.Printf("机器码: %s\n状态  : %s\n", st.Machine, st.Describe())
		if st.TokenErr != "" {
			fmt.Printf("许可串: %s\n", st.TokenErr)
		}
		return
	}

	// license-gen：签发端使用（需私钥，离线生成许可串给客户）
	if len(os.Args) >= 2 && os.Args[1] == "license-gen" {
		fs := flag.NewFlagSet("license-gen", flag.ExitOnError)
		bind := fs.String("bind", "machine", "绑定模式：machine=绑定机器码；none=不绑机器（浮动许可，同时仅 1 台）")
		machine := fs.String("machine", "", "目标服务器机器码，如 A1B2-C3D4-E5F6-7890（-bind machine 时必填）")
		customer := fs.String("customer", "", "客户名称（同 -company，兼容旧用法）")
		company := fs.String("company", "", "公司名称（浮动许可必填）")
		email := fs.String("email", "", "授权邮箱（浮动许可必填）")
		id := fs.String("id", "", "许可编号（留空按序号从 1 开始自增）")
		seqFile := fs.String("seq-file", "", "许可编号序号文件（默认与私钥同目录的 license.seq）")
		expire := fs.String("expire", "", "到期日 YYYY-MM-DD")
		days := fs.Int("days", 0, "自今天起有效天数（未给 -expire 时生效，默认 365）")
		keyPath := fs.String("key", "license-private.pem", "签发私钥 PEM 路径")
		edition := fs.String("edition", "community", "授权档位：community=社区版 / pro=专业版 / enterprise=企业版")
		features := fs.String("features", "", "显式功能清单（逗号分隔，留空按档位自动推导）：domain_route,sso,ccd,ldap,client_download,multi_instance,private_issuance,acme_auto_renew")
		nodes := fs.Int("nodes", 0, "授权台数上限（浮动许可默认 1，0 为不限）")
		maxUsers := fs.Int("max-users", 0, "授权 VPN 用户数上限（0 或留空 = 不限制用户数）")
		_ = fs.Parse(os.Args[2:])

		mode := strings.ToLower(strings.TrimSpace(*bind))
		if mode != license.BindNone {
			mode = license.BindMachine
		}
		name := strings.TrimSpace(*company)
		if name == "" {
			name = strings.TrimSpace(*customer)
		}
		mail := strings.TrimSpace(*email)
		if *maxUsers < 0 {
			fmt.Println("错误：-max-users 不能为负数（0 或留空 = 不限制用户数）")
			os.Exit(1)
		}

		if mode == license.BindMachine {
			if license.Normalize(*machine) == "" {
				fmt.Println("错误：-bind machine 时必须指定 -machine（在目标服务器执行 `sslvpn license-info` 可查看）")
				fmt.Println("      若不想绑定机器，请改用：-bind none -email 客户邮箱 -company \"公司名称\"")
				os.Exit(1)
			}
			if len(license.Normalize(*machine)) != 16 {
				fmt.Println("错误：机器码应为 16 位十六进制（形如 A1B2-C3D4-E5F6-7890）")
				os.Exit(1)
			}
		} else {
			if mail == "" || !strings.Contains(mail, "@") {
				fmt.Println("错误：浮动许可必须指定 -email（客户授权邮箱）")
				os.Exit(1)
			}
			if name == "" {
				fmt.Println("错误：浮动许可必须指定 -company（公司名称）")
				os.Exit(1)
			}
			*machine = ""
			if *nodes == 0 {
				*nodes = 1
			}
		}
		// 编号生成置于绑定模式分支之外：绑定机器码的许可同样带编号，前端不再显示 "-"
		seq := *seqFile
		if seq == "" {
			seq = filepath.Join(filepath.Dir(*keyPath), "license.seq")
		}
		nextID, err := nextLicenseID(seq, *id)
		if err != nil {
			fmt.Println("错误：许可编号序号写入失败：", err)
			os.Exit(1)
		}
		*id = nextID
		exp := *expire
		if exp == "" {
			d := *days
			if d <= 0 {
				d = 365
			}
			exp = time.Now().AddDate(0, 0, d).Format("2006-01-02")
		} else if _, err := time.ParseInLocation("2006-01-02", exp, time.Local); err != nil {
			fmt.Println("错误：-expire 需为 YYYY-MM-DD 格式")
			os.Exit(1)
		}
		priv, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Printf("错误：读取私钥失败（%s）：%v\n", *keyPath, err)
			os.Exit(1)
		}
		var feats []string
		for _, f := range strings.Split(*features, ",") {
			f = strings.ToLower(strings.TrimSpace(f))
			if f != "" {
				feats = append(feats, f)
			}
		}
		p := license.Payload{
			ID: *id, Bind: mode, Machine: *machine, Customer: name, Company: name,
			Email: mail, Expire: exp, Edition: *edition, Nodes: *nodes,
			MaxUsers: *maxUsers, Features: feats,
		}
		token, err := license.Sign(p, priv)
		if err != nil {
			fmt.Println("错误：签发失败：", err)
			os.Exit(1)
		}
		bindDesc := "绑定机器码 " + license.Group(*machine)
		if mode == license.BindNone {
			bindDesc = "不绑定机器（浮动许可，同时仅 " + fmt.Sprint(*nodes) + " 台）"
		}
		enabled := p.EnabledFeatures()
		sort.Strings(enabled)
		fmt.Println("──────────────────────────────────────────")
		fmt.Printf("许可编号: %s\n客户公司: %s\n授权邮箱: %s\n绑定方式: %s\n到期日  : %s\n版本    : %s（档位 %s）\n用户上限: %s\n",
			*id, name, mail, bindDesc, exp, *edition, p.Tier(), maxUsersDesc(*maxUsers))
		if len(feats) > 0 {
			fmt.Printf("显式功能: %s\n", strings.Join(feats, ", "))
		}
		fmt.Printf("开启功能: %s\n", strings.Join(enabled, ", "))
		if *maxUsers > 0 {
			fmt.Printf("用户数限制: 最多创建 %d 个 VPN 账号（含禁用账号），达到上限后新增 / 批量导入 / 自助注册 / LDAP 同步都会被拒绝\n", *maxUsers)
		}
		fmt.Println("──────────────────────────────────────────")
		fmt.Println("许可串（复制整行发给客户，粘贴到「授权管理 → 激活许可」）：")
		fmt.Println(token)
		if mode == license.BindNone {
			fmt.Println()
			fmt.Println("交付说明：换机时请在原机「授权管理 → 解除激活」后再在新机激活；")
			fmt.Println("          如需强约束（同一许可只能一台机器激活），请启用在线登记服务：")
			fmt.Println("          服务端：sslvpn license-registry -addr :8790 -secret <密钥> -file registry.json")
			fmt.Println("          客户端：在客户机 docker-compose.yml 设置环境变量")
			fmt.Println("                  SSLVPN_LICENSE_REGISTER=https://你的登记服务:8790")
			fmt.Println("                  SSLVPN_LICENSE_SECRET=<密钥>")
		}
		return
	}

	// license-inspect：自检许可串内容（不需要私钥，任何机器可跑）
	if len(os.Args) >= 2 && os.Args[1] == "license-inspect" {
		fs := flag.NewFlagSet("license-inspect", flag.ExitOnError)
		token := fs.String("token", "", "许可串")
		_ = fs.Parse(os.Args[2:])
		if *token == "" && fs.NArg() > 0 {
			*token = fs.Arg(0)
		}
		if strings.TrimSpace(*token) == "" {
			fmt.Println("用法：sslvpn license-inspect -token '<许可串>'")
			os.Exit(1)
		}
		p, err := license.Parse(*token)
		if err != nil {
			fmt.Println("校验失败：", err)
			os.Exit(1)
		}
		bindDesc := "绑定机器 " + license.Group(p.Machine)
		if p.Unbound() {
			bindDesc = "不绑定机器（浮动许可）"
		}
		enabled := p.EnabledFeatures()
		sort.Strings(enabled)
		fmt.Println("──────────────────────────────────────────")
		fmt.Printf("许可编号: %s\n客户公司: %s\n授权邮箱: %s\n绑定方式: %s\n授权台数: %d\n签发日  : %s\n到期日  : %s\n版本    : %s（档位 %s）\n用户上限: %s\n",
			p.ID, p.Display(), p.Email, bindDesc, p.Nodes, p.Issued, p.Expire, p.Edition, p.Tier(), maxUsersDesc(p.MaxUsers))
		if len(p.Features) > 0 {
			fmt.Printf("显式功能: %s\n", strings.Join(p.Features, ", "))
		}
		fmt.Printf("开启功能: %s\n", strings.Join(enabled, ", "))
		fmt.Println("签名校验: 通过")
		fmt.Println("──────────────────────────────────────────")
		return
	}

	// license-registry：授权方自建的激活登记服务（保证浮动许可同时只有一台）
	if len(os.Args) >= 2 && os.Args[1] == "license-registry" {
		fs := flag.NewFlagSet("license-registry", flag.ExitOnError)
		addr := fs.String("addr", ":8790", "监听地址")
		secret := fs.String("secret", os.Getenv("SSLVPN_LICENSE_SECRET"), "登记密钥（客户机需一致）")
		file := fs.String("file", "license-registry.json", "登记记录文件")
		_ = fs.Parse(os.Args[2:])
		if err := license.RunRegistry(*addr, *secret, *file); err != nil {
			log.Fatal("license-registry: ", err)
		}
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "init" {
		if err := runInit(); err != nil {
			log.Fatal("init: ", err)
		}
		fmt.Println("初始化完成：默认管理员 admin / ChangeMe（请立即修改密码）")
		return
	}

	// reset-admin：忘记管理员密码时的离线重置（直接改库，不经过 Web）
	//
	//	sslvpn reset-admin -list                  列出全部管理员（确认用户名）
	//	sslvpn reset-admin                        重置超级管理员，自动生成 16 位随机密码
	//	sslvpn reset-admin -u admin -p NewPass123 指定用户名与新密码
	//
	// 容器内用法：docker exec -it ks-sslvpn-go sslvpn reset-admin
	if len(os.Args) >= 2 && os.Args[1] == "reset-admin" {
		fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
		user := fs.String("u", "", "管理员用户名（留空=优先超级管理员，其次 id 最小者）")
		pass := fs.String("p", "", "新密码（至少 8 位；留空自动生成 16 位随机密码）")
		list := fs.Bool("list", false, "仅列出全部管理员，不做修改")
		_ = fs.Parse(os.Args[2:])

		if err := db.Open(dataDir()); err != nil {
			log.Fatal("db open: ", err)
		}

		// 列出管理员，方便确认要重置哪个用户名
		if *list {
			rows, err := db.DB.Query(`SELECT username, email, status, super FROM admin ORDER BY id`)
			if err != nil {
				log.Fatal("查询失败: ", err)
			}
			defer rows.Close()
			fmt.Println("用户名\t状态\t超级管理员\t邮箱")
			n := 0
			for rows.Next() {
				var name, mail string
				var status, super int
				if rows.Scan(&name, &mail, &status, &super) == nil {
					st := "禁用"
					if status == 1 {
						st = "启用"
					}
					sp := "否"
					if super == 1 {
						sp = "是"
					}
					fmt.Printf("%s\t%s\t%s\t%s\n", name, st, sp, mail)
					n++
				}
			}
			if n == 0 {
				fmt.Println("（无管理员账号，执行 sslvpn init 可重建默认管理员）")
			}
			return
		}

		name := strings.TrimSpace(*user)
		if name == "" {
			// 未指定用户名：优先超级管理员，避免重置到普通运维账号
			if err := db.DB.QueryRow(`SELECT username FROM admin WHERE super=1 ORDER BY id LIMIT 1`).Scan(&name); err != nil {
				if err := db.DB.QueryRow(`SELECT username FROM admin ORDER BY id LIMIT 1`).Scan(&name); err != nil {
					fmt.Println("错误：库中没有管理员账号，请执行 `sslvpn init` 重建默认管理员（admin / ChangeMe）")
					os.Exit(1)
				}
			}
		}

		var id int64
		if err := db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, name).Scan(&id); err != nil {
			fmt.Printf("错误：管理员 %q 不存在。可执行 `sslvpn reset-admin -list` 查看现有账号\n", name)
			os.Exit(1)
		}

		newPass := *pass
		generated := false
		if newPass == "" {
			newPass = util.RandomPassword(16)
			generated = true
		}
		if len(newPass) < 8 {
			fmt.Println("错误：新密码至少 8 位")
			os.Exit(1)
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("生成密码哈希失败: ", err)
		}
		// 同时把状态置为启用，避免账号被禁用后重置了也登不进去
		if _, err := db.DB.Exec(`UPDATE admin SET password=?, status=1, updated_at=datetime('now','localtime') WHERE id=?`, hash, id); err != nil {
			log.Fatal("写入失败: ", err)
		}
		// 清掉该账号遗留的找回密码验证码，避免旧验证码继续可用
		_, _ = db.DB.Exec(`DELETE FROM secure_code WHERE target IN (SELECT email FROM admin WHERE id=?) AND target<>''`, id)

		fmt.Println("管理员密码已重置：")
		fmt.Printf("  用户名: %s\n", name)
		if generated {
			fmt.Printf("  新密码: %s   （随机生成，请立即妥善保存）\n", newPass)
		} else {
			fmt.Printf("  新密码: 已按 -p 参数设置\n")
		}
		fmt.Println("提示：已登录的会话仍然有效；如需强制所有会话重新登录，请执行 `docker restart ks-sslvpn-go`")
		return
	}

	if err := runInit(); err != nil {
		log.Fatal("init: ", err)
	}

	// 注入 LDAP 认证检查器（openvpn auth-verify 子命令进程也会通过 vpn 包直连 DB 完成校验）
	registerLDAPVerifier()
	registerDNSProvider()
	registerDomainRouteProvider()

	// 证书自动续签：注入数据目录、热加载与邮件提醒钩子，并启动后台巡检
	acme.BaseDir = dataDir()
	acme.ReloadTLS = handler.ApplyTLSCertPEM
	acme.Notify = handler.SendSystemMail
	acme.StartLoop()

	mux := http.NewServeMux()

	// ---- API 路由 ----
	// 规范前缀：/api/v1/<基路径>（唯一的对外契约）
	// 旧前缀（裸路径 /logincheck、/api/logincheck）默认仍可用，便于灰度切换；
	// 设 SSLVPN_API_LEGACY_ALIAS=0 即可彻底关闭旧路径，完成契约收敛。
	registerAPIRoutes(mux, os.Getenv("SSLVPN_API_LEGACY_ALIAS") != "0")

	// ---- 飞书扫码登录的浏览器落地页（非 /api 前缀，需与飞书后台登记的 redirect_uri 一致）----
	// 规范路径 /feishu-sso/auth/start、/feishu-sso/callback；同时保留 /auth/start、/callback 便于对接既有配置。
	// 规范前缀 /sso/*；/feishu-sso、/auth、/callback 保留为兼容别名（已登记的 redirect_uri 不受影响）。
	mux.HandleFunc("/sso/auth/start", handler.SSOAuthStart)
	mux.HandleFunc("/sso/callback", handler.SSOCallback)
	// 桌面客户端安装包下载（开关/可见范围由「系统设置 → 客户端下载」控制）
	mux.HandleFunc("/downloads", handler.ClientDownloads)
	mux.HandleFunc("/downloads/", handler.ClientDownloadFile)
	mux.HandleFunc("/feishu-sso/auth/start", handler.SSOAuthStart)
	mux.HandleFunc("/feishu-sso/callback", handler.SSOCallback)
	mux.HandleFunc("/auth/start", handler.SSOAuthStart)
	mux.HandleFunc("/callback", handler.SSOCallback)
	mux.HandleFunc("/healthz", handler.SSOHealthz)
	go func() {
		for {
			vpn.PurgeExpiredSSO(db.DB)
			time.Sleep(30 * time.Minute)
		}
	}()

	// 前端静态资源
	dist, err := webfs.Dist()
	if err != nil {
		log.Fatal(err)
	}
	// 说明：内嵌文件没有修改时间，若直接 FileServer 输出，浏览器会无验证地复用缓存，
	// 升级后可能出现新旧 app.js/index.html 混用导致的白屏。这里改为显式输出：
	//   ETag(内容哈希) + Cache-Control: no-cache —— 升级后浏览器必拿新资源，未变更时命中 304。
	mux.Handle("/", staticFileHandler(dist))

	root := middleware.CORS(mux)

	apiPort := os.Getenv("SSLVPN_API_PORT")
	if apiPort == "" {
		apiPort = "8080"
	}
	webPort := os.Getenv("SSLVPN_WEB_PORT")
	if webPort == "" {
		webPort = "8443"
	}

	// API (明文，仅监听本地/容器内)
	go func() {
		srv := &http.Server{Addr: ":" + apiPort, Handler: root, ReadHeaderTimeout: 10 * time.Second}
		log.Printf("API 服务已启动 :%s", apiPort)
		log.Fatal(srv.ListenAndServe())
	}()

	// Web (HTTPS 自签或自定义证书)
	cert, err := loadOrGenCert()
	if err != nil {
		log.Fatal("证书: ", err)
	}
	handler.SetWebTLSCert(&cert)
	srvTLS := &http.Server{
		Addr:              ":" + webPort,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// GetCertificate：优先返回管理页上传并热替换的证书，兜底启动时加载的证书
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c := handler.CurrentWebTLSCert(); c != nil {
					return c, nil
				}
				return &cert, nil
			},
		},
	}
	log.Printf("Web 管理界面已启动 https://0.0.0.0:%s （默认账号 admin / ChangeMe）", webPort)
	log.Fatal(srvTLS.ListenAndServeTLS("", ""))
}

// registerAPIRoutes 把 handler.Routes 挂到 mux 上。
// 规范路径固定为 handler.APIPrefix + 基路径；legacyAlias=true 时额外挂裸路径与 /api/xxx 两个旧别名。
func registerAPIRoutes(mux *http.ServeMux, legacyAlias bool) {
	for path, rt := range handler.Routes {
		rt := rt
		base := path
		// 规范路径（唯一契约）
		mux.HandleFunc(handler.APIPath(base), apiEntry(base, rt, true))
		if legacyAlias {
			// 旧别名：裸路径（原 nginx 反代剥前缀后的形态）与 /api/xxx
			mux.HandleFunc(base, apiEntry(base, rt, false))
			mux.HandleFunc("/api"+base, apiEntry(base, rt, false))
		}
	}
}

// apiEntry 生成单个接口的处理器：方法校验 → 授权标记 → 登录/许可校验 → 业务处理
func apiEntry(base string, rt handler.Route, canonical bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != rt.Method && !(rt.Method == "GET" && r.Method == "HEAD") {
			util.Fail(w, "请求方法不允许")
			return
		}
		if canonical {
			w.Header().Set("X-API-Version", "v1")
		}
		if rt.Auth {
			middleware.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !licenseAllow(base) && license.Check().Expired() {
					util.FailCode(w, 402, "试用已到期且未激活许可，请前往「授权管理」激活")
					return
				}
				rt.H(w, r)
			})).ServeHTTP(w, r)
			return
		}
		rt.H(w, r)
	}
}

// licenseAllow 授权过期时仍可访问的接口（登录、退出、授权管理、品牌读取）
func licenseAllow(path string) bool {
	switch path {
	case "/logincheck", "/logout", "/captcha",
		"/license/info", "/license/activate", "/license/clear",
		"/system/getBrand", "/brand/logo":
		return true
	}
	return false
}

// runInit 幂等初始化：建库、默认管理员、PKI、目录
func runInit() error {
	if err := db.Open(dataDir()); err != nil {
		return err
	}
	// 默认管理员
	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&cnt)
	if cnt == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("ChangeMe"), bcrypt.DefaultCost)
		if _, err := db.DB.Exec(`INSERT INTO admin(username,password,email,status,super) VALUES('admin',?,'',1,1)`, hash); err != nil {
			return err
		}
		log.Println("已创建默认管理员 admin / ChangeMe")
	}
	// 会话密钥
	if db.GetSetting("session_secret") == "" {
		db.SetSetting("session_secret", util.RandomHex(32))
	}
	middleware.InitSession(db.GetSetting("session_secret"))
	// PKI
	if err := vpn.InitPKI(); err != nil {
		return fmt.Errorf("PKI 初始化失败: %w", err)
	}
	// 钩子脚本
	if err := writeHookScripts(); err != nil {
		return err
	}
	// 路由转发 + SNAT（容器重建后 iptables 规则会丢失，此处按实例网段重建）
	_ = fw.EnableForward()
	handler.SetupSNAT()
	// 虚拟 IP 绑定回收：启动时执行一次，之后每 24 小时一次（默认 90 天未登录且绑定满 180 天回收）
	go func() {
		for {
			if n := vpn.RecycleIPBindings(); n > 0 {
				log.Printf("IP 回收：%d 条绑定已释放", n)
			}
			time.Sleep(24 * time.Hour)
		}
	}()
	// 域名分流：
	//   - 按用户的规则 → 写进该用户 CCD 文件，解析变化时重写文件即可，用户重连生效（不重启实例）
	//   - 实例级规则 → 写进 server.conf，只在管理端点「应用变更」时重载
	if n, scopes, err := vpn.RefreshDomainRoutes(db.DB, false); err != nil {
		log.Printf("域名分流解析失败: %v", err)
	} else if n > 0 {
		syncDomainScopes(scopes)
		log.Printf("域名分流：%d 条规则 IP 有变化", n)
	}
	if n, err := vpn.SyncAllDomainCcd(db.DB); err != nil {
		log.Printf("域名分流 CCD 同步失败: %v", err)
	} else if n > 0 {
		log.Printf("域名分流：已重建 %d 个用户的 CCD 文件", n)
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			n, scopes, err := vpn.RefreshDomainRoutes(db.DB, false)
			if err != nil || n == 0 {
				continue
			}
			userFiles, instances := syncDomainScopes(scopes)
			db.Syslog("system", "域名分流解析更新",
				fmt.Sprintf("%d 条规则 IP 变化；用户 CCD %d 个已更新，实例级待重启 %v", n, userFiles, instances), "")
		}
	}()
	return nil
}

// syncDomainScopes 按作用域分发：用户维度直接重写 CCD（无需重启），实例级标记待重启。
// 返回重写的 CCD 文件数与需要重启的实例 ID。
func syncDomainScopes(scopes []vpn.DomainRouteScope) (int, []int64) {
	userScopes := []vpn.DomainRouteScope{}
	instances := []int64{}
	for _, sc := range scopes {
		if sc.Username == "" {
			instances = append(instances, sc.ServiceID)
		} else {
			userScopes = append(userScopes, sc)
		}
	}
	written := 0
	if len(userScopes) > 0 {
		if n, err := vpn.SyncDomainCcd(db.DB, userScopes); err == nil {
			written = n
		}
	}
	if len(instances) > 0 {
		handler.MarkDomainRouteDirty(instances)
	}
	return written, instances
}

// registerLDAPVerifier 注入基于 DB 配置的 LDAP 校验
func registerLDAPVerifier() {
	vpn.LdapChecker = vpn.LDAPBindCheck
}

// registerDomainRouteProvider 注入域名分流路由（后台填域名 → 解析成 IPv4 → /32 路由）
func registerDomainRouteProvider() {
	vpn.DomainRouteProvider = func(serviceID int64) []string {
		return vpn.DomainRouteLines(db.DB, serviceID)
	}
}

// registerDNSProvider 注入全局 DNS 推送（全局配置里的 DNS1/DNS2）
func registerDNSProvider() {
	vpn.DNSProvider = func() []string {
		return []string{db.GetSetting("dns1"), db.GetSetting("dns2")}
	}
}

// loadOrGenCert 加载自定义证书或生成自签证书
// staticFileHandler 前端静态资源处理器（内嵌 dist）
// ETag(内容哈希) + Cache-Control: no-cache：升级后浏览器必重新校验，未变更时 304，
// 避免升级后新旧 app.js/index.html 混用导致白屏。
func staticFileHandler(dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 命中已知接口但前缀不对（如关闭了旧别名后仍访问 /logincheck）时，返回 JSON 而非首页
		if strings.HasPrefix(r.URL.Path, "/api/") || handler.Routes[handler.BasePath(r.URL.Path)].H != nil {
			util.Fail(w, "接口不存在（请使用 "+handler.APIPrefix+" 前缀）")
			return
		}
		clean := path.Clean("/" + r.URL.Path) // URL 语义清洗，避免平台路径分隔符问题
		name := strings.TrimPrefix(clean, "/")
		if name == "" {
			name = "index.html"
		}
		data, rerr := fs.ReadFile(dist, name)
		if rerr != nil {
			// SPA 路由回退
			data, rerr = fs.ReadFile(dist, "index.html")
			if rerr != nil {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		sum := sha256.Sum256(data)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(data))
	})
}

func loadOrGenCert() (tls.Certificate, error) {
	sslDir := os.Getenv("SSLVPN_SSL_DIR")
	if sslDir == "" {
		sslDir = filepath.Join(dataDir(), "ssl")
	}
	crtPath := filepath.Join(sslDir, "server.crt")
	keyPath := filepath.Join(sslDir, "server.key")
	if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		return c, nil
	}
	_ = os.MkdirAll(sslDir, 0o700)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	host, _ := os.Hostname()
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: host, Organization: []string{"SSLVPN-Go"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	// 落盘
	_ = os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return cert, nil
}

// writeHookScripts 生成 openvpn 上下线钩子
func writeHookScripts() error {
	hooks := map[string]string{
		"connect.sh": `#!/bin/sh
# client-connect: 校验证书CN与用户名一致 + 单点在线
DB="/var/lib/sslvpn/auth/online_users"
TIME_STAMP=$(date "+%Y-%m-%d %T")
LOG_DIR="${SSLVPN_LOGDIR:-/var/lib/sslvpn/logs}"
mkdir -p "$LOG_DIR" "$(dirname "$DB")"
if [ "$common_name" != "$username" ]; then
  echo "{\"date\":\"$TIME_STAMP\",\"type\":\"认证拒绝\",\"msg\":\"用户名[$username]使用了[$common_name]的证书\",\"ip\":\"$trusted_ip\"}" >> "$LOG_DIR/$(date +%F)-openvpn-access.log"
  exit 1
fi
if grep -q "^$username " "$DB" 2>/dev/null; then
  exit 1
fi
/usr/local/bin/sslvpn record-ip "$username" "${ifconfig_pool_remote_ip}" >/dev/null 2>&1 || true
echo "$username 时间：$TIME_STAMP 隧道IP地址：${ifconfig_pool_remote_ip}" >> "$DB"
exit 0
`,
		"auth.sh": `#!/bin/sh
# auth-user-pass-verify 包装脚本
# OpenVPN 的 cmd 参数只能用空格分隔 argv，无法直接传 "sslvpn auth-verify"，
# 因此用这个单参数脚本转发；$1 为 OpenVPN 生成的临时凭证文件。
exec /usr/local/bin/sslvpn auth-verify "$1"
`,
		"disconnect.sh": `#!/bin/sh
DB="/var/lib/sslvpn/auth/online_users"
TIME_STAMP=$(date "+%Y-%m-%d %T")
LOG_DIR="${SSLVPN_LOGDIR:-/var/lib/sslvpn/logs}"
mkdir -p "$LOG_DIR"
echo "{\"date\":\"$TIME_STAMP\",\"type\":\"用户下线\",\"msg\":\"用户名=$common_name\",\"ip\":\"$trusted_ip\"}" >> "$LOG_DIR/$(date +%F)-openvpn-access.log"
sed -i "/^$common_name /d" "$DB" 2>/dev/null
exit 0
`,
	}
	dir := vpn.HookDir
	if dir == "" {
		dir = "/etc/openvpn/hooks"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, content := range hooks {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			return err
		}
	}
	// auth 目录
	_ = os.MkdirAll(filepath.Join(dataDir(), "auth"), 0o755)
	_ = os.MkdirAll(filepath.Join(dataDir(), "logs"), 0o755)
	_ = os.MkdirAll(filepath.Join(dataDir(), "backup"), 0o755)
	_ = os.MkdirAll(filepath.Join(dataDir(), "ssl"), 0o700)
	return nil
}
