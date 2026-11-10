// Package db SQLite 数据层：连接管理与建表迁移
package db

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	DB   *sql.DB
	once sync.Once
)

// Open 打开（或创建）SQLite 数据库并执行迁移
func Open(dataDir string) error {
	var err error
	once.Do(func() {
		if err = os.MkdirAll(dataDir, 0o755); err != nil {
			return
		}
		dsn := "file:" + filepath.ToSlash(filepath.Join(dataDir, "sslvpn.db")) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		DB, err = sql.Open("sqlite", dsn)
		if err != nil {
			return
		}
		// WAL 允许多读一写：连接池 >1 保证单个卡死/泄漏的连接不会饿死全站。
		// 写入由 busy_timeout(5000) 排队，无需担心锁竞争。
		DB.SetMaxOpenConns(4)
		DB.SetMaxIdleConns(4)
		DB.SetConnMaxLifetime(time.Hour)
		go leakWatchdog()
		if err = DB.Ping(); err != nil {
			return
		}
		err = migrate()
	})
	return err
}

func migrate() error {
	stmts := []string{
		// 管理员
		`CREATE TABLE IF NOT EXISTS admin(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,            -- bcrypt
			email TEXT DEFAULT '',
			status INTEGER DEFAULT 1,          -- 1 启用 0 禁用
			super INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// VPN 账号
		`CREATE TABLE IF NOT EXISTS account(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,            -- 明文（需下发/写入认证文件）+ verify 用
			auth_type TEXT DEFAULT 'local',    -- local | totp | ldap | feishu
			totp_secret TEXT DEFAULT '',
			email TEXT DEFAULT '',
			login_aliases TEXT DEFAULT '',     -- 逗号分隔的 UPN/DN 登录别名（管理员开启后生效）
			expire_date TEXT DEFAULT '',       -- YYYY-MM-DD，空=永不过期
			group_id INTEGER DEFAULT 0,
			status INTEGER DEFAULT 1,          -- 1 启用 0 禁用
			online INTEGER DEFAULT 0,
			note TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// VPN 服务实例
		`CREATE TABLE IF NOT EXISTS service(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,         -- 实例名（字母数字）
			port INTEGER UNIQUE NOT NULL,
			proto TEXT DEFAULT 'udp',
			subnet TEXT DEFAULT '10.8.0.0',
			mask TEXT DEFAULT '255.255.255.0',
			push_routes TEXT DEFAULT '',       -- 每行一条 "net mask"
			redirect_gw INTEGER DEFAULT 0,     -- 全局代理
			client_to_client INTEGER DEFAULT 0,
			duplicate_cn INTEGER DEFAULT 0,
			max_clients INTEGER DEFAULT 253,
			status INTEGER DEFAULT 0,          -- 0 停止 1 运行
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// CCD 每用户高级配置
		`CREATE TABLE IF NOT EXISTS ccd(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			ifconfig_push TEXT DEFAULT '',     -- "ip mask"
			iroutes TEXT DEFAULT '',           -- 每行一条 iroute
			push_routes TEXT DEFAULT '',
			dns TEXT DEFAULT '',               -- 按用户推送的 DNS
			proxy_mode INTEGER DEFAULT 0,      -- 0=继承服务实例 1=全局代理 2=仅内网
			raw TEXT DEFAULT '',               -- 原始 CCD 内容（非空时优先生效）
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(service_id, username))`,
		// 用户分组
		`CREATE TABLE IF NOT EXISTS "group"(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			note TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// 分组-服务关联
		`CREATE TABLE IF NOT EXISTS group_service(
			group_id INTEGER NOT NULL,
			service_id INTEGER NOT NULL,
			UNIQUE(group_id, service_id))`,
		// 域名分流规则（后台填域名 → 定时解析成 IPv4 → 以 /32 路由下发）
		`CREATE TABLE IF NOT EXISTS domain_route(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER DEFAULT 0,      -- 0=所有实例，>0=仅该实例
			username TEXT NOT NULL DEFAULT '',  -- 非空=仅该用户（写 CCD，重连即生效）；空=实例级（写 server.conf，需重启）
			domain TEXT NOT NULL,              -- 规范化后的域名
			note TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			ips TEXT DEFAULT '',               -- 上次解析到的 IPv4，逗号分隔
			resolved_at INTEGER DEFAULT 0,     -- 上次解析时间（unix）
			ttl INTEGER DEFAULT 300,           -- 重新解析间隔（秒）
			last_error TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(service_id, username, domain))`,
		// 防火墙端口规则
		`CREATE TABLE IF NOT EXISTS port_rule(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			port INTEGER NOT NULL,
			proto TEXT DEFAULT 'tcp',
			action TEXT DEFAULT 'ACCEPT',
			source TEXT DEFAULT '0.0.0.0/0',
			note TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// 系统设置 KV
		`CREATE TABLE IF NOT EXISTS settings(
			k TEXT PRIMARY KEY,
			v TEXT DEFAULT '')`,
		// 系统操作日志
		`CREATE TABLE IF NOT EXISTS syslog(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			admin TEXT DEFAULT '',
			action TEXT DEFAULT '',
			detail TEXT DEFAULT '',
			ip TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// 虚拟 IP 绑定登记（首次连接按顺序分配后在此登记，供到期回收）
		`CREATE TABLE IF NOT EXISTS ip_binding(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			service TEXT DEFAULT '',
			vip TEXT DEFAULT '',
			bound_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// 访问日志过滤规则
		`CREATE TABLE IF NOT EXISTS log_filter(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule TEXT NOT NULL)`,
		// LDAP 配置（单行）
		`CREATE TABLE IF NOT EXISTS ldap_conf(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			server TEXT DEFAULT '',
			port INTEGER DEFAULT 389,
			bind_dn TEXT DEFAULT '',
			bind_pass TEXT DEFAULT '',
			base_dn TEXT DEFAULT '',
			ou TEXT DEFAULT '',
			filter TEXT DEFAULT '(uid=%s)',
			enabled INTEGER DEFAULT 0)`,
		// 备份记录
		`CREATE TABLE IF NOT EXISTS backup(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			filename TEXT UNIQUE NOT NULL,
			size INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		// 密码找回安全码
		`CREATE TABLE IF NOT EXISTS secure_code(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,              -- 邮箱/用户名
			code TEXT NOT NULL,
			expire_at DATETIME NOT NULL)`,
		// 飞书扫码登录：设备授权请求（device_code 由客户端持有，state 由浏览器回跳携带）
		`CREATE TABLE IF NOT EXISTS sso_device(
			device_code TEXT PRIMARY KEY,
			provider TEXT NOT NULL DEFAULT 'feishu',  -- feishu | dingtalk | wecom
			verifier_hash TEXT NOT NULL DEFAULT '',   -- sha256(device_verifier)，明文不落库
			state TEXT NOT NULL DEFAULT '',           -- 飞书回调 state（防 CSRF）
			status TEXT NOT NULL DEFAULT 'pending',  -- pending|authorized|denied|delivered
			expected_username TEXT DEFAULT '',        -- 客户端指定的期望账号（可选）
			username TEXT DEFAULT '',
			email TEXT DEFAULT '',
			match_method TEXT DEFAULT '',             -- feishu_id|email|mock
			error TEXT DEFAULT '',
			callback_url TEXT DEFAULT '',             -- 本次授权使用的 redirect_uri
			vpn_plain TEXT DEFAULT '',                -- 待领取的一次性口令明文，poll 后立即清空
			created_ip TEXT DEFAULT '',
			profile_sent INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL DEFAULT 0,    -- unix 秒
			expires_at INTEGER NOT NULL DEFAULT 0)`,
		// 一次性 VPN 口令（OpenVPN 密码位）：FS1.<base64url>，只存哈希
		`CREATE TABLE IF NOT EXISTS sso_token(
			token_hash TEXT PRIMARY KEY,
			token_id TEXT DEFAULT '',
			username TEXT NOT NULL,
			email TEXT DEFAULT '',
			method TEXT DEFAULT 'feishu',
			consumed INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER NOT NULL DEFAULT 0)`,
		`CREATE INDEX IF NOT EXISTS idx_account_expire ON account(expire_date)`,
		`CREATE INDEX IF NOT EXISTS idx_syslog_time ON syslog(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_device_expire ON sso_device(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_device_state ON sso_device(state)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_token_expire ON sso_token(expires_at)`,
	}
	for _, s := range stmts {
		if _, err := DB.Exec(s); err != nil {
			return err
		}
	}
	// 旧库补列（ALTER TABLE 仅支持追加，常量默认值）
	for _, c := range [][3]string{
		{"ccd", "dns", "TEXT DEFAULT ''"},
		{"ccd", "proxy_mode", "INTEGER DEFAULT 0"},
		{"ccd", "raw", "TEXT DEFAULT ''"},
		{"ccd", "created_at", "TEXT DEFAULT ''"},
		{"ccd", "updated_at", "TEXT DEFAULT ''"},
		// 老库补列：飞书 SSO 首发版本没有 provider / vpn_plain
		{"sso_device", "provider", "TEXT NOT NULL DEFAULT 'feishu'"},
		{"sso_device", "vpn_plain", "TEXT DEFAULT ''"},
		{"sso_device", "callback_url", "TEXT DEFAULT ''"},
		{"sso_device", "profile_sent", "INTEGER DEFAULT 0"},
		// 登录别名：短账号与 UPN/DN 无字符串对应关系，必须由管理员显式配置
		{"account", "login_aliases", "TEXT DEFAULT ''"},
	} {
		if err := ensureColumn(c[0], c[1], c[2]); err != nil {
			return err
		}
	}
	return migrateDomainRouteUser()
}

// migrateDomainRouteUser 旧库的 domain_route 带 UNIQUE(service_id,domain)，同一域名无法按用户配多条；
// 这里重建为 UNIQUE(service_id,username,domain)。旧数据 username=” 表示实例级（行为不变）。
func migrateDomainRouteUser() error {
	var tableSQL string
	err := DB.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND name='domain_route'`).Scan(&tableSQL)
	if err != nil || tableSQL == "" {
		return nil
	}
	if strings.Contains(tableSQL, "username") {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range []string{
		`ALTER TABLE domain_route RENAME TO domain_route_legacy`,
		`CREATE TABLE domain_route(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER DEFAULT 0,
			username TEXT NOT NULL DEFAULT '',
			domain TEXT NOT NULL,
			note TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			ips TEXT DEFAULT '',
			resolved_at INTEGER DEFAULT 0,
			ttl INTEGER DEFAULT 300,
			last_error TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(service_id, username, domain))`,
		`INSERT INTO domain_route(id,service_id,username,domain,note,enabled,ips,resolved_at,ttl,last_error,created_at,updated_at)
			SELECT id,service_id,'',domain,COALESCE(note,''),COALESCE(enabled,1),COALESCE(ips,''),
				COALESCE(resolved_at,0),COALESCE(ttl,300),COALESCE(last_error,''),
				COALESCE(created_at,''),COALESCE(updated_at,'') FROM domain_route_legacy`,
		`DROP TABLE domain_route_legacy`,
	} {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ensureColumn 若表缺少某列则补上
func ensureColumn(table, col, decl string) error {
	rows, err := DB.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt any
		if rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk) == nil && name == col {
			exists = true
		}
	}
	rows.Close()
	if exists {
		return nil
	}
	_, err = DB.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + decl)
	return err
}

// GetSetting 读取设置项
func GetSetting(key string) string {
	var v string
	err := DB.QueryRow(`SELECT v FROM settings WHERE k=?`, key).Scan(&v)
	if err != nil {
		return ""
	}
	return v
}

// SetSetting 写入设置项
func SetSetting(key, val string) {
	_, err := DB.Exec(`INSERT INTO settings(k,v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, val)
	if err != nil {
		log.Println("set setting:", key, err)
	}
}

// Syslog 写系统日志
func Syslog(admin, action, detail, ip string) {
	_, _ = DB.Exec(`INSERT INTO syslog(admin,action,detail,ip,created_at) VALUES(?,?,?,?,datetime('now','localtime'))`,
		admin, action, detail, ip)
}

// Now 统一时间格式
func Now() string { return time.Now().Format("2006-01-02 15:04:05") }

// ErrNotFound 通用未找到
var ErrNotFound = errors.New("record not found")

// leakWatchdog 连接泄漏监视器：所有连接被持续占用 30 秒时，自动输出全 goroutine
// 堆栈到日志（不会终止进程），便于定位占住连接的代码路径。正常业务高峰几毫秒内
// 即归还连接，绝不会触发；触发即代表存在阻塞/泄漏。
func leakWatchdog() {
	sinceStuck := time.Time{}
	for {
		time.Sleep(10 * time.Second)
		st := DB.Stats()
		if st.InUse < st.MaxOpenConnections {
			sinceStuck = time.Time{}
			continue
		}
		if sinceStuck.IsZero() {
			sinceStuck = time.Now()
			continue
		}
		if time.Since(sinceStuck) >= 30*time.Second {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			log.Printf("!! DB 连接池被持续占用 30s（可能存在连接泄漏/阻塞），全 goroutine 堆栈：\n%s", buf[:n])
			sinceStuck = time.Now() // 60s 后若仍占用可再次输出
		}
	}
}
