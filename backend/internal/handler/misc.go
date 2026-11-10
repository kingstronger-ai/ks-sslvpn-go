// 管理员、系统设置、防火墙、LDAP、日志、全局配置
package handler

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sslvpn/internal/db"
	"sslvpn/internal/fw"
	"sslvpn/internal/mail"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

// ---------- 管理员 ----------

func AdminList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id,username,email,status,super,created_at FROM admin ORDER BY id`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int64
		var u, e string
		var st, sp int
		var created string
		if rows.Scan(&id, &u, &e, &st, &sp, &created) == nil {
			list = append(list, map[string]any{
				"id": id, "username": u, "email": e, "status": st, "super": sp, "created_at": dbTime(created)})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func AdminUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int64   `json:"id"`
		Username    *string `json:"username"`
		Password    string  `json:"password"`
		OldPassword string  `json:"old_password"`
		Email       *string `json:"email"`
		Status      *int    `json:"status"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	name := ""
	if req.Username != nil {
		name = *req.Username
	}
	if req.Password != "" {
		// 修改密码必须验证旧密码，防止会话被劫持/离开座位时被人顺手改密
		if len(req.Password) < 8 {
			util.Fail(w, "密码长度至少 8 位")
			return
		}
		var curHash string
		if err := db.DB.QueryRow(`SELECT password FROM admin WHERE id=?`, req.ID).Scan(&curHash); err != nil {
			util.Fail(w, "账号不存在")
			return
		}
		if req.OldPassword == "" {
			util.Fail(w, "修改密码需要先输入旧密码验证")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(curHash), []byte(req.OldPassword)) != nil {
			db.Syslog("admin", "修改密码失败", "旧密码验证未通过", clientIP(r))
			util.Fail(w, "旧密码不正确，密码未修改")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if _, err := db.DB.Exec(`UPDATE admin SET password=? WHERE id=?`, hash, req.ID); err != nil {
			util.Fail(w, "更新失败")
			return
		}
		db.Syslog("admin", "修改管理员密码", name, clientIP(r))
	}
	if req.Username != nil && *req.Username != "" {
		_, _ = db.DB.Exec(`UPDATE admin SET username=? WHERE id=?`, *req.Username, req.ID)
	}
	if req.Email != nil {
		_, _ = db.DB.Exec(`UPDATE admin SET email=? WHERE id=?`, *req.Email, req.ID)
	}
	if req.Status != nil {
		_, _ = db.DB.Exec(`UPDATE admin SET status=? WHERE id=?`, *req.Status, req.ID)
	}
	db.Syslog("admin", "更新管理员", name, clientIP(r))
	util.OKMsg(w, "已更新", nil)
}

func AdminDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.ID == 0 {
		util.Fail(w, "参数错误")
		return
	}
	var cnt int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&cnt)
	if cnt <= 1 {
		util.Fail(w, "至少保留一个管理员")
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM admin WHERE id=?`, req.ID); err != nil {
		util.Fail(w, "删除失败")
		return
	}
	util.OKMsg(w, "已删除", nil)
}

func AdminAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || !validName(req.Username) || len(req.Password) < 8 {
		util.Fail(w, "参数错误（用户名合法、密码≥8位）")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if _, err := db.DB.Exec(`INSERT INTO admin(username,password,email,status,super,created_at) VALUES(?,?,?,1,0,datetime('now','localtime'))`,
		req.Username, hash, req.Email); err != nil {
		util.Fail(w, "创建失败（用户名可能已存在）")
		return
	}
	db.Syslog("admin", "添加管理员", req.Username, clientIP(r))
	util.OKMsg(w, "管理员已创建", nil)
}

// ---------- 系统设置 ----------

func SysUpdateLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginLimit  string `json:"login_limit"` // 允许登录网段，空=不限
		LoginNotice string `json:"login_notice"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	db.SetSetting("login_limit", req.LoginLimit)
	db.SetSetting("login_notice", req.LoginNotice)
	util.OKMsg(w, "登录限制已更新", nil)
}

func SysGetLoginOp(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]string{
		"login_limit":  db.GetSetting("login_limit"),
		"login_notice": db.GetSetting("login_notice"),
	})
}

func SysUpdateEmail(w http.ResponseWriter, r *http.Request) {
	var c mail.Config
	if err := util.ReadJSON(r, &c); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	saveSMTP(&c)
	util.OKMsg(w, "SMTP 配置已保存", nil)
}

func SysGetSMTP(w http.ResponseWriter, r *http.Request) {
	util.OK(w, loadSMTP())
}

func SysSendTestMail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Email == "" {
		util.Fail(w, "请填写测试收件邮箱")
		return
	}
	if err := mail.Send(loadSMTP(), req.Email, "SSLVPN 测试邮件",
		"<p>这是一封测试邮件，收到即说明 SMTP 配置正确。</p>"); err != nil {
		util.Fail(w, "发送失败: "+err.Error())
		return
	}
	util.OKMsg(w, "测试邮件已发送", nil)
}

func SysTestDB(w http.ResponseWriter, r *http.Request) {
	// 重构版使用内嵌 SQLite，恒定可用
	util.OKMsg(w, "数据库连接正常（内嵌 SQLite）", map[string]string{"type": "sqlite"})
}

func SysUpdateDebug(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Debug bool `json:"debug"`
	}
	_ = util.ReadJSON(r, &req)
	if req.Debug {
		db.SetSetting("debug", "1")
	} else {
		db.SetSetting("debug", "0")
	}
	util.OKMsg(w, "已更新", nil)
}

func SysUpdateWebPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Port < 1 || req.Port > 65535 {
		util.Fail(w, "端口不合法")
		return
	}
	db.SetSetting("web_port", fmt.Sprint(req.Port))
	util.OKMsg(w, "端口已保存，重启容器后生效", nil)
}

func SysUpdateSecureCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	db.SetSetting("secure_code", req.Code)
	util.OKMsg(w, "内部安全代码已更新", nil)
}

func SysUpdateRegAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status bool `json:"status"`
	}
	_ = util.ReadJSON(r, &req)
	if req.Status {
		db.SetSetting("register_admin_status", "1")
	} else {
		db.SetSetting("register_admin_status", "0")
	}
	util.OKMsg(w, "已更新", nil)
}

func SysUpdateRegUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status bool `json:"status"`
	}
	_ = util.ReadJSON(r, &req)
	if req.Status {
		db.SetSetting("register_user_status", "1")
	} else {
		db.SetSetting("register_user_status", "0")
	}
	util.OKMsg(w, "已更新", nil)
}

func SysUpdateDownloadURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	_ = util.ReadJSON(r, &req)
	db.SetSetting("download_url", req.URL)
	util.OKMsg(w, "已更新", nil)
}

func SysUpdateKeyFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Cert == "" || req.Key == "" {
		util.Fail(w, "请提供证书与私钥内容（PEM）")
		return
	}
	// 先校验证书与私钥配对，再写盘并热替换（坏证书不会落盘）
	if err := ApplyTLSCertPEM([]byte(req.Cert), []byte(req.Key)); err != nil {
		util.Fail(w, "证书与私钥不匹配或格式错误: "+err.Error())
		return
	}
	// 标记为手工上传（自动续签状态里据此区分来源；续签成功后会被改回 acme）
	db.SetSetting("cert_source", "upload")
	db.Syslog("admin", "更新SSL证书", "", clientIP(r))
	util.OKMsg(w, "证书已更新并即时生效（无需重启服务）", nil)
}

func SysRebootWeb(w http.ResponseWriter, r *http.Request) {
	// Go 版证书保存后即时热生效，此处仅作状态确认
	util.OKMsg(w, "证书保存后已即时生效，无需重启服务", nil)
}

func SysBackup(w http.ResponseWriter, r *http.Request) {
	name := "backup_" + time.Now().Format("20060102_150405") + ".tar.gz"
	path := filepath.Join(backupDir(), name)
	if err := createBackup(path); err != nil {
		util.Fail(w, "备份失败: "+err.Error())
		return
	}
	st, _ := os.Stat(path)
	_, _ = db.DB.Exec(`INSERT INTO backup(filename,size,created_at) VALUES(?,?,datetime('now','localtime'))`, name, st.Size())
	db.Syslog("admin", "创建备份", name, clientIP(r))
	util.OK(w, map[string]string{"filename": name, "size": fmt.Sprint(st.Size())})
}

func backupDir() string {
	d := os.Getenv("SSLVPN_BACKUP_DIR")
	if d == "" {
		d = "/var/lib/sslvpn/backup"
	}
	_ = os.MkdirAll(d, 0o755)
	return d
}

// safeBackupName 只允许备份目录下的 .tar.gz 纯文件名，
// 防止 ../ 或绝对路径穿越，导致读取/删除任意文件。
func safeBackupName(name string) bool {
	return name != "" && name == filepath.Base(name) &&
		!strings.ContainsAny(name, `/\`) && !strings.Contains(name, "..") &&
		strings.HasSuffix(name, ".tar.gz")
}

func createBackup(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	add := func(p string, info os.FileInfo) {
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return
		}
		hdr.Name = strings.TrimPrefix(p, "/")
		if info.IsDir() {
			hdr.Name += "/"
			_ = tw.WriteHeader(hdr)
			return
		}
		_ = tw.WriteHeader(hdr)
		data, err := os.Open(p)
		if err != nil {
			return
		}
		defer data.Close()
		_, _ = io.Copy(tw, data)
	}

	// 数据库 + 认证文件 + 实例配置 + 证书
	_ = filepath.Walk("/var/lib/sslvpn", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.Contains(p, "/backup/") && !strings.HasSuffix(p, "-wal") && !strings.HasSuffix(p, "-shm") {
			add(p, info)
		}
		return nil
	})
	_ = filepath.Walk(filepath.Join(vpn.BaseDir, "instance"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			add(p, info)
		}
		return nil
	})
	_ = tw.Close()
	_ = gz.Close()
	return nil
}

func SysBackupInfo(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id,filename,size,created_at FROM backup ORDER BY id DESC`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, size int64
		var fn, created string
		if rows.Scan(&id, &fn, &size, &created) == nil {
			list = append(list, map[string]any{"id": id, "filename": fn, "size": size, "created_at": dbTime(created)})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func SysBackupDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	name := strings.TrimSpace(req.Filename)
	if !safeBackupName(name) {
		util.Fail(w, "参数错误")
		return
	}
	data, err := os.ReadFile(filepath.Join(backupDir(), name))
	if err != nil {
		util.Fail(w, "备份文件不存在")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(data)
}

// SysBackupDelete 删除备份文件及其数据库记录（不可恢复）
func SysBackupDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filename string `json:"filename"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	name := strings.TrimSpace(req.Filename)
	if !safeBackupName(name) {
		util.Fail(w, "参数错误")
		return
	}
	// 文件已不存在时仍允许清理数据库里的孤儿记录
	if err := os.Remove(filepath.Join(backupDir(), name)); err != nil && !os.IsNotExist(err) {
		util.Fail(w, "删除失败: "+err.Error())
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM backup WHERE filename=?`, name); err != nil {
		util.Fail(w, "删除记录失败: "+err.Error())
		return
	}
	db.Syslog("admin", "删除备份", name, clientIP(r))
	util.OKMsg(w, "已删除备份 "+name, nil)
}

func SysBackupUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(200 << 20); err != nil {
		util.Fail(w, "请上传备份文件（multipart）")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		util.Fail(w, "未找到上传文件字段 file")
		return
	}
	defer file.Close()
	if !strings.HasSuffix(hdr.Filename, ".tar.gz") {
		util.Fail(w, "仅支持 .tar.gz 备份文件")
		return
	}
	dst := filepath.Join(backupDir(), "upload_"+time.Now().Format("20060102_150405")+"_"+filepath.Base(hdr.Filename))
	out, err := os.Create(dst)
	if err != nil {
		util.Fail(w, "保存失败")
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		util.Fail(w, "保存失败")
		return
	}
	// 登记到备份列表，否则上传的文件只能下载/删除不到
	name := filepath.Base(dst)
	if st, err := out.Stat(); err == nil {
		_, _ = db.DB.Exec(`INSERT INTO backup(filename,size,created_at) VALUES(?,?,datetime('now','localtime'))`,
			name, st.Size())
	}
	db.Syslog("admin", "上传备份", name, clientIP(r))
	util.OKMsg(w, "备份文件已上传: "+name, nil)
}

func SysUpdateName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	_ = util.ReadJSON(r, &req)
	db.SetSetting("sys_name", req.Name)
	util.OKMsg(w, "系统名称已更新", nil)
}

func SysUpdateCopyright(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Copyright string `json:"copyright"`
	}
	_ = util.ReadJSON(r, &req)
	db.SetSetting("copyright", req.Copyright)
	util.OKMsg(w, "版权信息已更新", nil)
}

func SysUpdateSystem(w http.ResponseWriter, r *http.Request) {
	util.Fail(w, "重构版为社区开源实现，暂不支持在线更新")
}

func SysGetRegisterList(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]string{
		"register_admin_status": db.GetSetting("register_admin_status"),
		"register_user_status":  db.GetSetting("register_user_status"),
	})
}

func SysGetCertList(w http.ResponseWriter, r *http.Request) {
	// 列出 PKI 已签发证书
	entries, err := os.ReadDir(filepath.Join(vpn.PKIDir, "issued"))
	if err != nil {
		util.OK(w, map[string]any{"list": []any{}})
		return
	}
	list := []map[string]string{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".crt") {
			list = append(list, map[string]string{
				"name": strings.TrimSuffix(e.Name(), ".crt"),
				"file": e.Name(),
			})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func SysGetOtherInfo(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]any{
		"sys":      systemInfoMap(),
		"oem":      map[string]string{"sys_name": db.GetSetting("sys_name"), "copyright": db.GetSetting("copyright"), "copyright_url": db.GetSetting("copyright_url")},
		"web_port": db.GetSetting("web_port"),
	})
}

// ---------- 防火墙 ----------

func FWRuleList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id,port,proto,action,source,note,created_at FROM port_rule ORDER BY id DESC`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, port int64
		var proto, action, source, note, created string
		if rows.Scan(&id, &port, &proto, &action, &source, &note, &created) == nil {
			list = append(list, map[string]any{
				"id": id, "port": port, "proto": proto, "action": action,
				"source": source, "note": note, "created_at": dbTime(created)})
		}
	}
	util.OK(w, map[string]any{"list": list, "out_iface": fw.OutInterface(), "out_ip": fw.OutInterfaceIP()})
}

func FWAddRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Action string `json:"action"`
		Source string `json:"source"`
		Note   string `json:"note"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Port <= 0 {
		util.Fail(w, "参数错误")
		return
	}
	if req.Proto != "tcp" && req.Proto != "udp" {
		req.Proto = "tcp"
	}
	if req.Action != "DROP" {
		req.Action = "ACCEPT"
	}
	if req.Source == "" {
		req.Source = "0.0.0.0/0"
	}
	if err := fw.AddRule(req.Port, req.Proto, req.Action, req.Source); err != nil {
		util.Fail(w, "iptables 执行失败: "+err.Error())
		return
	}
	_, _ = db.DB.Exec(`INSERT INTO port_rule(port,proto,action,source,note,created_at) VALUES(?,?,?,?,?,datetime('now','localtime'))`,
		req.Port, req.Proto, req.Action, req.Source, req.Note)
	db.Syslog("admin", "添加防火墙规则", fmt.Sprintf("%d/%s %s", req.Port, req.Proto, req.Action), clientIP(r))
	util.OKMsg(w, "规则已生效", nil)
}

// ---------- LDAP ----------

func LdapGet(w http.ResponseWriter, r *http.Request) {
	var row struct {
		Server   string
		Port     int
		BindDN   string
		BindPass string
		BaseDN   string
		OU       string
		Filter   string
		Enabled  int
	}
	err := db.DB.QueryRow(`SELECT server,port,bind_dn,bind_pass,base_dn,ou,filter,enabled FROM ldap_conf WHERE id=1`).
		Scan(&row.Server, &row.Port, &row.BindDN, &row.BindPass, &row.BaseDN, &row.OU, &row.Filter, &row.Enabled)
	if err == sql.ErrNoRows {
		util.OK(w, map[string]any{"enabled": 0, "filter": "(uid=%s)", "port": 389})
		return
	}
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	util.OK(w, map[string]any{
		"server": row.Server, "port": row.Port, "bind_dn": row.BindDN, "bind_pass": row.BindPass,
		"base_dn": row.BaseDN, "ou": row.OU, "filter": row.Filter, "enabled": row.Enabled,
	})
}

func LdapSet(w http.ResponseWriter, r *http.Request) { LdapUpdate(w, r) }

func LdapUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		BindDN   string `json:"bind_dn"`
		BindPass string `json:"bind_pass"`
		BaseDN   string `json:"base_dn"`
		OU       string `json:"ou"`
		Filter   string `json:"filter"`
		Enabled  int    `json:"enabled"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if req.Filter == "" {
		req.Filter = "(uid=%s)"
	}
	if req.Port == 0 {
		req.Port = 389
	}
	if _, err := db.DB.Exec(`INSERT INTO ldap_conf(id,server,port,bind_dn,bind_pass,base_dn,ou,filter,enabled)
		VALUES(1,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET server=excluded.server,port=excluded.port,bind_dn=excluded.bind_dn,
		bind_pass=excluded.bind_pass,base_dn=excluded.base_dn,ou=excluded.ou,filter=excluded.filter,enabled=excluded.enabled`,
		req.Server, req.Port, req.BindDN, req.BindPass, req.BaseDN, req.OU, req.Filter, req.Enabled); err != nil {
		util.Fail(w, "保存失败")
		return
	}
	util.OKMsg(w, "LDAP 配置已保存", nil)
}

// ldapConn 建立 LDAP 连接（供测试/认证/同步使用）
func ldapConnect() (ldapClient, error) {
	var server string
	var port int
	var bindDN, bindPass, baseDN, ou, filter string
	err := db.DB.QueryRow(`SELECT server,port,bind_dn,bind_pass,base_dn,ou,filter FROM ldap_conf WHERE id=1`).
		Scan(&server, &port, &bindDN, &bindPass, &baseDN, &ou, &filter)
	if err != nil {
		return ldapClient{}, fmt.Errorf("LDAP 未配置")
	}
	if filter == "" {
		filter = "(uid=%s)"
	}
	return newLDAPClient(server, port, bindDN, bindPass, baseDN, ou, filter)
}

func LdapTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := util.ReadJSON(r, &req); err != nil || req.Username == "" {
		util.Fail(w, "请输入测试账号")
		return
	}
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	defer c.Close()
	if err := c.BindCheck(req.Username, req.Password); err != nil {
		util.Fail(w, "LDAP 认证失败: "+err.Error())
		return
	}
	util.OKMsg(w, "LDAP 认证成功", nil)
}

// LdapSync 从 LDAP 同步用户（本地建号，密码标记为 LDAP 认证）
func LdapSync(w http.ResponseWriter, r *http.Request) {
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsers()
	if err != nil {
		util.Fail(w, "同步失败: "+err.Error())
		return
	}
	added, skipped := 0, 0
	for _, u := range users {
		if !validName(u) {
			continue
		}
		var exists int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, u).Scan(&exists)
		if exists > 0 {
			skipped++
			continue
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,status,created_at) VALUES(?,?,?,1,datetime('now','localtime'))`,
			u, "-", "ldap"); err == nil {
			_ = vpn.IssueUserCert(u)
			added++
		}
	}
	syncAuthFiles()
	util.OK(w, map[string]int{"added": added, "skipped": skipped, "total": len(users)})
}

// LdapPing 测试连接：管理员绑定 + 统计匹配用户数（对齐原版"成功匹配 N 个用户"）
func LdapPing(w http.ResponseWriter, r *http.Request) {
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, "连接失败: "+err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsersDetail()
	if err != nil {
		util.Fail(w, "搜索失败: "+err.Error())
		return
	}
	util.OKMsg(w, fmt.Sprintf("连接成功，匹配到 %d 个用户", len(users)), map[string]int{"count": len(users)})
}

// LdapListUsers 拉取 LDAP 服务器用户列表（不导入），前端弹窗勾选
func LdapListUsers(w http.ResponseWriter, r *http.Request) {
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsersDetail()
	if err != nil {
		util.Fail(w, "获取用户列表失败: "+err.Error())
		return
	}
	if users == nil {
		users = []LdapUser{}
	}
	// 标记本地是否已存在（含已禁用）
	exists := map[string]bool{}
	for _, u := range users {
		var n int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, u.Username).Scan(&n)
		exists[u.Username] = n > 0
	}
	util.OK(w, map[string]any{"list": users, "exists": exists})
}

// LdapImport 导入 LDAP 用户：body 可传 {usernames:[...], group_id}；
// usernames 为空 = 导入全部（兼容原全量同步）
func LdapImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Usernames []string `json:"usernames"`
		GroupID   int64    `json:"group_id"`
	}
	if r.ContentLength > 0 {
		_ = util.ReadJSON(r, &req)
	}
	set := map[string]bool{}
	for _, u := range req.Usernames {
		set[u] = true
	}
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsersDetail()
	if err != nil {
		util.Fail(w, "同步失败: "+err.Error())
		return
	}
	added, skipped := 0, 0
	for _, u := range users {
		if len(req.Usernames) > 0 && !set[u.Username] {
			continue
		}
		if !validName(u.Username) {
			continue
		}
		var exists int
		_ = db.DB.QueryRow(`SELECT COUNT(*) FROM account WHERE username=?`, u.Username).Scan(&exists)
		if exists > 0 {
			skipped++
			continue
		}
		if _, err := db.DB.Exec(`INSERT INTO account(username,password,auth_type,email,group_id,status,created_at) VALUES(?,?,?,?,?,1,datetime('now','localtime'))`,
			u.Username, "-", "ldap", u.Email, req.GroupID); err == nil {
			_ = vpn.IssueUserCert(u.Username)
			added++
		}
	}
	syncAuthFiles()
	db.Syslog("admin", "导入 LDAP 用户", fmt.Sprintf("新增 %d 跳过 %d", added, skipped), clientIP(r))
	util.OK(w, map[string]int{"added": added, "skipped": skipped, "total": len(users)})
}

// ---------- 系统日志 / 访问日志 ----------

func SyslogList(w http.ResponseWriter, r *http.Request) {
	page := atoiSafe(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size := 50
	rows, err := db.DB.Query(`SELECT id,admin,action,detail,ip,created_at FROM syslog
		ORDER BY id DESC LIMIT ? OFFSET ?`, size, (page-1)*size)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int64
		var admin, action, detail, ip, created string
		if rows.Scan(&id, &admin, &action, &detail, &ip, &created) == nil {
			list = append(list, map[string]any{
				"id": id, "admin": admin, "action": action, "detail": detail, "ip": ip, "created_at": dbTime(created)})
		}
	}
	util.OK(w, map[string]any{"list": list, "page": page})
}

func SyslogTruncate(w http.ResponseWriter, r *http.Request) {
	if _, err := db.DB.Exec(`DELETE FROM syslog`); err != nil {
		util.Fail(w, "清空失败")
		return
	}
	util.OKMsg(w, "系统日志已清空", nil)
}

// ---------- 全局配置（linuxcc 组） ----------

func GlobalCfgGet(w http.ResponseWriter, r *http.Request) {
	util.OK(w, map[string]string{
		"public_host":    db.GetSetting("public_host"),
		"dns1":           db.GetSetting("dns1"),
		"dns2":           db.GetSetting("dns2"),
		"download_url":   db.GetSetting("download_url"),
		"sys_name":       db.GetSetting("sys_name"),
		"copyright":      db.GetSetting("copyright"),
		"copyright_url":  db.GetSetting("copyright_url"),
		"web_port":       db.GetSetting("web_port"),
		"register_user":  db.GetSetting("register_user_status"),
		"register_admin": db.GetSetting("register_admin_status"),
		"login_limit":    db.GetSetting("login_limit"),
	})
}

func GlobalCfgUpdate(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	allowed := map[string]bool{
		"public_host": true, "dns1": true, "dns2": true,
		"download_url": true, "sys_name": true, "copyright": true, "copyright_url": true,
		"web_port": true, "register_user": true, "register_admin": true, "login_limit": true,
	}
	for k, v := range req {
		if allowed[k] {
			db.SetSetting(k, v)
		}
	}
	util.OKMsg(w, "配置已保存", nil)
}

// ---------- License ----------

func LicenseAccept(w http.ResponseWriter, r *http.Request) {
	db.SetSetting("license_accepted", "1")
	util.OKMsg(w, "授权协议已接受（社区开源版）", nil)
}

// ---------- 其它信息 ----------

func GetFlagHandler() http.HandlerFunc { return GetFlag }
