// 虚拟 IP 绑定登记与回收
// 规则：
//   - 用户首次连接时 OpenVPN 按顺序从地址池分配 IP（ifconfig-pool-persist ipp.txt 天然保序持久），
//     client-connect 钩子调用 record-ip 把绑定写入 ip_binding 表；
//   - 回收条件（两者同时满足）：连续未登录 >= 90 天 且 绑定时长 >= 180 天
//     （可用 SSLVPN_IP_RECYCLE_DAYS / SSLVPN_IP_HOLD_DAYS 调整）；
//   - 回收 = 从各实例 ipp.txt 删除该用户行 + 删除登记记录，IP 回到池中按序复用；
//     在线用户不受影响，回收后该用户再次连接会分配新 IP。
package vpn

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func envDays(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// RecordIPBinding client-connect 钩子登记/刷新绑定（失败静默，不阻断连接）
func RecordIPBinding(username, vip string) {
	username = strings.TrimSpace(username)
	vip = strings.TrimSpace(vip)
	if username == "" || vip == "" {
		return
	}
	d, err := sql.Open("sqlite", "file:"+DBPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return
	}
	defer d.Close()
	// 已存在：刷新 last_login 与 vip；不存在：登记 bound_at/last_login=now
	_, _ = d.Exec(`INSERT INTO ip_binding(username,service,vip,bound_at,last_login)
		VALUES(?,?,?,datetime('now','localtime'),datetime('now','localtime'))
		ON CONFLICT(username) DO UPDATE SET vip=excluded.vip, last_login=datetime('now','localtime')`,
		username, os.Getenv("SSLVPN_INSTANCE"), vip)
}

// RecycleIPBindings 按规则回收过期绑定，返回回收条数（出错返回 -1）
func RecycleIPBindings() int {
	recycleDays := envDays("SSLVPN_IP_RECYCLE_DAYS", 90) // 连续未登录超过 N 天
	holdDays := envDays("SSLVPN_IP_HOLD_DAYS", 180)      // 绑定最长保留 N 天
	d, err := sql.Open("sqlite", "file:"+DBPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return -1
	}
	defer d.Close()
	rows, err := d.Query(`SELECT username, COALESCE(vip,'') FROM ip_binding
		WHERE last_login <= datetime('now','localtime', ?)
		  AND bound_at  <= datetime('now','localtime', ?)`,
		"-"+strconv.Itoa(recycleDays)+" days", "-"+strconv.Itoa(holdDays)+" days")
	if err != nil {
		return -1
	}
	type bind struct{ user, vip string }
	var stale []bind
	for rows.Next() {
		var b bind
		if rows.Scan(&b.user, &b.vip) == nil {
			stale = append(stale, b)
		}
	}
	rows.Close()
	if len(stale) == 0 {
		return 0
	}
	// 从所有实例的 ipp.txt 删除该用户，释放 IP
	entries, _ := os.ReadDir(filepath.Join(BaseDir, "instance"))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ipp := filepath.Join(BaseDir, "instance", e.Name(), "ipp.txt")
		data, err := os.ReadFile(ipp)
		if err != nil {
			continue
		}
		var keep []string
		changed := false
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRight(line, "\r")
			u := line
			if i := strings.IndexByte(line, ','); i >= 0 {
				u = line[:i]
			}
			if u == "" {
				continue
			}
			drop := false
			for _, b := range stale {
				if u == b.user {
					drop = true
					break
				}
			}
			if drop {
				changed = true
				continue
			}
			keep = append(keep, line)
		}
		if changed {
			content := strings.Join(keep, "\n")
			if content != "" && !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			if err := os.WriteFile(ipp, []byte(content), 0o644); err != nil {
				continue
			}
		}
	}
	n := 0
	for _, b := range stale {
		if _, err := d.Exec(`DELETE FROM ip_binding WHERE username=?`, b.user); err == nil {
			n++
			_ = appendRecycleLog(b.user, b.vip)
		}
	}
	return n
}

func appendRecycleLog(user, vip string) error {
	dir := os.Getenv("SSLVPN_LOGDIR")
	if dir == "" {
		dir = "/var/lib/sslvpn/logs"
	}
	_ = os.MkdirAll(dir, 0o755)
	entry := fmt.Sprintf(`{"date":%q,"type":"IP回收","msg":"用户名=%s 虚拟IP=%s 超期未使用，绑定已释放","ip":"-"}`+"\n",
		time.Now().Format("2006-01-02 15:04:05"), user, vip)
	f, err := os.OpenFile(filepath.Join(dir, time.Now().Format("2006-01-02")+"-openvpn-access.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}
