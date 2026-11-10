// 访问日志（JSON 行文件）与 VPN 服务日志
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
	"sslvpn/internal/vpn"
)

func logDir() string {
	d := os.Getenv("SSLVPN_LOGDIR")
	if d == "" {
		d = "/var/lib/sslvpn/logs"
	}
	return d
}

type accessEntry struct {
	Date string `json:"date"`
	Type string `json:"type"`
	Msg  string `json:"msg"`
	IP   string `json:"ip"`
	ID   string `json:"id"`
}

func readAccessLog(day string, filterFn func(*accessEntry) bool) []accessEntry {
	if day == "" {
		day = time.Now().Format("2006-01-02")
	}
	data, err := os.ReadFile(filepath.Join(logDir(), day+"-openvpn-access.log"))
	if err != nil {
		return []accessEntry{}
	}
	var out []accessEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e accessEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			if filterFn == nil || filterFn(&e) {
				out = append(out, e)
			}
		}
	}
	// 新的在后
	return out
}

func LogStatus(w http.ResponseWriter, r *http.Request) {
	users := vpn.AllOnlineUsers()
	util.OK(w, map[string]any{"list": users, "count": len(users), "time": db.Now()})
}

func LogAccess(w http.ResponseWriter, r *http.Request) {
	day := r.URL.Query().Get("date")
	keyword := r.URL.Query().Get("keyword")
	entries := readAccessLog(day, func(e *accessEntry) bool {
		return keyword == "" || strings.Contains(e.Msg, keyword) || strings.Contains(e.Type, keyword) || strings.Contains(e.IP, keyword)
	})
	util.OK(w, map[string]any{"list": entries, "count": len(entries)})
}

func LogClientIP(w http.ResponseWriter, r *http.Request) {
	// 汇总近 30 天客户端 IP 出现次数
	counts := map[string]int{}
	days := listLogDays(30)
	for _, d := range days {
		for _, e := range readAccessLog(d, nil) {
			if e.IP != "" {
				counts[e.IP]++
			}
		}
	}
	list := []map[string]any{}
	for ip, c := range counts {
		list = append(list, map[string]any{"ip": ip, "count": c})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i]["count"].(int) > list[j]["count"].(int)
	})
	util.OK(w, map[string]any{"list": list})
}

func listLogDays(max int) []string {
	entries, err := os.ReadDir(logDir())
	if err != nil {
		return nil
	}
	var days []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, "-openvpn-access.log") {
			days = append(days, strings.TrimSuffix(name, "-openvpn-access.log"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	if len(days) > max {
		days = days[:max]
	}
	return days
}

func LogVPNServer(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("service")
	lines := atoiSafe(r.URL.Query().Get("lines"))
	if lines <= 0 || lines > 2000 {
		lines = 200
	}
	if name == "" {
		util.Fail(w, "请指定服务实例名")
		return
	}
	data, err := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", name, "openvpn.log"))
	if err != nil {
		util.OK(w, map[string]string{"log": "(无日志)"})
		return
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	util.OK(w, map[string]any{"log": strings.Join(all, "\n")})
}

func DeleteAccessLogs(w http.ResponseWriter, r *http.Request) {
	day := r.URL.Query().Get("date")
	removed := 0
	entries, err := os.ReadDir(logDir())
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "-openvpn-access.log") {
				if day == "" || day == "all" || strings.HasPrefix(e.Name(), day) {
					if os.Remove(filepath.Join(logDir(), e.Name())) == nil {
						removed++
					}
				}
			}
		}
	}
	util.OK(w, map[string]int{"removed": removed})
}

func DownloadVPNServerLogs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("service")
	if name == "" || strings.Contains(name, "..") {
		util.Fail(w, "参数错误")
		return
	}
	data, err := os.ReadFile(filepath.Join(vpn.BaseDir, "instance", name, "openvpn.log"))
	if err != nil {
		data = []byte("")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_openvpn.log"`, name))
	_, _ = w.Write(data)
}

func EditFilterRule(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id,rule FROM log_filter ORDER BY id`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id int64
		var rule string
		if rows.Scan(&id, &rule) == nil {
			list = append(list, map[string]any{"id": id, "rule": rule})
		}
	}
	util.OK(w, map[string]any{"list": list})
}

func UpdateFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule  string `json:"rule"`
		ID    int64  `json:"id"`
		DelID int64  `json:"del_id"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	if req.DelID > 0 {
		_, _ = db.DB.Exec(`DELETE FROM log_filter WHERE id=?`, req.DelID)
		util.OKMsg(w, "过滤规则已删除", nil)
		return
	}
	if req.Rule == "" {
		util.Fail(w, "规则不能为空")
		return
	}
	_, _ = db.DB.Exec(`INSERT INTO log_filter(rule,created_at) VALUES(?,datetime('now','localtime'))`, req.Rule)
	util.OKMsg(w, "过滤规则已添加", nil)
}

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

func ShowRouterTable(w http.ResponseWriter, r *http.Request) {
	out, err := osReadFile("/proc/net/route")
	if err != nil {
		util.Fail(w, "路由表读取失败")
		return
	}
	util.OK(w, map[string]string{"route_table": string(out)})
}
