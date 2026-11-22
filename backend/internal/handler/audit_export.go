// 审计归因与导出（B2 最小可用版）：真实操作主体 + CSV/JSON 导出 + 近 30 天聚合。
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
)

// syslogFromRequest 从会话 token 取真实管理员主体写审计；无法识别身份时记 unknown。
// 全 handler 统一走这里，避免主体被硬编码为 "admin"。
func syslogFromRequest(r *http.Request, action, detail string) {
	subject := middleware.SessionUser(middleware.TokenFromRequest(r))
	var adminID int64
	if subject == "" {
		subject = "unknown"
	} else if a, ok := currentAdmin(r); ok {
		adminID = a.ID
	} else if db.DB != nil {
		_ = db.DB.QueryRow(`SELECT id FROM admin WHERE username=?`, subject).Scan(&adminID)
	}
	db.SyslogWithID(subject, action, detail, clientIP(r), adminID)
}

type auditRow struct {
	ID        int64  `json:"id"`
	Admin     string `json:"admin"`
	AdminID   int64  `json:"admin_id"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	CreatedAt string `json:"created_at"`
}

// AuditExport POST：按日期区间与 action 过滤导出 syslog，format=csv|json
func AuditExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format string `json:"format"`
		Start  string `json:"start"`
		End    string `json:"end"`
		Action string `json:"action"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		util.Fail(w, "format 仅支持 csv 或 json")
		return
	}
	start, ok := auditDate(req.Start)
	if !ok {
		util.Fail(w, "start 日期格式错误，应为 YYYY-MM-DD")
		return
	}
	end, ok := auditDate(req.End)
	if !ok {
		util.Fail(w, "end 日期格式错误，应为 YYYY-MM-DD")
		return
	}
	if start != "" && end != "" && start > end {
		util.Fail(w, "start 不能晚于 end")
		return
	}

	query := `SELECT id,admin,COALESCE(admin_id,0),action,detail,ip,created_at FROM syslog WHERE 1=1`
	var args []any
	if start != "" {
		query += ` AND date(created_at)>=?`
		args = append(args, start)
	}
	if end != "" {
		query += ` AND date(created_at)<=?`
		args = append(args, end)
	}
	if action := strings.TrimSpace(req.Action); action != "" {
		query += ` AND action=?`
		args = append(args, action)
	}
	query += ` ORDER BY id DESC`
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []auditRow{}
	for rows.Next() {
		var row auditRow
		if rows.Scan(&row.ID, &row.Admin, &row.AdminID, &row.Action, &row.Detail, &row.IP, &row.CreatedAt) == nil {
			list = append(list, row)
		}
	}

	filename := "syslog_" + time.Now().Format("20060102_150405") + "." + format
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		b, _ := json.Marshal(list)
		_, _ = w.Write(b)
		return
	}
	var sb strings.Builder
	sb.WriteString("ID,时间,主体,主体ID,动作,详情,IP\n")
	for _, row := range list {
		_, _ = fmt.Fprintf(&sb, "%d,%s,%s,%d,%s,%s,%s\n",
			row.ID, csvAuditCell(row.CreatedAt), csvAuditCell(row.Admin), row.AdminID,
			csvAuditCell(row.Action), csvAuditCell(row.Detail), csvAuditCell(row.IP))
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	_, _ = w.Write([]byte("\xEF\xBB\xBF" + sb.String()))
}

// auditDate 严格校验 YYYY-MM-DD；空串表示不过滤
func auditDate(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return "", false
	}
	return t.Format("2006-01-02"), true
}

// csvAuditCell 先防 CSV 公式注入：以 = + - @ Tab CR 开头的值前加单引号，再做标准 CSV 转义。
func csvAuditCell(s string) string {
	if s != "" {
		switch s[0] {
		case '=', '+', '-', '@', '\t', '\r':
			s = "'" + s
		}
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// SyslogStats GET：按 action 聚合近 30 天的系统操作日志计数
func SyslogStats(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT action, COUNT(*) AS n FROM syslog
		WHERE created_at >= datetime('now','localtime','-30 days')
		GROUP BY action ORDER BY n DESC`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var action string
		var n int64
		if rows.Scan(&action, &n) == nil {
			list = append(list, map[string]any{"action": action, "count": n})
		}
	}
	util.OK(w, map[string]any{"list": list, "days": 30})
}
