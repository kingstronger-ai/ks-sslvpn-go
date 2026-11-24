package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ---- 参数读取工具 ----

func argString(a map[string]any, key string) string {
	v, ok := a[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func argInt64(a map[string]any, key string) int64 {
	v, ok := a[key]
	if !ok || v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int64(x)
	case json.Number:
		i, _ := x.Int64()
		return i
	case int:
		return int64(x)
	case int64:
		return x
	case string:
		i, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return i
	default:
		return 0
	}
}

func argBool(a map[string]any, key string) bool {
	v, ok := a[key]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "yes"
	case float64:
		return x != 0
	default:
		return false
	}
}

func dataMap(obj map[string]any) map[string]any {
	if d, ok := obj["data"].(map[string]any); ok {
		return d
	}
	return obj
}

func listFrom(obj map[string]any) []any {
	d := dataMap(obj)
	if d == nil {
		return nil
	}
	if l, ok := d["list"].([]any); ok {
		return l
	}
	return nil
}

func fmtVal(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		if x == "" {
			return "-"
		}
		return x
	case bool:
		return strconv.FormatBool(x)
	case map[string]any, []any:
		return prettyJSON(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func getRun(path string) toolRun {
	return func(ctx context.Context, c *APIClient, _ map[string]any) (string, bool) {
		res, err := c.do(ctx, http.MethodGet, path, nil, false)
		if err != nil {
			return "请求 KSVPN API 失败：" + c.safeErr(err), true
		}
		return c.resultText(res)
	}
}

func postRun(path string, body map[string]any) toolRun {
	return func(ctx context.Context, c *APIClient, _ map[string]any) (string, bool) {
		res, err := c.do(ctx, http.MethodPost, path, body, false)
		if err != nil {
			return "请求 KSVPN API 失败：" + c.safeErr(err), true
		}
		return c.resultText(res)
	}
}

// ---- A. 状态与可观测 ----

func statusRun(ctx context.Context, c *APIClient, _ map[string]any) (string, bool) {
	versionRes, err := c.do(ctx, http.MethodGet, "/upgrade/version", nil, false)
	if err != nil {
		return "查询版本失败：" + c.safeErr(err), true
	}
	healthRes, healthErr := c.do(ctx, http.MethodGet, "/health", nil, false)

	var lines []string
	lines = append(lines, "KSVPN 状态摘要")
	if versionObj, ok := versionRes.object(); ok {
		v := dataMap(versionObj)
		lines = append(lines, "- 版本: "+fmtVal(v["version"]))
		lines = append(lines, "- 升级代理: "+fmtVal(v["agent_online"]))
	} else {
		text, isErr := c.resultText(versionRes)
		if isErr {
			return text, true
		}
		lines = append(lines, "- 版本响应: "+text)
	}
	if healthErr != nil {
		lines = append(lines, "- 健康探针: 请求失败（"+c.safeErr(healthErr)+"）")
	} else if healthObj, ok := healthRes.object(); ok {
		h := dataMap(healthObj)
		lines = append(lines, "- 运行状态: "+fmtVal(h["status"]))
		lines = append(lines, "- 运行时间: "+fmtVal(h["uptime"]))
		lines = append(lines, "- 实例数: "+fmtVal(h["instances"]))
		lines = append(lines, "- 在线用户: "+fmtVal(h["online"]))
		lines = append(lines, "- 磁盘使用率: "+fmtVal(h["disk_percent"])+"%")
		if days, ok := h["cert_days"].(map[string]any); ok {
			parts := make([]string, 0, len(days))
			for k, v := range days {
				parts = append(parts, k+"="+fmtVal(v)+"天")
			}
			lines = append(lines, "- 证书剩余: "+strings.Join(parts, ", "))
		}
	} else {
		lines = append(lines, "- 健康探针: 返回非 JSON（"+c.sanitizeText(strings.TrimSpace(string(healthRes.Body)))+"）")
	}
	return strings.Join(lines, "\n"), false
}

func healthRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	// 修复独立版隐患：/health 实际注册在裸路径，先 bare=true 请求；失败再回退 /api/v1/health。
	res, err := c.do(ctx, http.MethodGet, "/health", nil, true)
	if err != nil || res.StatusCode >= 400 {
		fallback, fbErr := c.do(ctx, http.MethodGet, "/health", nil, false)
		if fbErr != nil {
			return "请求 KSVPN API 失败：" + c.safeErr(err) + "；回退失败：" + c.safeErr(fbErr), true
		}
		res = fallback
	}
	if !argBool(args, "detail") {
		if obj, ok := res.object(); ok {
			delete(obj, "checks")
			return truncateText(prettyJSON(redactValue(obj)), 64<<10), false
		}
	}
	return c.resultText(res)
}

func metricsRun(ctx context.Context, c *APIClient, _ map[string]any) (string, bool) {
	// /metrics 为裸路径，不在 /api/v1 前缀下。
	res, err := c.do(ctx, http.MethodGet, "/metrics", nil, true)
	if err != nil || res.StatusCode >= 400 {
		fallback, fbErr := c.do(ctx, http.MethodGet, "/metrics", nil, false)
		if fbErr != nil {
			return "抓取 /metrics 失败：" + c.safeErr(err) + "；回退失败：" + c.safeErr(fbErr), true
		}
		res = fallback
	}
	return truncateText(c.sanitizeText(strings.TrimSpace(string(res.Body))), 64<<10), false
}

// ---- B. 用户与会话 ----

func listAccountsRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	q := url.Values{}
	if p := argInt64(args, "page"); p > 0 {
		q.Set("page", strconv.FormatInt(p, 10))
	}
	if l := argInt64(args, "limit"); l > 0 {
		q.Set("limit", strconv.FormatInt(l, 10))
	}
	if kw := argString(args, "keyword"); kw != "" {
		q.Set("keyword", kw)
	}
	path := "/account/userlist"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return getRun(path)(ctx, c, args)
}

func accountDetailRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	id := argInt64(args, "id")
	if id == 0 {
		username := argString(args, "username")
		if username == "" {
			return "请提供 id 或 username 之一。", true
		}
		res, err := c.do(ctx, http.MethodGet, "/account/userlist?keyword="+url.QueryEscape(username), nil, false)
		if err != nil {
			return "解析用户名失败：" + c.safeErr(err), true
		}
		obj, ok := res.object()
		if !ok {
			return "解析用户名失败：userlist 返回非 JSON。", true
		}
		for _, item := range listFrom(obj) {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if strings.EqualFold(argString(m, "username"), username) {
				id = argInt64(m, "id")
				break
			}
		}
		if id == 0 {
			return "未找到用户名 " + username + "，请检查后重试（也可用 id 直接查询）。", true
		}
	}
	res, err := c.do(ctx, http.MethodPost, "/account/showDetail", map[string]any{"id": id}, false)
	if err != nil {
		return "请求 KSVPN API 失败：" + c.safeErr(err), true
	}
	return c.resultText(res)
}

func auditLogRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	format := argString(args, "format")
	if format == "" {
		format = "json"
	}
	body := map[string]any{
		"format": format,
		"start":  argString(args, "start"),
		"end":    argString(args, "end"),
		"action": argString(args, "action"),
	}
	res, err := c.do(ctx, http.MethodPost, "/syslog/export", body, false)
	fallback := func(note string) (string, bool) {
		text, isErr := getRun("/syslog/list")(ctx, c, args)
		return note + "\n" + text, isErr
	}
	if err != nil || res.StatusCode >= 400 || res.StatusCode == 0 {
		return fallback("/syslog/export 请求失败，已回退 /syslog/list：" + c.safeErr(err))
	}
	if _, ok := res.object(); !ok {
		return fallback("导出接口返回非 JSON（可能是下载文件流），已回退 /syslog/list。")
	}
	text, isErr := c.resultText(res)
	if isErr {
		return fallback("导出接口返回失败，已回退 /syslog/list。")
	}
	return text, false
}

func revokeSessionRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	jti := argString(args, "jti")
	if jti == "" {
		return "缺少 jti 参数。请先调用 ksvpn_admin_sessions 获取会话 jti。", true
	}
	return postRun("/admin/session/revoke", map[string]any{"jti": jti})(ctx, c, args)
}

func kickUserRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	// 批量踢下线一次最多 500 人，与 stop_all_vpn / upgrade_apply 同级高危，必须先二次确认。
	if argBool(args, "all") && argString(args, "confirm") != "KICK_ALL" {
		return "高危操作已阻止：批量踢下线必须显式传 confirm:\"KICK_ALL\"；本次未发起任何请求。单用户下线无需确认。", true
	}
	items := make([]map[string]string, 0, 1)
	if argBool(args, "all") {
		res, err := c.do(ctx, http.MethodGet, "/log/status", nil, false)
		if err != nil {
			return "读取在线用户失败：" + c.safeErr(err), true
		}
		obj, ok := res.object()
		if !ok {
			return "读取在线用户失败：/log/status 返回非 JSON。", true
		}
		skipped := 0
		for _, item := range listFrom(obj) {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			u, svc := argString(m, "username"), argString(m, "service")
			if u == "" || svc == "" {
				skipped++
				continue
			}
			if len(items) >= 500 {
				skipped++
				continue
			}
			items = append(items, map[string]string{"username": u, "service": svc})
		}
		if len(items) == 0 {
			return "没有可下线的在线用户（已跳过 " + strconv.Itoa(skipped) + " 条无效记录）。", true
		}
	} else {
		username, service, cid := argString(args, "username"), argString(args, "service"), argString(args, "cid")
		if username == "" && cid == "" {
			return "请提供 username 或 cid；如需全部下线请传 all:true（高风险）。", true
		}
		if (username == "" || service == "") && (cid != "" || username != "") {
			res, err := c.do(ctx, http.MethodGet, "/log/status", nil, false)
			if err != nil {
				return "解析目标失败：" + c.safeErr(err), true
			}
			obj, ok := res.object()
			if !ok {
				return "解析目标失败：/log/status 返回非 JSON。", true
			}
			matches := 0
			for _, item := range listFrom(obj) {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				u, svc := argString(m, "username"), argString(m, "service")
				hit := false
				if cid != "" && username == "" {
					hit = u == cid || argString(m, "virtual_ip") == cid ||
						argString(m, "real_ip") == cid || strings.HasPrefix(argString(m, "real_ip"), cid+":")
				} else {
					hit = strings.EqualFold(u, username)
					if service != "" {
						hit = hit && svc == service
					}
				}
				if hit {
					if username == "" {
						username = u
					}
					if service == "" {
						service = svc
					}
					items = append(items, map[string]string{"username": username, "service": service})
					matches++
				}
			}
			if matches == 0 {
				return "未在在线列表中找到目标（username=" + username + ", cid=" + cid + "）。可尝试先调用 ksvpn_online_users 确认用户名与实例名。", true
			}
		}
	}
	if len(items) == 0 {
		items = append(items, map[string]string{"username": argString(args, "username"), "service": argString(args, "service")})
	}
	res, err := c.do(ctx, http.MethodPost, "/log/kick", map[string]any{"items": items}, false)
	if err != nil {
		return "请求 KSVPN API 失败：" + c.safeErr(err), true
	}
	return c.resultText(res)
}

func stopAllRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	if argString(args, "confirm") != "I_KNOW" {
		return "高危操作已阻止：必须显式传 confirm:\"I_KNOW\" 才会停止全部 VPN 服务；本次未发起任何请求。", true
	}
	return postRun("/account/disableVpnServer", map[string]any{})(ctx, c, args)
}

// ---- C. 实例与配置 ----

func serviceActionRun(path string) toolRun {
	return func(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
		// 停服务会让该实例上的全部在线客户端断开，与 stop_all_vpn 同级需二次确认；
		// 启动服务无需确认。
		if path == "/service/stop" && argString(args, "confirm") != "STOP" {
			return "高危操作已阻止：停止服务实例必须显式传 confirm:\"STOP\"；本次未发起任何请求。", true
		}
		id, name := argInt64(args, "id"), argString(args, "name")
		if id == 0 && name == "" {
			return "请提供 id 或 name 之一以定位实例。", true
		}
		body := map[string]any{}
		if id > 0 {
			body["id"] = id
		}
		if name != "" {
			body["name"] = name
		}
		return postRun(path, body)(ctx, c, args)
	}
}

func ccdRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	path := "/ccd/"
	if sid := argInt64(args, "service_id"); sid > 0 {
		path += "?service_id=" + strconv.FormatInt(sid, 10)
	}
	return getRun(path)(ctx, c, args)
}

func portRulesRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	res, err := c.do(ctx, http.MethodGet, "/fw/getPortRuleList", nil, false)
	useFallback := err != nil || res.StatusCode >= 400
	if !useFallback {
		if code, ok := res.code(); ok && code != 1 {
			useFallback = true
		}
	}
	if useFallback {
		text, isErr := getRun("/system/getOtherInfo")(ctx, c, args)
		return "当前 API 的 /fw/getPortRuleList 不可用，已返回系统信息供参考。专用列表接口为 GET /fw/getPortRuleList（写操作在 /fw/addPortRule 与 /system/delPortRule）。\n" + text, isErr
	}
	return c.resultText(res)
}

// ---- D. 运维与升级 ----

func upgradeApplyRun(ctx context.Context, c *APIClient, args map[string]any) (string, bool) {
	if argString(args, "confirm") != "UPGRADE" {
		return "高危操作已阻止：必须显式传 confirm:\"UPGRADE\" 才会提交升级；本次未发起任何请求。", true
	}
	// 后端 /upgrade/apply 使用布尔 confirm；MCP 层的 UPGRADE 字符串是额外的人机确认闸门。
	return postRun("/upgrade/apply", map[string]any{"confirm": true})(ctx, c, args)
}
