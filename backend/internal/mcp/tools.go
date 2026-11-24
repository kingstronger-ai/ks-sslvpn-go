package mcp

import (
	"context"
)

type toolRun func(ctx context.Context, c *APIClient, args map[string]any) (string, bool)

// Tool 是 MCP tools/list 条目；Write/Run 不参与 JSON 输出。
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
	Write       bool        `json:"-"`
	Run         toolRun     `json:"-"`
}

type inputSchema struct {
	Type                 string         `json:"type"`
	Properties           map[string]any `json:"properties"`
	Required             []string       `json:"required,omitempty"`
	AdditionalProperties bool           `json:"additionalProperties"`
}

func str(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func enum(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func newTool(name, desc string, write bool, props map[string]any, required []string, run toolRun) Tool {
	return Tool{
		Name:        "ksvpn_" + name,
		Description: desc,
		InputSchema: inputSchema{Type: "object", Properties: props, Required: required, AdditionalProperties: false},
		Write:       write,
		Run:         run,
	}
}

// BuildTools 返回全部 27 个工具（业务逻辑与独立版一致，未改动）。
func BuildTools() []Tool {
	return []Tool{
		// ---------- A. 状态与可观测（read） ----------
		newTool("status", "只读：合并 /upgrade/version 与 /health，返回版本、运行状态、实例数、在线数、证书剩余天数与磁盘使用率的一页摘要。", false,
			map[string]any{}, nil, statusRun),
		newTool("health", "只读：查询 KSVPN 健康探针 /health。detail=true 时包含全部检查项，默认只返回摘要。", false,
			map[string]any{"detail": boolean("是否返回完整检查项（默认 false，仅摘要）")}, nil, healthRun),
		newTool("instances", "只读：列出 VPN 服务实例及其运行状态（GET /service/list）。", false,
			map[string]any{}, nil, getRun("/service/list")),
		newTool("online_users", "只读：列出当前在线 VPN 用户与会话信息（GET /log/status）。", false,
			map[string]any{}, nil, getRun("/log/status")),
		newTool("metrics", "只读：抓取 Prometheus 裸路径 /metrics 文本指标；失败时回退到 /api/v1/metrics。输出最大 64KB。", false,
			map[string]any{}, nil, metricsRun),
		newTool("alert_history", "只读：返回最近 50 条告警历史（GET /alert/history）。", false,
			map[string]any{}, nil, getRun("/alert/history")),
		newTool("alert_config", "只读：返回告警配置（GET /alert/config，后端已对 URL 等敏感项打码）。", false,
			map[string]any{}, nil, getRun("/alert/config")),

		// ---------- B. 用户与会话管理 ----------
		newTool("list_accounts", "只读：查询 VPN 账号列表。后端按 keyword 模糊匹配用户名；page/limit 为兼容参数，当前后端会返回全量匹配结果。", false,
			map[string]any{
				"page":    integer("页码，从 1 开始（兼容参数）"),
				"limit":   integer("每页条数（兼容参数）"),
				"keyword": str("用户名关键字，模糊匹配；留空返回全部"),
			}, nil, listAccountsRun),
		newTool("account_detail", "只读：按用户名或数字 id 查询账号详情。注意：后端 showDetail 仅接受 id，传 username 时本工具会先查 userlist 解析。返回中的口令/TOTP 密钥已脱敏。", false,
			map[string]any{
				"username": str("用户名（与 id 二选一；优先使用 id）"),
				"id":       integer("账号数字 id（与 username 二选一）"),
			}, nil, accountDetailRun),
		newTool("admin_sessions", "只读：列出全部管理员会话（含吊销状态、IP/UA），可用于定位待吊销的 jti。", false,
			map[string]any{}, nil, getRun("/admin/sessions")),
		newTool("audit_log", "只读：导出审计日志。优先 POST /syslog/export 请求 JSON 文件；若后端返回非 JSON（如 CSV/下载流）则自动回退 GET /syslog/list。", false,
			map[string]any{
				"format": str("导出格式，固定建议 json（后端支持 json/csv）"),
				"start":  str("开始时间，如 2026-11-01 或 2026-11-01 00:00:00"),
				"end":    str("结束时间，如 2026-11-22 或 2026-11-22 23:59:59"),
				"action": str("按操作类型过滤，留空表示不过滤"),
			}, nil, auditLogRun),
		newTool("login_stats", "只读：登录统计（GET /syslog/stats，近 30 天按 action 聚合）。", false,
			map[string]any{}, nil, getRun("/syslog/stats")),
		newTool("kick_user", "写操作（需 write Token 且专业版及以上）：强制在线用户下线。传 username（可带 service），或传 cid（按虚拟 IP/真实 IP/用户名从在线列表解析）；all=true 为批量踢下线（上限 500 人，高风险），必须同时传 confirm:\"KICK_ALL\"。", true,
			map[string]any{
				"username": str("要下线的用户名（证书 CN），与 cid/all 二选一"),
				"service":  str("所属实例名；按 username 踢下线时建议提供，跨实例时必填"),
				"cid":      str("客户端标识：虚拟 IP、真实 IP 或用户名；用于从在线列表解析目标"),
				"all":      boolean("踢下线全部在线用户（高风险；单次最多 500 人，需同时传 confirm:\"KICK_ALL\"）"),
				"confirm":  enum("仅 all=true 时需要，必须精确填写 KICK_ALL", "KICK_ALL"),
			}, nil, kickUserRun),
		newTool("stop_all_vpn", "【高风险·写操作】停止全部 VPN 服务实例，所有在线客户端将断开且不会自动重连。必须显式传 confirm:\"I_KNOW\" 才会执行（需 write Token 且专业版及以上）。", true,
			map[string]any{
				"confirm": enum("二次确认口令，必须精确填写 I_KNOW", "I_KNOW"),
			}, []string{"confirm"}, stopAllRun),
		newTool("revoke_session", "写操作（需 write Token 且专业版及以上）：按 jti 吊销指定管理员会话；普通管理员只能吊销自己的会话。可先用 ksvpn_admin_sessions 查 jti。注意：API Token 没有管理员会话身份，调用本工具会返回不支持提示，请改用管理页操作。", true,
			map[string]any{"jti": str("管理员会话 JWT ID（jti）")}, []string{"jti"}, revokeSessionRun),

		// ---------- C. 实例与配置 ----------
		newTool("service_list", "只读：列出 VPN 服务实例（GET /service/list），与 ksvpn_instances 相同的数据源。", false,
			map[string]any{}, nil, getRun("/service/list")),
		newTool("service_start", "写操作（需 write Token 且专业版及以上）：启动指定 VPN 服务实例。后端接受 id 或 name；建议至少传 id。", true,
			map[string]any{
				"id":   integer("实例数字 id（与 name 二选一）"),
				"name": str("实例名称（与 id 二选一；id 优先）"),
			}, nil, serviceActionRun("/service/start")),
		newTool("service_stop", "【写操作·需二次确认】停止指定 VPN 服务实例，会影响该实例上的所有在线客户端。需 write Token 且专业版及以上，并显式传 confirm:\"STOP\"。", true,
			map[string]any{
				"id":      integer("实例数字 id（与 name 二选一）"),
				"name":    str("实例名称（与 id 二选一；id 优先）"),
				"confirm": enum("二次确认口令，必须精确填写 STOP", "STOP"),
			}, []string{"confirm"}, serviceActionRun("/service/stop")),
		newTool("group_list", "只读：列出用户分组及每组用户数/关联实例数（GET /group/list）。", false,
			map[string]any{}, nil, getRun("/group/list")),
		newTool("ccd_list", "只读：列出 CCD 逐用户配置（GET /ccd/，专业版功能）。未授权时后端返回 403，本工具会给出可读提示而不是原始错误。", false,
			map[string]any{"service_id": integer("可选：按实例 id 过滤；0 或留空表示全部")}, nil, ccdRun),
		newTool("port_rules", "只读：查询端口规则列表。后端存在专用接口 GET /fw/getPortRuleList；若不可用则回退 GET /system/getOtherInfo 并提示可用接口。", false,
			map[string]any{}, nil, portRulesRun),

		// ---------- D. 运维与升级 ----------
		newTool("upgrade_status", "只读：查询升级流程状态、进度、备份与代理心跳（GET /upgrade/status）。", false,
			map[string]any{}, nil, getRun("/upgrade/status")),
		newTool("upgrade_check", "只读：检查是否有新版本（GET /upgrade/check），仅检测不触发升级。", false,
			map[string]any{}, nil, getRun("/upgrade/check")),
		newTool("upgrade_apply", "【高风险·写操作】执行在线升级，将触发宿主机代理替换程序并可能重启服务。必须显式传 confirm:\"UPGRADE\"（需 write Token 且专业版及以上）。", true,
			map[string]any{"confirm": enum("二次确认口令，必须精确填写 UPGRADE", "UPGRADE")}, []string{"confirm"}, upgradeApplyRun),
		newTool("backups", "只读：列出升级前自动备份（GET /upgrade/backups）。", false,
			map[string]any{}, nil, getRun("/upgrade/backups")),
		newTool("certificates", "只读：列出 PKI 已签发证书（GET /system/getCertList）。", false,
			map[string]any{}, nil, getRun("/system/getCertList")),
		newTool("license_info", "只读：查询授权档位、机器码与用户数占用（GET /license/info）。", false,
			map[string]any{}, nil, getRun("/license/info")),
	}
}

// FindTool 按完整工具名（含 ksvpn_ 前缀）查找。
func FindTool(name string) (Tool, bool) {
	for _, t := range BuildTools() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}
