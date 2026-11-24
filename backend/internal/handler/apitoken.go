// API Token 管理接口：仅现有 session 认证可调用（管理接口本身禁止用 API Token，避免自我提权）。
package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"sslvpn/internal/db"
	"sslvpn/internal/license"
	"sslvpn/internal/middleware"
	"sslvpn/internal/util"
)

// apitokenBodyLimit 防止管理员接口被超大 JSON 请求体拖垮内存。
const apitokenBodyLimit = 64 << 10

func readAPITokenJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, apitokenBodyLimit)
	return util.ReadJSON(r, dst)
}

// apiTokenMaxActive 未撤销 token 数量上限（已吊销记录仅留审计，不占额度）
const apiTokenMaxActive = 20

// apiTokenItem 列表项：只暴露元数据，绝不引入 token_hash / 明文
type apiTokenItem struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	Scope      string `json:"scope"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Revoked    int    `json:"revoked"`
}

// rejectIfTokenAuth 管理接口只允许现有 session 认证调用；若请求已被 TokenAuthDispatch
// 识别为 API Token，则直接拒绝，防止 token 创建/吊销 token 实现自我提权。
func rejectIfTokenAuth(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := middleware.TokenInfoFromContext(r.Context()); ok {
		util.FailCode(w, 401, "API Token 不能调用 Token 管理接口")
		return true
	}
	return false
}

// APITokenList GET：列出 token 元数据（不含 token_hash / 明文）
func APITokenList(w http.ResponseWriter, r *http.Request) {
	if rejectIfTokenAuth(w, r) {
		return
	}
	rows, err := db.DB.Query(`SELECT id,name,prefix,scope,created_by,created_at,last_used_at,expires_at,revoked
		FROM api_token ORDER BY id DESC`)
	if err != nil {
		util.Fail(w, "查询失败")
		return
	}
	defer rows.Close()
	list := []apiTokenItem{}
	for rows.Next() {
		var it apiTokenItem
		if rows.Scan(&it.ID, &it.Name, &it.Prefix, &it.Scope, &it.CreatedBy, &it.CreatedAt,
			&it.LastUsedAt, &it.ExpiresAt, &it.Revoked) == nil {
			list = append(list, it)
		}
	}
	util.OK(w, map[string]any{"list": list, "total": len(list)})
}

// APITokenCreate POST：创建 token，明文仅本次响应返回一次，库中只存 sha256
func APITokenCreate(w http.ResponseWriter, r *http.Request) {
	if rejectIfTokenAuth(w, r) {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Scope       string `json:"scope"`
		ExpiresDays int    `json:"expires_days"`
	}
	if err := readAPITokenJSON(w, r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	name := strings.TrimSpace(req.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		util.Fail(w, "名称长度需为 1-64 个字符")
		return
	}
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope != middleware.TokenScopeRead && scope != middleware.TokenScopeWrite {
		util.Fail(w, "scope 必须为 read 或 write")
		return
	}
	// 社区版只读是服务端硬约束：既禁止创建 write Token，也禁止脚本绕过前端创建后
	// 经通用 API 调用写接口（鉴权层另有 EffectiveAPITokenScope 兜底降级）。
	if scope == middleware.TokenScopeWrite && !license.AllowFeature(license.FeatMCPWrite) {
		util.Fail(w, "当前授权档位不支持 write Token（需专业版及以上）；社区版仅可创建 read Token")
		return
	}
	if req.ExpiresDays < 0 || req.ExpiresDays > 365 {
		util.Fail(w, "expires_days 需为 0（永久）或 1-365 天")
		return
	}

	var cnt int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM api_token WHERE revoked=0`).Scan(&cnt); err != nil || cnt >= apiTokenMaxActive {
		util.Fail(w, "最多只能保留 20 个未撤销的 API Token，请先吊销旧 Token")
		return
	}

	plain, hash, prefix, err := middleware.NewAPIToken()
	if err != nil {
		util.Fail(w, "生成 Token 失败")
		return
	}
	now := time.Now().Unix()
	var expiresAt int64
	if req.ExpiresDays > 0 {
		expiresAt = now + int64(req.ExpiresDays)*86400
	}
	createdBy := ""
	if admin, ok := currentAdmin(r); ok {
		createdBy = admin.Username
	}
	res, err := db.DB.Exec(`INSERT INTO api_token(name,token_hash,prefix,scope,created_by,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?)`, name, hash, prefix, scope, createdBy, now, expiresAt)
	if err != nil {
		syslogFromRequest(r, "创建API Token失败", fmt.Sprintf("name=%s err=%v", name, err))
		util.Fail(w, "创建失败")
		return
	}
	id, _ := res.LastInsertId()

	// 明文只回显一次，且禁止缓存/代理留存。
	w.Header().Set("Cache-Control", "no-store")
	msg := "创建成功，明文仅显示一次，请妥善保存"
	if req.ExpiresDays == 0 {
		msg += "（expires_days=0：永久有效，请定期轮换）"
	}
	util.OKMsg(w, msg, map[string]any{
		"id": id, "name": name, "token": plain, "prefix": prefix,
		"scope": scope, "expires_at": expiresAt,
	})

	// 审计只记动作与 name/id，绝不记录明文或 hash。
	syslogFromRequest(r, "创建API Token", fmt.Sprintf("id=%d name=%s scope=%s expires_days=%d",
		id, name, scope, req.ExpiresDays))
}

// APITokenRevoke POST：软吊销（revoked=1，保留审计记录，不物理删除）
func APITokenRevoke(w http.ResponseWriter, r *http.Request) {
	if rejectIfTokenAuth(w, r) {
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := readAPITokenJSON(w, r, &req); err != nil || req.ID <= 0 {
		util.Fail(w, "参数错误")
		return
	}
	var name string
	var revoked int
	if err := db.DB.QueryRow(`SELECT name,revoked FROM api_token WHERE id=?`, req.ID).Scan(&name, &revoked); err != nil {
		util.Fail(w, "Token 不存在")
		return
	}
	if revoked != 0 {
		util.Fail(w, "Token 已吊销")
		return
	}
	if _, err := db.DB.Exec(`UPDATE api_token SET revoked=1 WHERE id=? AND revoked=0`, req.ID); err != nil {
		util.Fail(w, "吊销失败")
		return
	}
	syslogFromRequest(r, "吊销API Token", fmt.Sprintf("id=%d name=%s", req.ID, name))
	util.OKMsg(w, "已吊销", nil)
}

// APITokenTest POST：验证明文 token 当前是否有效（不泄露 token 本身）
func APITokenTest(w http.ResponseWriter, r *http.Request) {
	if rejectIfTokenAuth(w, r) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := readAPITokenJSON(w, r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		util.Fail(w, "参数错误")
		return
	}
	info, ok := middleware.AuthenticateToken(strings.TrimSpace(req.Token))
	msg := "Token 有效"
	if !ok {
		msg = "Token 无效、已过期或已吊销"
	}
	effective := info.Scope
	if ok {
		effective = middleware.EffectiveAPITokenScope(info)
		if effective != info.Scope {
			msg = "Token 有效，但当前授权档位不支持写操作，实际按只读使用（需专业版及以上）"
		}
	}
	util.OK(w, map[string]any{
		"valid": ok, "scope": effective, "name": info.Name, "msg": msg,
	})
}
