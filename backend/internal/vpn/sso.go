package vpn

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"sslvpn/internal/util"
)

// FeishuTokenPrefix 飞书一次性口令前缀（口令整体作为 OpenVPN 的「密码」字段提交）
const FeishuTokenPrefix = "FS1."

// TokenDigest 口令摘要（库里只存摘要，明文仅在签发那一刻返回给客户端）
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SafeEqual 定长比较，避免时序侧信道（长度不同直接失败）
func SafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConsumeFeishuToken 校验并核销一次性口令。
// 返回 (通过?, 拒绝原因)。核销用带条件的 UPDATE 保证原子性：
// 并发或重放时只有第一个请求能命中 RowsAffected==1。
func ConsumeFeishuToken(d *sql.DB, username, token string) (bool, string) {
	if !strings.HasPrefix(token, FeishuTokenPrefix) || len(token) < 16 {
		return false, "一次性口令格式错误"
	}
	hash := TokenDigest(token)
	now := time.Now().Unix()

	var owner string
	var consumed int
	var expires int64
	err := d.QueryRow(`SELECT username, consumed, expires_at FROM sso_token WHERE token_hash=?`, hash).
		Scan(&owner, &consumed, &expires)
	if err == sql.ErrNoRows {
		return false, "一次性口令无效"
	}
	if err != nil {
		return false, "一次性口令校验失败"
	}
	if consumed == 1 {
		return false, "一次性口令已被使用"
	}
	if expires <= now {
		return false, "一次性口令已过期"
	}
	if owner != username {
		return false, "一次性口令与账号不匹配"
	}
	res, err := d.Exec(`UPDATE sso_token SET consumed=1 WHERE token_hash=? AND consumed=0 AND expires_at>?`, hash, now)
	if err != nil {
		return false, "一次性口令校验失败"
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, "一次性口令已被使用"
	}
	return true, ""
}

// AppendAccessLog 追加一条认证审计日志（与管理页「认证日志」读的是同一份文件）
func AppendAccessLog(typ, msg, ip string) {
	appendAccessLog(map[string]any{
		"date": time.Now().Format("2006-01-02 15:04:05"),
		"type": typ, "msg": msg, "ip": ip, "id": util.RandomHex(8),
	})
}

// PurgeExpiredSSO 清理过期的设备授权请求与口令（保留 1 天便于排查日志）
func PurgeExpiredSSO(d *sql.DB) int64 {
	cut := time.Now().Add(-24 * time.Hour).Unix()
	var total int64
	if res, err := d.Exec(`DELETE FROM sso_device WHERE expires_at < ?`, cut); err == nil {
		n, _ := res.RowsAffected()
		total += n
	}
	if res, err := d.Exec(`DELETE FROM sso_token WHERE expires_at < ?`, cut); err == nil {
		n, _ := res.RowsAffected()
		total += n
	}
	return total
}
