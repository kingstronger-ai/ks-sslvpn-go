// LDAP 账号状态对比与单向禁用（预览 → 确认两步）
package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
)

// ldapDisableItem 展示用的待禁用账号：使用人/邮箱优先取 LDAP 目录里的值（停用账号仍在目录中）。
// ldapDisableItem 展示用的待禁用账号：使用人/邮箱优先取 LDAP 目录里的值（停用账号仍在目录中）。
type ldapDisableItem struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Action      string `json:"action"`
}

type ldapStatusSnapshot struct {
	ActiveHash string   `json:"-"`
	Usernames  []string `json:"-"`
	Active     int      `json:"-"`
	VPNAdmin   int      `json:"-"`
	Created    time.Time
}

var (
	ldapSnapMu    sync.Mutex
	ldapSnapshots = map[string]*ldapStatusSnapshot{}
)

func randomSnapToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ldapActiveSet 返回 LDAP 有效账号集合（小写用户名）与有效数量。
func ldapActiveSet(users []LdapUser) map[string]bool {
	set := make(map[string]bool, len(users))
	for _, u := range users {
		if !u.Disabled {
			set[strings.ToLower(u.Username)] = true
		}
	}
	return set
}

// hashActiveSet 对有效用户名集合做稳定哈希，用于确认阶段校验 LDAP 预览后未变化。
func hashActiveSet(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return hex.EncodeToString(h[:])
}

// ldapStatusDiff 计算待禁用清单（本地 auth_type='ldap' 且启用，但不在 LDAP 有效集合中）。
func ldapStatusDiff(active map[string]bool, ldapUsers []LdapUser) ([]ldapDisableItem, int, error) {
	// 从 LDAP 明细建索引（含停用条目），用于展示使用人 / 邮箱
	detail := map[string]LdapUser{}
	for _, u := range ldapUsers {
		detail[strings.ToLower(u.Username)] = u
	}
	rows, err := db.DB.Query(`SELECT id,username,COALESCE(note,'') FROM account WHERE auth_type='ldap' AND status=1`)
	if err != nil {
		return nil, 0, err
	}
	type localItem struct {
		id       int64
		username string
		note     string
	}
	var locals []localItem
	for rows.Next() {
		var x localItem
		if rows.Scan(&x.id, &x.username, &x.note) == nil {
			locals = append(locals, x)
		}
	}
	_ = rows.Close()
	// 熔断：OU 配错导致 LDAP 用户骤减时，禁止一次性批量禁用。
	if len(locals) >= 5 {
		willDisable := 0
		for _, a := range locals {
			if !active[strings.ToLower(a.username)] {
				willDisable++
			}
		}
		if float64(willDisable)/float64(len(locals)) > 0.4 {
			return nil, len(locals), fmt.Errorf("LDAP 有效用户数异常（本地启用 LDAP 账号 %d，本次将禁用 %d，占 %.0f%%），疑似 OU/连接配置错误，已停止以防批量误禁用",
				len(locals), willDisable, float64(willDisable)/float64(len(locals))*100)
		}
	}
	out := make([]ldapDisableItem, 0)
	for _, a := range locals {
		if active[strings.ToLower(a.username)] {
			continue
		}
		it := ldapDisableItem{ID: a.id, Username: a.username, DisplayName: a.note, Action: "禁用"}
		if u, ok := detail[strings.ToLower(a.username)]; ok {
			if u.DisplayName != "" {
				it.DisplayName = u.DisplayName
			}
			it.Email = u.Email
		}
		out = append(out, it)
	}
	return out, len(locals), nil
}

// LdapStatusCheck GET /ldap/statusCheck
// 只做差异预览，不修改任何账号；返回统计与待禁用清单 + 一次性快照 token。
func LdapStatusCheck(w http.ResponseWriter, r *http.Request) {
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, "连接 LDAP 失败: "+err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsersDetail()
	if err != nil {
		util.Fail(w, "查询 LDAP 用户失败: "+err.Error())
		return
	}
	if len(users) == 0 {
		util.Fail(w, "LDAP 未返回任何用户，已停止（结果不完整，防止误禁用）")
		return
	}
	active := ldapActiveSet(users)
	if len(active) == 0 {
		util.Fail(w, "LDAP 返回的用户全部为停用状态，已停止（结果异常，防止误禁用）")
		return
	}
	items, vpnCount, err := ldapStatusDiff(active, users)
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	token := randomSnapToken()
	ldapSnapMu.Lock()
	ldapSnapshots[token] = &ldapStatusSnapshot{
		ActiveHash: hashActiveSet(active), Active: len(active), VPNAdmin: vpnCount, Created: time.Now(),
	}
	for k, s := range ldapSnapshots {
		if time.Since(s.Created) > 15*time.Minute {
			delete(ldapSnapshots, k)
		}
	}
	ldapSnapMu.Unlock()
	util.OK(w, map[string]any{
		"token": token, "ldap_active": len(active), "vpn_ldap": vpnCount, "to_disable": len(items), "items": items,
	})
}

// LdapStatusApply POST /ldap/statusApply
// 按快照确认禁用：重新查询 LDAP，校验有效集合哈希与预览一致、名单未变，再单向禁用（不启用任何账号）。
func LdapStatusApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := util.ReadJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		util.Fail(w, "参数错误：缺少预览快照 token，请重新检查同步状态")
		return
	}
	ldapSnapMu.Lock()
	snap, ok := ldapSnapshots[req.Token]
	ldapSnapMu.Unlock()
	if !ok || time.Since(snap.Created) > 15*time.Minute {
		util.Fail(w, "预览已过期或不存在，请重新检查同步状态")
		return
	}
	c, err := ldapConnect()
	if err != nil {
		util.Fail(w, "连接 LDAP 失败: "+err.Error())
		return
	}
	defer c.Close()
	users, err := c.ListUsersDetail()
	if err != nil {
		util.Fail(w, "查询 LDAP 用户失败: "+err.Error())
		return
	}
	active := ldapActiveSet(users)
	if len(active) == 0 || hashActiveSet(active) != snap.ActiveHash {
		util.Fail(w, "LDAP 用户列表在预览后发生变化，已停止执行，请重新检查同步状态")
		return
	}
	items, _, err := ldapStatusDiff(active, users)
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	if len(items) == 0 {
		util.Fail(w, "待禁用名单已为空（可能已在别处处理），未执行任何变更")
		return
	}
	disabled := 0
	for _, it := range items {
		res, e := db.DB.Exec(`UPDATE account SET status=0 WHERE id=? AND auth_type='ldap' AND status=1`, it.ID)
		if e == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				disabled++
			}
		}
	}
	ldapSnapMu.Lock()
	delete(ldapSnapshots, req.Token)
	ldapSnapMu.Unlock()
	syncAuthFiles()
	syslogFromRequest(r, "LDAP 状态同步确认禁用", fmt.Sprintf("待禁用=%d 实际禁用=%d", len(items), disabled))
	util.OK(w, map[string]any{"disabled": disabled, "total": len(items)})
}
