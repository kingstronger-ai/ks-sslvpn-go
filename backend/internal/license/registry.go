// 浮动许可（不绑定机器）的在线登记：保证"同一个许可只允许一台机器在用"
//
// 客户端：激活时向上报 SSLVPN_LICENSE_REGISTER 指向的登记服务占用一个席位；
// 服务端：`sslvpn license-registry -addr :8790 -secret <密钥> -file registry.json`。
//
// 未配置 SSLVPN_LICENSE_REGISTER 时退化为纯离线（软约束），此时只在本机做记录，
// 无法阻止同一许可串被复制到另一台机器激活。
package license

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
)

// ---------------- 客户端 ----------------

func registryURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("SSLVPN_LICENSE_REGISTER")), "/")
}

func registryEnabled() bool { return registryURL() != "" }

type claimReq struct {
	ID      string `json:"id"`
	Machine string `json:"machine"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Expire  string `json:"expire"`
}

type claimResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Machine string `json:"machine"`
}

// claimSeat 占用授权席位（同一许可编号只允许一台机器）
func claimSeat(p *Payload, machine string) error {
	base := registryURL()
	if base == "" {
		// 纯离线：仅做本机提示，硬约束依赖登记服务
		if lock := db.GetSetting("license_lock_machine"); lock != "" && Normalize(lock) != Normalize(machine) {
			return errors.New("本机此前激活的许可是 " + lock + "，如需更换许可请先点「解除激活」")
		}
		return nil
	}
	if p.ID == "" {
		return errors.New("浮动许可缺少许可编号（id），请用新版 license-gen 重新签发")
	}
	body, _ := json.Marshal(claimReq{
		ID: p.ID, Machine: Group(machine), Email: p.Email, Company: p.Display(), Expire: p.Expire,
	})
	req, err := http.NewRequest("POST", base+"/claim", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s := os.Getenv("SSLVPN_LICENSE_SECRET"); s != "" {
		req.Header.Set("X-License-Secret", s)
	}
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接授权登记服务（%s）：请检查网络或联系授权方", base)
	}
	defer resp.Body.Close()
	var cr claimResp
	_ = json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Code != 1 {
		if cr.Msg != "" {
			return errors.New(cr.Msg)
		}
		return fmt.Errorf("授权登记失败（HTTP %d），请联系授权方", resp.StatusCode)
	}
	return nil
}

// ReleaseSeat 解除激活时通知登记服务释放席位（失败仅记录，不阻塞本地解绑）
func ReleaseSeat() {
	base := registryURL()
	if base == "" {
		return
	}
	tok := db.GetSetting("license_token")
	if tok == "" {
		return
	}
	p, err := Parse(tok)
	if err != nil || !p.Unbound() || p.ID == "" {
		return
	}
	body, _ := json.Marshal(claimReq{ID: p.ID, Machine: Machine()})
	req, err := http.NewRequest("POST", base+"/release", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s := os.Getenv("SSLVPN_LICENSE_SECRET"); s != "" {
		req.Header.Set("X-License-Secret", s)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("释放授权席位失败：%v", err)
		return
	}
	resp.Body.Close()
}

// ---------------- 服务端（授权方自建） ----------------
// Seat 一个许可的占用记录
type Seat struct {
	Machine string `json:"machine"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Expire  string `json:"expire"`
	Time    string `json:"time"`
}

type registry struct {
	mu     sync.Mutex
	file   string
	secret string
	seats  map[string]Seat
}

// RunRegistry 启动登记服务（授权方部署一次即可，供所有客户激活时回调）
func RunRegistry(addr, secret, file string) error {
	r := &registry{file: file, secret: secret, seats: map[string]Seat{}}
	r.load()

	mux := http.NewServeMux()
	mux.HandleFunc("/claim", r.handleClaim)
	mux.HandleFunc("/release", r.handleRelease)
	mux.HandleFunc("/list", r.handleList)

	log.Printf("授权登记服务已启动：%s（记录文件 %s，密钥%s）", addr, file,
		map[bool]string{true: "已启用", false: "未启用"}[secret != ""])
	return http.ListenAndServe(addr, mux)
}

func (r *registry) load() {
	raw, err := os.ReadFile(r.file)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &r.seats)
}

func (r *registry) flush() {
	raw, err := json.MarshalIndent(r.seats, "", "  ")
	if err != nil {
		return
	}
	tmp := r.file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("写入登记文件失败：%v", err)
		return
	}
	if err := os.Rename(tmp, r.file); err != nil {
		log.Printf("替换登记文件失败：%v", err)
	}
}

func (r *registry) auth(w http.ResponseWriter, req *http.Request) bool {
	if r.secret == "" {
		return true
	}
	if req.Header.Get("X-License-Secret") != r.secret {
		writeRegJSON(w, 403, "登记密钥不正确", nil)
		return false
	}
	return true
}

func (r *registry) handleClaim(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeRegJSON(w, 0, "请求方法不允许", nil)
		return
	}
	if !r.auth(w, req) {
		return
	}
	var in claimReq
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil || strings.TrimSpace(in.ID) == "" {
		writeRegJSON(w, 0, "参数不完整", nil)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.seats[in.ID]; ok && Normalize(s.Machine) != Normalize(in.Machine) {
		writeRegJSON(w, 0, "该许可已在机器 "+s.Machine+" 上激活，如需换机请先在原机「解除激活」", nil)
		return
	}
	r.seats[in.ID] = Seat{
		Machine: Group(in.Machine), Email: in.Email, Company: in.Company,
		Expire: in.Expire, Time: time.Now().Format("2006-01-02 15:04:05"),
	}
	r.flush()
	log.Printf("许可 %s 激活于 %s（%s）", in.ID, Group(in.Machine), in.Company)
	writeRegJSON(w, 1, "ok", r.seats[in.ID])
}

func (r *registry) handleRelease(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeRegJSON(w, 0, "请求方法不允许", nil)
		return
	}
	if !r.auth(w, req) {
		return
	}
	var in claimReq
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil || in.ID == "" {
		writeRegJSON(w, 0, "参数不完整", nil)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.seats[in.ID]
	if !ok {
		writeRegJSON(w, 1, "该许可未占用", nil)
		return
	}
	if in.Machine != "" && Normalize(s.Machine) != Normalize(in.Machine) {
		writeRegJSON(w, 0, "只能由已激活的机器解除（当前为 "+s.Machine+"）", nil)
		return
	}
	delete(r.seats, in.ID)
	r.flush()
	log.Printf("许可 %s 已释放（原机器 %s）", in.ID, s.Machine)
	writeRegJSON(w, 1, "已释放", nil)
}

func (r *registry) handleList(w http.ResponseWriter, req *http.Request) {
	if !r.auth(w, req) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	writeRegJSON(w, 1, "ok", r.seats)
}

func writeRegJSON(w http.ResponseWriter, code int, msg string, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if code != 1 {
		w.WriteHeader(http.StatusOK) // 业务错误也用 200 + code=0，客户端只认 code
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": code, "msg": msg, "data": data})
}
