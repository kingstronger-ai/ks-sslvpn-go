package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/mail"
)

// HistoryEntry 内存中的最近告警记录
type HistoryEntry struct {
	Time    string `json:"time"`
	Rule    string `json:"rule"`
	Key     string `json:"key"`
	Level   string `json:"level"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Result  string `json:"result"` // ok / fail: 发送结果摘要
}

const maxHistory = 50

var (
	histMu  sync.Mutex
	history []HistoryEntry
)

// addHistory 新记录置顶，最多保留 50 条。
func addHistory(e HistoryEntry) {
	if e.Time == "" {
		e.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	histMu.Lock()
	history = append([]HistoryEntry{e}, history...)
	if len(history) > maxHistory {
		history = history[:maxHistory]
	}
	histMu.Unlock()
}

// History 返回最近告警记录的副本
func History() []HistoryEntry {
	histMu.Lock()
	defer histMu.Unlock()
	out := make([]HistoryEntry, len(history))
	copy(out, history)
	return out
}

// SendResult 单渠道发送结果
type SendResult struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// SendTest 向所有已配置渠道发送测试通知（不受 Enabled 限制，用于验证配置）。
func SendTest() ([]SendResult, error) {
	c, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	title := "【KSVPN】告警通道测试"
	message := "这是一条 KSVPN 告警测试通知。若你收到它，说明该推送渠道配置正确。"
	results := sendAll(c.Channels, title, message)
	addHistory(HistoryEntry{Rule: "test", Key: "test", Level: "info", Title: title, Message: message, Result: summarize(results)})
	return results, nil
}

func summarize(results []SendResult) string {
	var ok, fail int
	for _, r := range results {
		if r.OK {
			ok++
		} else {
			fail++
		}
	}
	return fmt.Sprintf("成功 %d / 失败 %d", ok, fail)
}

// sendAll 逐个渠道推送，单个失败不影响其它渠道。
func sendAll(channels []Channel, title, message string) []SendResult {
	results := make([]SendResult, 0, len(channels))
	for _, ch := range channels {
		r := SendResult{Type: ch.Type, Target: ch.Email}
		if r.Target == "" {
			r.Target = MaskURL(ch.URL)
		}
		if err := sendChannel(ch, title, message); err != nil {
			r.Error = err.Error()
		} else {
			r.OK = true
		}
		results = append(results, r)
	}
	return results
}

func sendChannel(ch Channel, title, message string) error {
	typ := strings.ToLower(strings.TrimSpace(ch.Type))
	if typ == "email" {
		return sendEmail(ch.Email, title, message)
	}
	return sendWebhook(typ, ch.URL, title, message)
}

func sendEmail(to, title, body string) error {
	raw := strings.TrimSpace(db.GetSetting("smtp"))
	c := &mail.Config{Port: 465}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), c); err != nil {
			return fmt.Errorf("SMTP 配置解析失败：%w", err)
		}
	}
	html := "<div style='font-family:sans-serif'><h3>" + title + "</h3><p>" + strings.ReplaceAll(body, "\n", "<br>") + "</p></div>"
	return mail.Send(c, to, title, html)
}

func sendWebhook(typ, rawURL, title, message string) error {
	// 二次校验：即便配置已存库，发送前仍拒绝内网地址，防配置被直接改库绕过。
	if err := ValidateWebhookURL(rawURL); err != nil {
		return err
	}
	var payload any
	switch typ {
	case "feishu":
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": title + "\n" + message}}
	case "wecom", "dingtalk":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": title + "\n" + message}}
	default: // webhook：通用格式，兼容常见消费方
		payload = map[string]any{"title": title, "text": title + "\n" + message, "level": "alert"}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 HTTP %d", resp.StatusCode)
	}
	return nil
}
