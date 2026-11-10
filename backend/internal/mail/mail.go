// Package mail SMTP 邮件发送
package mail

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/smtp"
	"strings"
)

// Config SMTP 配置（存于 settings）
type Config struct {
	Host     string `json:"host"` // smtp.example.com
	Port     int    `json:"port"` // 465/587/25
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Title    string `json:"title"`  // 发送者标题（显示名，如"KSVPN"）
	Sender   string `json:"sender"` // 发件人地址（必须是邮箱）
	SSL      bool   `json:"ssl"`    // 465 隐式 TLS
	TestMail string `json:"test_mail"`
}

// Send 发送邮件（兼容 465 隐式 TLS 与 587 STARTTLS）
func Send(c *Config, to, subject, body string) error {
	return SendWithAttachments(c, to, subject, body, nil)
}

// Attachment 邮件附件
type Attachment struct {
	Name string
	Data []byte
}

// SendWithAttachment 发送邮件，filename/content 非空时携带 base64 附件
func SendWithAttachment(c *Config, to, subject, body, filename string, content []byte) error {
	var atts []Attachment
	if filename != "" && len(content) > 0 {
		atts = []Attachment{{Name: filename, Data: content}}
	}
	return SendWithAttachments(c, to, subject, body, atts)
}

// SendWithAttachments 发送邮件，可携带多个 base64 附件
func SendWithAttachments(c *Config, to, subject, body string, atts []Attachment) error {
	if c.Host == "" || c.Port == 0 {
		return fmt.Errorf("SMTP 未配置")
	}
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	from := c.Sender
	if from == "" {
		from = c.User
	}
	// 显示名 + 地址，如 "=?UTF-8?B?...?= <it@x.com>"；信封 MAIL FROM 始终用纯地址
	fromHdr := from
	if c.Title != "" {
		fromHdr = fmt.Sprintf("=?UTF-8?B?%s?= <%s>", b64(c.Title), from)
	}

	var msg strings.Builder
	if len(atts) > 0 {
		// multipart/mixed：正文 + 多个附件
		boundary := "----=_sslvpn_" + randHex(16)
		msg.WriteString("From: " + fromHdr + "\r\n")
		msg.WriteString("To: " + to + "\r\n")
		msg.WriteString("Subject: " + fmt.Sprintf("=?UTF-8?B?%s?=", b64(subject)) + "\r\n")
		msg.WriteString("MIME-Version: 1.0\r\n")
		fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)
		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
		msg.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		msg.WriteString(body)
		msg.WriteString("\r\n\r\n")
		for _, a := range atts {
			fmt.Fprintf(&msg, "--%s\r\n", boundary)
			fmt.Fprintf(&msg, "Content-Type: application/octet-stream; name=\"%s\"\r\n", a.Name)
			msg.WriteString("Content-Transfer-Encoding: base64\r\n")
			fmt.Fprintf(&msg, "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", a.Name)
			msg.WriteString(wrap76(base64.StdEncoding.EncodeToString(a.Data)))
			msg.WriteString("\r\n\r\n")
		}
		fmt.Fprintf(&msg, "--%s--\r\n", boundary)
	} else {
		msg.WriteString("From: " + fromHdr + "\r\n")
		msg.WriteString("To: " + to + "\r\n")
		msg.WriteString("Subject: " + fmt.Sprintf("=?UTF-8?B?%s?=", b64(subject)) + "\r\n")
		msg.WriteString("MIME-Version: 1.0\r\n")
		msg.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n")
		msg.WriteString(body)
	}

	auth := smtp.PlainAuth("", c.User, c.Pass, c.Host)

	if c.SSL { // 隐式 TLS
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: c.Host})
		if err != nil {
			return err
		}
		defer conn.Close()
		cl, err := smtp.NewClient(conn, c.Host)
		if err != nil {
			return err
		}
		defer cl.Quit()
		if err = cl.Auth(auth); err != nil {
			return err
		}
		if err = cl.Mail(from); err != nil {
			return err
		}
		if err = cl.Rcpt(to); err != nil {
			return err
		}
		w, err := cl.Data()
		if err != nil {
			return err
		}
		if _, err = w.Write([]byte(msg.String())); err != nil {
			return err
		}
		return w.Close()
	}

	// 25/587 STARTTLS
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg.String()))
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// randHex 生成 n 字节随机数的 hex 串（用于 MIME boundary）
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// wrap76 按 76 字符换行（base64 附件规范）
func wrap76(s string) string {
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76])
		out.WriteString("\r\n")
		s = s[76:]
	}
	out.WriteString(s)
	return out.String()
}

// UserWelcome 新用户开通通知邮件模板
func UserWelcome(username, password, expire, downloadURL string) string {
	return fmt.Sprintf(`<div style="font-family:sans-serif;max-width:560px">
<h2>VPN 账号开通通知</h2>
<p>您的 VPN 账号已创建成功，信息如下：</p>
<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse">
<tr><td>用户名</td><td><b>%s</b></td></tr>
<tr><td>密码</td><td><b>%s</b></td></tr>
<tr><td>到期时间</td><td>%s</td></tr>
</table>
<p>客户端与配置文件下载：%s</p>
<p style="color:#888">请妥善保管账号信息，勿泄露给他人。</p>
</div>`, username, password, expireOrNever(expire), downloadURL)
}

func expireOrNever(e string) string {
	if e == "" {
		return "永久有效"
	}
	return e
}
