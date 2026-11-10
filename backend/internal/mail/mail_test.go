package mail

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// TestSendWithAttachment 起一个假 SMTP 服务，验证带附件邮件的 MIME 结构
func TestSendWithAttachment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		inData := false
		var data strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					got <- data.String()
					w("250 OK")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			up := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
				w("250-fake")
				w("250 AUTH PLAIN LOGIN")
			case strings.HasPrefix(up, "AUTH"):
				w("235 ok")
			case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
				w("250 OK")
			case up == "DATA":
				inData = true
				w("354 go")
			case up == "QUIT":
				w("221 bye")
				return
			default:
				w("250 OK")
			}
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	cfg := &Config{Host: host, Port: p, User: "it@x.com", Pass: "x", Sender: "it@x.com", Title: "KSVPN"}
	body := `<div>您的 VPN 账号已创建成功</div>`
	if err := SendWithAttachment(cfg, "u@x.com", "VPN 账号开通通知", body, "zhangsan_vpn.tgz", []byte("hello-tgz-bytes")); err != nil {
		t.Fatal(err)
	}
	raw := <-got
	checks := []string{
		"multipart/mixed",
		"text/html",
		"name=\"zhangsan_vpn.tgz\"",
		"Content-Disposition: attachment; filename=\"zhangsan_vpn.tgz\"",
		"Content-Transfer-Encoding: base64",
		"aGVsbG8tdGd6LWJ5dGVz", // base64("hello-tgz-bytes")
	}
	for _, c := range checks {
		if !strings.Contains(raw, c) {
			t.Errorf("MIME 缺少 %q\n---\n%s", c, raw)
		}
	}
}
