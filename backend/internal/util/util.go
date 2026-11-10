// Package util 通用工具：统一响应、TOTP、随机串
package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// Resp 统一 JSON 响应结构（对齐原 ThinkPHP {code,msg,data} 契约）
type Resp struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

// OK 成功响应
func OK(w http.ResponseWriter, data interface{}) {
	writeJSON(w, Resp{Code: 1, Msg: "ok", Data: data})
}

// OKMsg 成功带消息
func OKMsg(w http.ResponseWriter, msg string, data interface{}) {
	writeJSON(w, Resp{Code: 1, Msg: msg, Data: data})
}

// Fail 失败响应
func Fail(w http.ResponseWriter, msg string) {
	writeJSON(w, Resp{Code: 0, Msg: msg})
}

// FailCode 自定义业务码失败响应（如 402 授权过期，前端据此跳转授权页）
func FailCode(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, Resp{Code: code, Msg: msg})
}

func writeJSON(w http.ResponseWriter, r Resp) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(r)
}

// ReadJSON 解析请求体
func ReadJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

// RandomHex 生成 n 字节随机 hex
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// RandomPassword 生成高强度随机密码（默认 12 位）
// 字符集：大写 + 小写 + 数字，排除易混淆字符 0 O o 1 l I；
// 保证至少各含 1 个大写、1 个小写、1 个数字，最后做安全洗牌。
func RandomPassword(n int) string {
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // 去掉 I、O
	const lower = "abcdefghijkmnopqrstuvwxyz" // 去掉 l、o
	const digit = "23456789"                  // 去掉 0、1
	const all = upper + lower + digit
	if n < 9 {
		n = 12
	}
	pick := func(set string) byte {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return set[0]
		}
		return set[i.Int64()]
	}
	out := make([]byte, 0, n)
	out = append(out, pick(upper), pick(lower), pick(digit))
	for len(out) < n {
		out = append(out, pick(all))
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			break
		}
		k := int(j.Int64())
		out[i], out[k] = out[k], out[i]
	}
	return string(out)
}

// RandomCode 数字验证码
func RandomCode(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		s += fmt.Sprint(n.Int64())
	}
	return s
}

// ---------- TOTP (RFC 6238) ----------

// TOTPSecret 生成 Base32 密钥（20 字节）
func TOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpCode(secretB32 string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyTOTP 校验动态码，允许前后一个窗口
func VerifyTOTP(secret, otp string) bool {
	if len(otp) != 6 {
		return false
	}
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totpCode(secret, now.Add(d))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(c), []byte(otp)) == 1 {
			return true
		}
	}
	return false
}

// OTPAuthURL 生成 otpauth:// 链接供扫码
func OTPAuthURL(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30",
		issuer, account, secret, issuer)
}
