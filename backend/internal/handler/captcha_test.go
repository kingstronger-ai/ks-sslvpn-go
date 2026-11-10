package handler

import (
	"testing"
	"time"
)

func TestCheckCaptcha(t *testing.T) {
	captchaStore.Lock()
	captchaStore.m["t1"] = "10"
	captchaStore.expired["t1"] = time.Now().Add(5 * time.Minute)
	captchaStore.Unlock()

	if checkCaptcha("t1", "") || checkCaptcha("", "10") || checkCaptcha("", "") {
		t.Error("验证码留空不应放行")
	}
	if !checkCaptcha("t1", "10") {
		t.Error("正确答案应通过")
	}
	if checkCaptcha("t1", "10") || checkCaptcha("t1", " 10 ") {
		t.Error("验证码应一次性消费（答错或重复使用均无效）")
	}
	if checkCaptcha("noexist", "10") {
		t.Error("不存在的 code_id 不应通过")
	}
}
