package handler

import (
	"strings"
	"testing"
)

// 路由表里的基路径不能自带 /api 前缀，否则会拼出 /api/v1/api/xxx
func TestRoutesHaveNoAPIEnvPrefix(t *testing.T) {
	for p := range Routes {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("路由 %q 必须以 / 开头", p)
		}
		if strings.HasPrefix(p, "/api/") || p == "/api" {
			t.Errorf("路由 %q 不应包含 /api 前缀（基路径即可，前缀由 APIPrefix 统一加）", p)
		}
	}
}

func TestAPIPathAndBasePath(t *testing.T) {
	cases := []struct{ base, want string }{
		{"/logincheck", "/api/v1/logincheck"},
		{"/ccd/", "/api/v1/ccd/"},
		{"/", "/api/v1/"},
		{"", "/api/v1/"},
		{"/api/v1/logincheck", "/api/v1/logincheck"}, // 已是完整路径时不重复加
	}
	for _, c := range cases {
		if got := APIPath(c.base); got != c.want {
			t.Errorf("APIPath(%q) = %q, want %q", c.base, got, c.want)
		}
	}

	// BasePath 应能把三种前缀还原成同一个基路径
	for _, p := range []string{"/api/v1/logincheck", "/api/logincheck", "/logincheck"} {
		if got := BasePath(p); got != "/logincheck" {
			t.Errorf("BasePath(%q) = %q, want /logincheck", p, got)
		}
	}
	// 非接口路径原样返回
	if got := BasePath("/logo.png"); got != "/logo.png" {
		t.Errorf("BasePath(/logo.png) = %q", got)
	}
	if got := BasePath("/api"); got != "/" {
		t.Errorf("BasePath(/api) = %q, want /", got)
	}
}

// 所有基路径拼上前缀后必须唯一（同一方法+路径不能注册两次）
func TestAPIPathUnique(t *testing.T) {
	seen := map[string]string{}
	for p := range Routes {
		full := APIPath(p)
		if prev, ok := seen[full]; ok {
			t.Errorf("路径冲突：%q 与 %q 都映射到 %q", prev, p, full)
		}
		seen[full] = p
	}
}
