// Package version 提供程序版本的唯一来源（同目录 VERSION 文件）与语义版本比较。
// 交付新版本时只需修改 VERSION 文件内容，前端「系统版本」与在线升级检测都会同步。
package version

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed VERSION
var raw string

// Version 当前程序版本号
var Version = strings.TrimSpace(raw)

// Parse 解析 x.y.z（允许 v 前缀、不足三段与预发布后缀）；失败返回 false。
func Parse(s string) ([3]int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "v"))
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Compare 比较 a、b：a 更新返回 1，相同返回 0，更旧返回 -1；无法解析按 0 处理。
func Compare(a, b string) int {
	x, ok1 := Parse(a)
	y, ok2 := Parse(b)
	if !ok1 || !ok2 {
		return 0
	}
	for i := 0; i < 3; i++ {
		if x[i] > y[i] {
			return 1
		}
		if x[i] < y[i] {
			return -1
		}
	}
	return 0
}

// IsNewer latest 是否比 current 更新
func IsNewer(latest, current string) bool { return Compare(latest, current) > 0 }
