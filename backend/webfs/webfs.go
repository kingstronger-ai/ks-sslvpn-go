// Package webfs 内嵌前端静态资源
package webfs

import (
	"embed"
	"io/fs"
)

//go:embed dist
var embedded embed.FS

// Dist 返回 dist 子文件系统
func Dist() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
