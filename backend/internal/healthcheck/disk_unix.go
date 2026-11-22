//go:build !windows

package healthcheck

import "syscall"

// DiskUsedPercent 用 syscall.Statfs 返回路径所在文件系统的使用百分比（0-100）。
// 取不到时返回 0，调用方按「未知」处理。
func DiskUsedPercent(path string) int {
	if path == "" {
		path = "."
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	if st.Blocks == 0 {
		return 0
	}
	used := st.Blocks - st.Bavail
	return int(used * 100 / st.Blocks)
}
