//go:build windows

package healthcheck

// DiskUsedPercent Windows 本机开发场景返回 0（表示未知）。
// 生产环境为 Linux 容器，走 disk_unix.go 的 syscall.Statfs 实现。
func DiskUsedPercent(path string) int { return 0 }
