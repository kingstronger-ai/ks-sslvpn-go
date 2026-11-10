package handler

import "testing"

// 备份文件名白名单：只允许纯 .tar.gz 文件名，阻断路径穿越与任意文件读写/删除
func TestSafeBackupName(t *testing.T) {
	allow := []string{
		"backup_20261105_174221.tar.gz",
		"upload_20261105_174221_my-backup.tar.gz",
	}
	for _, n := range allow {
		if !safeBackupName(n) {
			t.Errorf("合法备份文件名被拒绝: %q", n)
		}
	}
	deny := []string{
		"", "backup.tar", "backup.tar.gz.exe", "backup_20261105.tar.gz.bak",
		"../etc/passwd.tar.gz", "..\\windows.tar.gz",
		"/etc/sslvpn.tar.gz", "sub/backup.tar.gz",
		"backup..tar.gz", "backup_../x.tar.gz",
	}
	for _, n := range deny {
		if safeBackupName(n) {
			t.Errorf("危险文件名被放行: %q", n)
		}
	}
}
