package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readLicenseSeq 读取签发机上的许可序号；文件不存在或内容非法时视为 0（下一张从 1 开始）。
func readLicenseSeq(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// nextLicenseID 返回本次应使用的许可编号。
// 签发端是离线 CLI，无法依赖客户数据库，故用签发机上的序号文件保证编号连续、从 1 开始。
// 显式指定 -id 时按原值签发；若该值是纯数字，顺带把序号推进到它，避免后续自动签发撞号。
func nextLicenseID(path, explicit string) (string, error) {
	cur := readLicenseSeq(path)
	if v := strings.TrimSpace(explicit); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > cur {
			if err := writeLicenseSeq(path, n); err != nil {
				return "", err
			}
		}
		return v, nil
	}
	n := cur + 1
	if err := writeLicenseSeq(path, n); err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10), nil
}

func writeLicenseSeq(path string, n int64) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(strconv.FormatInt(n, 10)), 0o600)
}
