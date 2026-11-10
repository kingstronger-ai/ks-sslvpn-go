package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestNextLicenseIDStartsFromOne(t *testing.T) {
	dir := t.TempDir()
	seq := filepath.Join(dir, "nested", "license.seq")

	for want := int64(1); want <= 3; want++ {
		got, err := nextLicenseID(seq, "")
		if err != nil {
			t.Fatalf("第 %d 次签发失败: %v", want, err)
		}
		if got != strconv.FormatInt(want, 10) {
			t.Fatalf("第 %d 次签发编号 = %q，期望 %q", want, got, strconv.FormatInt(want, 10))
		}
	}
	b, err := os.ReadFile(seq)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "3" {
		t.Errorf("序号文件内容 = %q，期望 3", b)
	}
}

func TestNextLicenseIDExplicit(t *testing.T) {
	dir := t.TempDir()
	seq := filepath.Join(dir, "license.seq")

	// 显式编号原样签发，并推进序号，避免下次自动生成撞号
	got, err := nextLicenseID(seq, "100")
	if err != nil || got != "100" {
		t.Fatalf("显式编号 = %q, err = %v", got, err)
	}
	next, err := nextLicenseID(seq, "")
	if err != nil || next != "101" {
		t.Fatalf("显式编号后自动签发 = %q, err = %v，期望 101", next, err)
	}

	// 非数字编号不推进序号
	if _, err := nextLicenseID(seq, "KS-CUSTOM"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(seq)
	if string(b) != "101" {
		t.Errorf("非数字编号不应推进序号，当前 = %q", b)
	}
}

func TestReadLicenseSeqCorrupted(t *testing.T) {
	dir := t.TempDir()
	seq := filepath.Join(dir, "license.seq")
	if err := os.WriteFile(seq, []byte("not-a-number"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := nextLicenseID(seq, "")
	if err != nil || got != "1" {
		t.Fatalf("损坏的序号文件应从 1 重新计数，得到 %q, err = %v", got, err)
	}
}
