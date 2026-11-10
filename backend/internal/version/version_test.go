package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"1.2.0", [3]int{1, 2, 0}, true},
		{"v2.0", [3]int{2, 0, 0}, true},
		{" 1.10.3 ", [3]int{1, 10, 3}, true},
		{"1.2.0-beta.1", [3]int{1, 2, 0}, true},
		{"abc", [3]int{}, false},
		{"1.2.3.4", [3]int{}, false},
		{"", [3]int{}, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("Parse(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCompareAndIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.1.9", 1},
		{"1.10.0", "1.9.9", 1},
		{"1.2.0", "1.2.0", 0},
		{"1.1.0", "1.2.0", -1},
		{"bad", "1.2.0", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
	if Version == "" {
		t.Fatal("VERSION 文件不能为空")
	}
	if _, ok := Parse(Version); !ok {
		t.Fatalf("VERSION 内容不是合法语义版本：%q", Version)
	}
	if !IsNewer("99.0.0", Version) || IsNewer(Version, Version) {
		t.Fatal("IsNewer 判断异常")
	}
}
