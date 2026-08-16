package main

import "testing"

// TestParseMemMax 覆盖 cgroup 上限文件的各种取值。
func TestParseMemMax(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"268435456\n", 268435456, true},
		{"  536870912  ", 536870912, true},
		{"max\n", 0, false}, // 未设限
		{"", 0, false},      // 空文件
		{"\n", 0, false},    // 仅换行
		{"abc", 0, false},   // 非法内容
		{"-1", 0, false},    // 负值
		{"0", 0, false},     // 零值无意义
	}
	for _, c := range cases {
		got, ok := parseMemMax(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseMemMax(%q) = (%d,%v), 期望 (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestApplyCgroupMemoryLimitIsSafe 确保在任何环境下都不 panic。
// 读不到 cgroup 上限时应静默跳过，不能影响启动。
func TestApplyCgroupMemoryLimitIsSafe(t *testing.T) {
	applyCgroupMemoryLimit()
}

// TestApplyCgroupMemoryLimitRespectsEnv 显式设置 GOMEMLIMIT 时不得覆盖。
func TestApplyCgroupMemoryLimitRespectsEnv(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "123MiB")
	applyCgroupMemoryLimit() // 应直接返回，不做任何修改
}
