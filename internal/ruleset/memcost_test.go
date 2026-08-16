package ruleset

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestRuleSetMemoryCost 量化一次规则集重建的内存代价。
//
// 生产事故背景：热重载会在旧引擎仍存活时构建一份全新引擎，
// 若规则集也跟着重建，内存瞬时翻倍并撞破 cgroup 上限被 OOM kill。
// 本用例不是断言阈值，而是把真实代价打印出来作为决策依据。
func TestRuleSetMemoryCost(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过内存基准")
	}

	// 构造与生产同量级的域名集：cn-domain 约 11 万条、ad-block 约 10 万条
	const n = 110000
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "sub%d.example%d.com\n", i, i%5000)
	}
	data := sb.String()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	ds, err := parseDomains(strings.NewReader(data))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ds.Len() == 0 {
		t.Fatal("解析结果为空")
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	costMB := float64(after.HeapAlloc-before.HeapAlloc) / 1048576
	t.Logf("域名规则集 %d 条常驻堆约 %.1f MB；生产同时持有 cn-domain + ad-block 两套，"+
		"热重载期间新旧并存即约 4 套", ds.Len(), costMB)

	// 保持引用，避免被提前回收导致测量失真
	runtime.KeepAlive(ds)
}
