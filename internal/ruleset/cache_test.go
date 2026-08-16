package ruleset

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLoadDomainFileCachedReusesParsedSet 锁定 OOM 事故的核心修复：
//
// 规则集载入后只读，热重载时若文件未变必须复用同一对象。旧实现每次
// 重建引擎都重新解析 20 余万条规则，新旧引擎并存导致内存翻倍，撞破
// cgroup 上限被 OOM kill，形成 OOM→重启→再 OOM 的死循环。
func TestLoadDomainFileCachedReusesParsedSet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cn-domain.list")
	if err := os.WriteFile(p, []byte("example.com\nfoo.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := LoadDomainFileCached(p)
	if err != nil {
		t.Fatalf("首次载入失败: %v", err)
	}
	b, err := LoadDomainFileCached(p)
	if err != nil {
		t.Fatalf("二次载入失败: %v", err)
	}
	if a != b {
		t.Fatal("文件未变却重新解析了规则集 —— 热重载内存翻倍回归")
	}
}

// TestLoadDomainFileCachedDetectsChange 文件内容变化后必须重新解析，
// 否则规则库更新永远不生效。
func TestLoadDomainFileCachedDetectsChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cn-domain.list")
	if err := os.WriteFile(p, []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadDomainFileCached(p)
	if err != nil {
		t.Fatal(err)
	}

	// mtime 粒度可能较粗，显式后移以确保可检测
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(p, []byte("example.com\nnew.example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(p, future, future)

	b, err := LoadDomainFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("文件已变却复用了旧规则集 —— 规则更新将永不生效")
	}
	if !b.Match("new.example.org") {
		t.Fatal("新规则未生效")
	}
}

// TestLoadDomainFileCachedNoUnboundedGrowth 同一路径反复更新时，
// 缓存不得无限增长。
func TestLoadDomainFileCachedNoUnboundedGrowth(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "grow.list")

	for i := 0; i < 12; i++ {
		content := fmt.Sprintf("example%d.com\n", i)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(time.Duration(i+1) * time.Second)
		_ = os.Chtimes(p, ts, ts)
		if _, err := LoadDomainFileCached(p); err != nil {
			t.Fatal(err)
		}
	}

	dsMu.Lock()
	n := 0
	for k := range dsCache {
		if k.path == p {
			n++
		}
	}
	dsMu.Unlock()
	if n != 1 {
		t.Fatalf("同一路径缓存条目数 = %d, 期望 1（旧版本应被清理）", n)
	}
}

// TestLoadCIDRFileCachedReusesParsedSet CIDR 集同样必须复用。
func TestLoadCIDRFileCachedReusesParsedSet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "geoip_cn.list")
	if err := os.WriteFile(p, []byte("1.2.3.0/24\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadCIDRFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadCIDRFileCached(p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("CIDR 规则集未复用")
	}
}

// TestCachedLoadersAreConcurrencySafe 热重载与后台刷新可能并发调用。
func TestCachedLoadersAreConcurrencySafe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "concurrent.list")
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "host%d.example.com\n", i)
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	got := make([]*DomainSet, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ds, err := LoadDomainFileCached(p)
			if err != nil {
				t.Errorf("并发载入失败: %v", err)
				return
			}
			got[idx] = ds
		}(i)
	}
	wg.Wait()

	for i := 1; i < len(got); i++ {
		if got[i] != nil && got[0] != nil && got[i] != got[0] {
			t.Fatal("并发载入返回了不同实例，存在重复解析")
		}
	}
	runtime.KeepAlive(got)
}

// TestLoadDomainFileCachedRejectsEmpty 空文件不得被缓存为有效规则集。
func TestLoadDomainFileCachedRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.list")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDomainFileCached(p); err == nil {
		t.Fatal("空规则集文件应报错")
	}
}
