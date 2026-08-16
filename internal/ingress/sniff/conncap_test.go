package sniff

import (
	"testing"
)

// TestConnCapBoundsConcurrency 锁定 OOM 事故的一环：TCP 接管必须有并发上限。
//
// 旧实现对 Accept 不设任何限制，来多少连接就开多少 goroutine。每条连接
// 占两个 goroutine、两条 io.Copy 的 32KB 缓冲，以及内核为 socket 预留的
// 收发缓冲（默认各约 208KB）。内核那部分计入 cgroup 的
// slab_unreclaimable，不受 GOMEMLIMIT 约束也无法由应用回收——生产 OOM
// 现场即为 anon 222MB + slab 260MB 顶破 512MB。
func TestConnCapBoundsConcurrency(t *testing.T) {
	s := &Server{}

	// 占满全部名额
	for i := 0; i < maxConns; i++ {
		if !s.acquire() {
			t.Fatalf("第 %d 个名额本应可用（上限 %d）", i+1, maxConns)
		}
	}

	// 超出上限必须被拒绝，而不是继续分配
	if s.acquire() {
		t.Fatal("超过并发上限仍放行 —— 内存无上界回归")
	}

	// 释放一个后应能再获取
	s.release()
	if !s.acquire() {
		t.Fatal("释放名额后应可重新获取")
	}
}

// TestConnCapReleaseIsSafe 释放次数多于获取时不得阻塞或 panic。
// handle 中用 defer release，异常路径可能重复触发。
func TestConnCapReleaseIsSafe(t *testing.T) {
	s := &Server{}
	if !s.acquire() {
		t.Fatal("首次获取应成功")
	}
	s.release()
	s.release() // 多余的释放
	s.release()

	// 名额不应因多余释放而变多
	for i := 0; i < maxConns; i++ {
		if !s.acquire() {
			t.Fatalf("第 %d 个名额本应可用", i+1)
		}
	}
	if s.acquire() {
		t.Fatal("多余的 release 不得放大并发上限")
	}
}

// TestConnCapIsBounded 上限必须是有限值，且对小内存机器合理。
func TestConnCapIsBounded(t *testing.T) {
	if maxConns <= 0 {
		t.Fatal("maxConns 必须为正数")
	}
	// 每条连接内核侧最坏约 416KB（收发各 208KB）
	worstMB := maxConns * 416 / 1024
	if worstMB > 512 {
		t.Fatalf("maxConns=%d 时内核缓冲最坏约 %dMB，对 512MB cgroup 上限过大",
			maxConns, worstMB)
	}
}
