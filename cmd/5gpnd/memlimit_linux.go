//go:build linux

package main

import (
	"log"

	"golang.org/x/sys/unix"
)

// disableTHP 为本进程关闭透明大页（THP）。
//
// 事故根因：主机 THP 策略为 always 时，内核会把进程的匿名内存按 2MiB
// 大页凑整。Go 的堆是稀疏的——运行时向 OS 保留大片地址空间但只按需触碰
// 其中少量页，THP 却会把整个 2MiB 区间实打实地计入 cgroup。
//
// 生产实测（OOM 瞬间的 memory.stat）：
//
//	anon        124MB   ← Go 堆本身，正常
//	kernel      144MB   ← 内核侧记账，异常
//	anon_thp    117MB   ← 几乎整个堆都被大页接管
//
// 两者相加正好撞破 256MiB 上限。关键在于这部分放大量 GOMEMLIMIT 完全
// 管不到：Go 运行时只统计自己的堆（当时才 55MB 左右，离限制很远），
// 于是既不会主动 GC，也没有任何反制手段，只能被内核硬杀。
//
// PR_SET_THP_DISABLE 只作用于当前进程及其子进程，不修改 /sys 全局策略，
// 因此不会影响同机其它服务；该标志会被 fork 继承、exec 后保留。
//
// 失败不致命：老内核可能不支持该 prctl，此时退回原行为，仅记录日志。
func disableTHP() {
	if err := unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0); err != nil {
		log.Printf("提示: 未能为本进程关闭透明大页（%v），"+
			"若主机 THP 为 always 且内存吃紧，建议调大 MemoryMax", err)
		return
	}
	log.Printf("已为本进程关闭透明大页（避免稀疏堆被按 2MiB 放大计入 cgroup）")
}
