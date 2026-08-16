package quicfwd

import "testing"

// TestSessionCapFitsMemoryBudget 锁定 OOM 事故：QUIC 会话上限必须与
// cgroup 内存预算相称。
//
// 每个被接管的 QUIC 会话要向出口建立一个 UDP socket，内核为其预留收发
// 缓冲。项目已把该缓冲收紧到 64KB（见 egress.udpSocketBuffer），但会话
// 数本身也必须有界，否则内核侧 slab_unreclaimable 仍会顶破 cgroup。
//
// 生产事故：maxSessions=4096 时，按内核默认 208KB 缓冲计算，仅内核侧
// 上界就达 1664MB，而目标机总内存 941MB、cgroup 上限 512MB。OOM 现场
// 为 anon 222MB + slab_unreclaimable 260MB，健康态 slab 仅 0.23MB。
func TestSessionCapFitsMemoryBudget(t *testing.T) {
	const (
		cgroupLimitMB = 512
		udpBufKB      = 64 // 与 egress.udpSocketBuffer 保持一致
	)

	// 内核侧：每会话收发各一份缓冲
	kernelMB := maxSessions * udpBufKB * 2 / 1024
	// Go 侧：握手期间每会话最多缓冲 maxPendingDatagrams × maxDatagram
	goMB := maxSessions * maxPendingDatagrams * maxDatagram / (1024 * 1024)

	t.Logf("maxSessions=%d 内核侧上界≈%dMB Go 侧 pending 上界≈%dMB (cgroup %dMB)",
		maxSessions, kernelMB, goMB, cgroupLimitMB)

	if kernelMB+goMB >= cgroupLimitMB {
		t.Fatalf("maxSessions=%d 时内存上界 %dMB 已达 cgroup 上限 %dMB，会触发 OOM",
			maxSessions, kernelMB+goMB, cgroupLimitMB)
	}
}

// TestPendingBufferBounded 握手期缓冲必须双重有界：既限个数也限字节，
// 否则单个恶意会话即可撑爆内存。
func TestPendingBufferBounded(t *testing.T) {
	if maxPendingDatagrams <= 0 || maxPendingBytes <= 0 {
		t.Fatal("pending 缓冲必须有正的上界")
	}
	// 字节上限不得超过按个数计算的理论最大值，否则字节限制形同虚设
	if maxPendingBytes > maxPendingDatagrams*maxDatagram {
		t.Fatalf("maxPendingBytes=%d 超过 %d×%d，字节限制失效",
			maxPendingBytes, maxPendingDatagrams, maxDatagram)
	}
}
