package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// applyCgroupMemoryLimit 让 Go 运行时感知 cgroup 内存上限。
//
// 事故背景：unit 设了 MemoryMax=256M，但 Go 运行时对此一无所知。默认
// GOGC=100 意味着堆要涨到存活量的两倍才触发 GC——存活约 60MB 时，运行时
// 会安心让堆涨到 120MB 以上才回收，再加上规则集重建、栈与运行时开销，
// 峰值轻易越过 256M 被内核 OOM kill，且是硬杀，Go 完全没有反应机会。
//
// 设置 GOMEMLIMIT 后，运行时会在接近上限时主动、持续地 GC，把回收压力
// 提前到撞墙之前。留出余量是必要的：GOMEMLIMIT 只约束 Go 堆，而 cgroup
// 统计的是包含栈、mmap、page cache 在内的全部常驻内存。
//
// 显式设置的 GOMEMLIMIT 环境变量优先，便于运维临时覆盖。
func applyCgroupMemoryLimit() {
	if v, ok := os.LookupEnv("GOMEMLIMIT"); ok && strings.TrimSpace(v) != "" {
		return // 尊重显式配置
	}

	max, ok := readCgroupMemoryMax()
	if !ok {
		return
	}

	// 预留一半（至少 64MiB）给非堆内存。
	//
	// 比例看似保守，但有生产数据支撑：OOM 现场的 memory.stat 显示
	// slab_unreclaimable 高达 123MB（socket 缓冲等内核对象），体量与 Go
	// 堆相当。这部分计入 cgroup 却不受 GOMEMLIMIT 约束，也无法由应用
	// 侧回收；若只预留少量额度，Go 会认为自己远未触顶而不加大 GC
	// 力度，最终仍被内核硬杀。
	reserve := max / 2
	if reserve < 64<<20 {
		reserve = 64 << 20
	}
	limit := max - reserve
	if limit < 48<<20 {
		// 上限本身过小，设限意义不大，交给运维调大 MemoryMax。
		return
	}

	debug.SetMemoryLimit(limit)
	log.Printf("已按 cgroup 上限设置 GOMEMLIMIT=%dMiB（cgroup 上限 %dMiB）",
		limit>>20, max>>20)
}

// readCgroupMemoryMax 读取当前进程所属 cgroup 的内存上限，单位字节。
// 无上限（max）、读取失败或非 Linux 环境时返回 ok=false。
//
// 关键：cgroup v2 下限制写在进程所属的子 cgroup（如
// /sys/fs/cgroup/system.slice/5gpn-next.service/memory.max），而不是根目录。
// 必须先从 /proc/self/cgroup 解析出自身路径，否则永远读不到限制。
// 同时逐级向上查找：限制可能设在父级 slice 上。
func readCgroupMemoryMax() (int64, bool) {
	const root = "/sys/fs/cgroup"

	// cgroup v2：/proc/self/cgroup 形如 "0::/system.slice/foo.service"
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) != 3 || parts[0] != "0" {
				continue
			}
			// 从自身路径逐级向上，取遇到的第一个有效上限。
			rel := parts[2]
			for {
				p := filepath.Join(root, rel, "memory.max")
				if c, err := os.ReadFile(p); err == nil {
					if v, ok := parseMemMax(string(c)); ok {
						return v, true
					}
				}
				if rel == "/" || rel == "" || rel == "." {
					break
				}
				rel = filepath.Dir(rel)
			}
			break
		}
	}

	// cgroup v1 回退
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, ok := parseMemMax(string(b)); ok {
			// v1 无上限时是一个极大值，视作未设限
			if v < 1<<62 {
				return v, true
			}
		}
	}
	return 0, false
}

func parseMemMax(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}
