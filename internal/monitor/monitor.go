// Package monitor 提供网关内置健康监控：出口探测、真实转发结果埋点、
// DoT 上游耗时与告警。
//
// 存在理由：用户体感的「偶尔卡一下」是瞬态事件，事后 SSH 上来只能看到
// 静态快照，什么都抓不到。监控必须常驻在网关内部持续采样，Bot 里随时
// 回看，才能把「刚才卡了」对应到具体出口/DNS/会话水位。
//
// 设计取舍：全部数据放内存环形缓冲（每出口 1440 个探测点 ≈ 24h），
// 不落盘不写数据库；重启清零可接受——监控是诊断工具，不是审计日志。
// 采样失败绝不影响转发路径：本包只观测，不参与任何数据面决策。
package monitor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// ProbeInterval 是出口探测周期。
	ProbeInterval = 60 * time.Second
	// probeTimeout 与数据面 egress.DialTimeout 对齐：探测比真实流量
	// 更宽容没有意义，用户流量 4s 就超时了。
	probeTimeout = 4 * time.Second

	probeCap = 1500 // ≈ 25h @ 60s
	fwCap    = 1024 // 真实转发结果，按次数保留
	dnsCap   = 2048 // DoT 上游查询结果

	// alertAfter 是连续失败多少次后告警。首次失败可能只是单点抖动，
	// 连续三个周期（3 分钟）失败才值得打扰人。
	alertAfter = 3
	// alertCooldown 限制同一出口的告警频率。
	alertCooldown = 30 * time.Minute
)

// Target 是一个可探测的出口端点。
type Target struct {
	Name string
	Addr string // host:port
}

// Sample 是一次采样结果。
type Sample struct {
	At time.Time
	MS int64
	OK bool
}

// ring 是固定容量环形缓冲。非并发安全，由 Monitor 的锁保护。
type ring struct {
	buf  []Sample
	next int
	full bool
}

func newRing(capacity int) *ring { return &ring{buf: make([]Sample, capacity)} }

func (r *ring) add(s Sample) {
	r.buf[r.next] = s
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// all 按时间顺序返回全部样本。
func (r *ring) all() []Sample {
	if !r.full {
		return append([]Sample(nil), r.buf[:r.next]...)
	}
	out := make([]Sample, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

func (r *ring) since(t time.Time) []Sample {
	var out []Sample
	for _, s := range r.all() {
		if !s.At.Before(t) {
			out = append(out, s)
		}
	}
	return out
}

// Window 是一段时间窗口内的聚合。
type Window struct {
	Count      int
	Fail       int
	AvgMS      int64
	P95MS      int64
	MaxMS      int64
	LastFailAt time.Time
}

// FailRate 返回失败率（0~1）。
func (w Window) FailRate() float64 {
	if w.Count == 0 {
		return 0
	}
	return float64(w.Fail) / float64(w.Count)
}

func summarize(ss []Sample) Window {
	var w Window
	var sum int64
	var lat []int64
	for _, s := range ss {
		w.Count++
		if !s.OK {
			w.Fail++
			if s.At.After(w.LastFailAt) {
				w.LastFailAt = s.At
			}
			continue
		}
		sum += s.MS
		lat = append(lat, s.MS)
		if s.MS > w.MaxMS {
			w.MaxMS = s.MS
		}
	}
	if len(lat) > 0 {
		w.AvgMS = sum / int64(len(lat))
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		idx := len(lat) * 95 / 100
		if idx >= len(lat) {
			idx = len(lat) - 1
		}
		w.P95MS = lat[idx]
	}
	return w
}

// Monitor 是健康监控中枢。
type Monitor struct {
	mu        sync.Mutex
	probes    map[string]*ring
	fw        map[string]*ring
	dns       *ring
	consec    map[string]int
	alerted   map[string]bool
	lastAlert map[string]time.Time

	// Targets 返回当前可探测的出口列表；配置热重载后自动跟随。
	Targets func() []Target
	// Notify 用于主动告警（可为空，Bot 未启用时静默）。
	Notify func(text string)
	// SniffActive / QUICActive 返回 (活跃数, 上限)；可为空。
	SniffActive func() (int, int)
	QUICActive  func() (int, int)

	now  func() time.Time
	dial func(ctx context.Context, addr string) (time.Duration, error)
}

// New 构造 Monitor。
func New() *Monitor {
	return &Monitor{
		probes:    make(map[string]*ring),
		fw:        make(map[string]*ring),
		dns:       newRing(dnsCap),
		consec:    make(map[string]int),
		alerted:   make(map[string]bool),
		lastAlert: make(map[string]time.Time),
		now:       time.Now,
		dial: func(ctx context.Context, addr string) (time.Duration, error) {
			d := net.Dialer{}
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", addr)
			el := time.Since(start)
			if err != nil {
				return el, err
			}
			c.Close()
			return el, nil
		},
	}
}

// Run 周期探测，直到 ctx 结束。
func (m *Monitor) Run(ctx context.Context) {
	// 启动后先等一小段，让 mihomo/出口就绪，避免开机误报。
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	m.probeOnce(ctx)
	t := time.NewTicker(ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.probeOnce(ctx)
		}
	}
}

func (m *Monitor) probeOnce(ctx context.Context) {
	if m.Targets == nil {
		return
	}
	targets := m.Targets()
	var wg sync.WaitGroup
	for _, tgt := range targets {
		if tgt.Addr == "" {
			continue
		}
		wg.Add(1)
		go func(tgt Target) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			el, err := m.dial(dctx, tgt.Addr)
			m.recordProbe(tgt.Name, err == nil, el.Milliseconds())
		}(tgt)
	}
	wg.Wait()
}

func (m *Monitor) recordProbe(name string, ok bool, ms int64) {
	now := m.now()
	var alert string
	m.mu.Lock()
	r := m.probes[name]
	if r == nil {
		r = newRing(probeCap)
		m.probes[name] = r
	}
	r.add(Sample{At: now, MS: ms, OK: ok})
	if ok {
		if m.alerted[name] {
			m.alerted[name] = false
			alert = fmt.Sprintf("✅ 出口 <b>%s</b> 探测已恢复（%dms）", name, ms)
		}
		m.consec[name] = 0
	} else {
		m.consec[name]++
		if m.consec[name] == alertAfter && !m.alerted[name] &&
			now.Sub(m.lastAlert[name]) >= alertCooldown {
			m.alerted[name] = true
			m.lastAlert[name] = now
			alert = fmt.Sprintf("🚨 出口 <b>%s</b> 连续 %d 次探测失败，链路可能中断", name, alertAfter)
		}
	}
	notify := m.Notify
	m.mu.Unlock()
	if alert != "" && notify != nil {
		notify(alert)
	}
}

// RecordForward 记录一次真实转发的拨号结果（TCP 与 QUIC 共用）。
func (m *Monitor) RecordForward(egress string, ok bool, ms int64) {
	if egress == "" {
		egress = "DIRECT"
	}
	m.mu.Lock()
	r := m.fw[egress]
	if r == nil {
		r = newRing(fwCap)
		m.fw[egress] = r
	}
	r.add(Sample{At: m.now(), MS: ms, OK: ok})
	m.mu.Unlock()
}

// RecordDNS 记录一次 DoT 上游查询结果。
func (m *Monitor) RecordDNS(ok bool, ms int64) {
	m.mu.Lock()
	m.dns.add(Sample{At: m.now(), MS: ms, OK: ok})
	m.mu.Unlock()
}

// EgressHealth 是单出口健康汇总。
type EgressHealth struct {
	Name     string
	Probe1h  Window
	Probe24h Window
	Fw1h     Window
}

// Health 是给 Bot / 面板的整体快照。
type Health struct {
	Egress                 []EgressHealth
	DNS1h                  Window
	DNS24h                 Window
	TCPActive, TCPMax      int
	QUICActive, QUICMax    int
}

// Snapshot 返回当前健康快照。
func (m *Monitor) Snapshot() Health {
	now := m.now()
	h1 := now.Add(-time.Hour)
	h24 := now.Add(-24 * time.Hour)

	m.mu.Lock()
	names := make([]string, 0, len(m.probes))
	for n := range m.probes {
		names = append(names, n)
	}
	// 有真实转发但没探测记录的出口（如 DIRECT）也要展示。
	for n := range m.fw {
		if _, ok := m.probes[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var out Health
	for _, n := range names {
		eh := EgressHealth{Name: n}
		if r := m.probes[n]; r != nil {
			eh.Probe1h = summarize(r.since(h1))
			eh.Probe24h = summarize(r.since(h24))
		}
		if r := m.fw[n]; r != nil {
			eh.Fw1h = summarize(r.since(h1))
		}
		out.Egress = append(out.Egress, eh)
	}
	out.DNS1h = summarize(m.dns.since(h1))
	out.DNS24h = summarize(m.dns.since(h24))
	m.mu.Unlock()

	if m.SniffActive != nil {
		out.TCPActive, out.TCPMax = m.SniffActive()
	}
	if m.QUICActive != nil {
		out.QUICActive, out.QUICMax = m.QUICActive()
	}
	return out
}

// Anomalies 返回某出口最近的异常探测点（失败或显著慢），最多 limit 条，
// 新的在前。慢的判定用 24h 平均值的 3 倍且不低于 200ms，避免把低延迟
// 出口的正常波动当异常。
func (m *Monitor) Anomalies(name string, limit int) []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.probes[name]
	if r == nil {
		return nil
	}
	all := r.all()
	avg := summarize(all).AvgMS
	slow := avg * 3
	if slow < 200 {
		slow = 200
	}
	var out []Sample
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		s := all[i]
		if !s.OK || s.MS >= slow {
			out = append(out, s)
		}
	}
	return out
}
