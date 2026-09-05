package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const ms = int64(1000) // 1ms = 1000µs

func TestRingWrapsAndKeepsOrder(t *testing.T) {
	r := newRing(3)
	base := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		r.add(Sample{At: base.Add(time.Duration(i) * time.Second), US: int64(i), OK: true})
	}
	all := r.all()
	if len(all) != 3 {
		t.Fatalf("len=%d want 3", len(all))
	}
	for i, s := range all {
		if s.US != int64(i+2) {
			t.Fatalf("order wrong: idx %d got US=%d want %d", i, s.US, i+2)
		}
	}
}

func TestSummarizeSkipsFailuresInLatency(t *testing.T) {
	now := time.Now()
	w := summarize([]Sample{
		{At: now, US: 10 * ms, OK: true},
		{At: now, US: 30 * ms, OK: true},
		{At: now.Add(time.Second), US: 4000 * ms, OK: false},
	})
	if w.Count != 3 || w.Fail != 1 {
		t.Fatalf("count=%d fail=%d", w.Count, w.Fail)
	}
	if w.AvgUS != 20*ms {
		t.Fatalf("avg=%d want %d（失败样本的耗时不能计入延迟）", w.AvgUS, 20*ms)
	}
	if w.LastFailAt.IsZero() {
		t.Fatal("LastFailAt 未记录")
	}
}

// 亚毫秒必须能被区分出来：这正是面板一排 0ms 的根因。
func TestFormatUSKeepsSubMillisecondVisible(t *testing.T) {
	cases := []struct {
		us   int64
		want string
	}{
		{0, "0ms"},
		{40, "≤0.1ms"}, // 本机 SOCKS5 桥的真实量级
		{99, "≤0.1ms"},
		{100, "0.1ms"},
		{432, "0.4ms"},
		{1500, "1.5ms"},
		{9999, "10.0ms"},
		{36_000, "36ms"}, // 跨国链路量级
		{135_400, "135ms"},
	}
	for _, c := range cases {
		if got := FormatUS(c.us); got != c.want {
			t.Fatalf("FormatUS(%d)=%q want %q", c.us, got, c.want)
		}
	}
}

func TestAlertFiresAfterConsecutiveFailuresAndRecovers(t *testing.T) {
	m := New()
	var notes []string
	m.Notify = func(s string) { notes = append(notes, s) }

	for i := 0; i < DefaultAlertAfter+2; i++ {
		m.recordProbe("hinet", false, 4000*ms, ProbeKindEndToEnd)
	}
	if len(notes) != 1 {
		t.Fatalf("连续失败应只告警一次，got %d: %v", len(notes), notes)
	}
	m.recordProbe("hinet", true, 40*ms, ProbeKindEndToEnd)
	if len(notes) != 2 {
		t.Fatalf("恢复应通知一次，got %d", len(notes))
	}
	// 恢复后再次少量失败：未达阈值不告警。
	m.recordProbe("hinet", false, 4000*ms, ProbeKindEndToEnd)
	if len(notes) != 2 {
		t.Fatalf("单次失败不应告警，got %d", len(notes))
	}
}

// 探测语义必须随样本一起暴露，否则面板无法区分「桥 0.04ms」和「链路 130ms」。
func TestSnapshotCarriesProbeKind(t *testing.T) {
	m := New()
	m.ProbeTarget = DefaultProbeRemote
	m.recordProbe("hinet", true, 135*ms, ProbeKindEndToEnd)
	m.recordProbe("local", true, 40, ProbeKindBridge)

	h := m.Snapshot()
	if h.ProbeTarget != DefaultProbeRemote {
		t.Fatalf("ProbeTarget=%q", h.ProbeTarget)
	}
	byName := map[string]EgressHealth{}
	for _, e := range h.Egress {
		byName[e.Name] = e
	}
	if got := byName["hinet"].Kind; got != ProbeKindEndToEnd {
		t.Fatalf("hinet kind=%v", got)
	}
	if got := byName["hinet"].Probe1h.Avg(); got != "135ms" {
		t.Fatalf("hinet avg=%q want 135ms", got)
	}
	if got := byName["local"].Kind; got != ProbeKindBridge {
		t.Fatalf("local kind=%v", got)
	}
	if got := byName["local"].Probe1h.Avg(); got != "≤0.1ms" {
		t.Fatalf("local avg=%q want ≤0.1ms（不能再显示 0ms）", got)
	}
}

func TestRecordForwardDefaultsToDirect(t *testing.T) {
	m := New()
	m.RecordForward("", true, 5*ms)
	h := m.Snapshot()
	if len(h.Egress) != 1 || h.Egress[0].Name != "DIRECT" {
		t.Fatalf("snapshot=%+v", h.Egress)
	}
	if h.Egress[0].Fw1h.Count != 1 {
		t.Fatalf("fw count=%d", h.Egress[0].Fw1h.Count)
	}
}

func TestAnomaliesFindsFailuresAndSlowPoints(t *testing.T) {
	m := New()
	for i := 0; i < 50; i++ {
		m.recordProbe("sb", true, 10*ms, ProbeKindEndToEnd)
	}
	m.recordProbe("sb", true, 900*ms, ProbeKindEndToEnd) // 明显慢
	m.recordProbe("sb", false, 4000*ms, ProbeKindEndToEnd)
	an := m.Anomalies("sb", 10)
	if len(an) != 2 {
		t.Fatalf("anomalies=%d want 2: %+v", len(an), an)
	}
	if an[0].OK { // 新的在前：最后一条是失败
		t.Fatal("第一条应为失败样本")
	}
	// 低延迟正常波动（低于 200ms 下限）不算异常。
	m2 := New()
	for i := 0; i < 10; i++ {
		m2.recordProbe("x", true, 10*ms, ProbeKindEndToEnd)
	}
	m2.recordProbe("x", true, 120*ms, ProbeKindEndToEnd)
	if got := m2.Anomalies("x", 10); len(got) != 0 {
		t.Fatalf("120ms 不应算异常: %+v", got)
	}
}

func TestProbeOnceUsesInjectedDialer(t *testing.T) {
	m := New()
	m.Targets = func() []Target {
		return []Target{
			{Name: "a", Addr: "10.0.0.1:1", Kind: ProbeKindNode},
			{Name: "b", Addr: "10.0.0.2:1", Kind: ProbeKindNode},
		}
	}
	m.dial = func(_ context.Context, tg Target) (time.Duration, error) {
		if tg.Addr == "10.0.0.1:1" {
			return 15 * time.Millisecond, nil
		}
		return 0, errors.New("refused")
	}
	m.probeOnce(context.Background())
	h := m.Snapshot()
	if len(h.Egress) != 2 {
		t.Fatalf("egress=%d", len(h.Egress))
	}
	byName := map[string]EgressHealth{}
	for _, e := range h.Egress {
		byName[e.Name] = e
	}
	if byName["a"].Probe1h.Fail != 0 || byName["a"].Probe1h.Count != 1 {
		t.Fatalf("a: %+v", byName["a"].Probe1h)
	}
	if got := byName["a"].Probe1h.AvgUS; got != 15*ms {
		t.Fatalf("a avg=%dµs want %d（必须按微秒记录）", got, 15*ms)
	}
	if byName["b"].Probe1h.Fail != 1 {
		t.Fatalf("b: %+v", byName["b"].Probe1h)
	}
}

// 端到端探测的远端目标被指向网关自身时，必须降级为桥探测而不是制造自连接环路。
func TestProbeOnceGuardDowngradesSelfPointingRemote(t *testing.T) {
	m := New()
	m.Targets = func() []Target {
		return []Target{{
			Name: "loop", Addr: "127.0.0.1:7891", Socks5: true,
			Remote: "10.9.9.9:853", Kind: ProbeKindEndToEnd,
		}}
	}
	m.Guard = func(addr string) error {
		if addr == "10.9.9.9:853" {
			return errors.New("self")
		}
		return nil
	}
	var seen Target
	m.dial = func(_ context.Context, tg Target) (time.Duration, error) {
		seen = tg
		return 40 * time.Microsecond, nil
	}
	m.probeOnce(context.Background())

	if seen.Remote != "" {
		t.Fatalf("远端目标指向网关自身时必须清空，got %q", seen.Remote)
	}
	if seen.Kind != ProbeKindBridge {
		t.Fatalf("降级后语义应为桥探测，got %v", seen.Kind)
	}
	h := m.Snapshot()
	if h.Egress[0].Kind != ProbeKindBridge {
		t.Fatalf("快照 kind=%v", h.Egress[0].Kind)
	}
}

// 老快照存的是毫秒字段 MS；升级后必须换算，否则历史全部塌成 0。
func TestSampleUnmarshalAcceptsLegacyMilliseconds(t *testing.T) {
	var legacy Sample
	if err := json.Unmarshal([]byte(`{"At":"2026-08-27T10:00:00Z","MS":135,"OK":true}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.US != 135*ms {
		t.Fatalf("legacy US=%d want %d", legacy.US, 135*ms)
	}
	if !legacy.OK {
		t.Fatal("OK 丢失")
	}

	// 新格式原样解析。
	var cur Sample
	if err := json.Unmarshal([]byte(`{"At":"2026-08-27T10:00:00Z","us":432,"OK":true}`), &cur); err != nil {
		t.Fatal(err)
	}
	if cur.US != 432 {
		t.Fatalf("cur US=%d want 432", cur.US)
	}

	// 往返：Marshal 后必须仍能读回同一值。
	b, err := json.Marshal(cur)
	if err != nil {
		t.Fatal(err)
	}
	var back Sample
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.US != cur.US || back.OK != cur.OK {
		t.Fatalf("round trip 丢失: %+v vs %+v", back, cur)
	}
}

func TestForgetEgressDropsSnapshotAndPersist(t *testing.T) {
	dir := t.TempDir()
	m := New()
	m.PersistPath = dir + "/health.json"
	m.recordProbe("gone", true, 40*ms, ProbeKindEndToEnd)
	m.recordProbe("keep", true, 20*ms, ProbeKindEndToEnd)
	m.RecordForward("gone", true, 10*ms)
	m.AddEgressTraffic("gone", 100, 200)

	h := m.Snapshot()
	if len(h.Egress) != 2 {
		t.Fatalf("before forget egress=%d", len(h.Egress))
	}
	m.ForgetEgress("gone")
	h = m.Snapshot()
	if len(h.Egress) != 1 || h.Egress[0].Name != "keep" {
		t.Fatalf("after forget: %+v", h.Egress)
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2 := New()
	m2.PersistPath = m.PersistPath
	m2.Load()
	h = m2.Snapshot()
	for _, e := range h.Egress {
		if e.Name == "gone" {
			t.Fatal("deleted egress survived persist")
		}
	}
}
