package monitor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRingWrapsAndKeepsOrder(t *testing.T) {
	r := newRing(3)
	base := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		r.add(Sample{At: base.Add(time.Duration(i) * time.Second), MS: int64(i), OK: true})
	}
	all := r.all()
	if len(all) != 3 {
		t.Fatalf("len=%d want 3", len(all))
	}
	for i, s := range all {
		if s.MS != int64(i+2) {
			t.Fatalf("order wrong: idx %d got MS=%d want %d", i, s.MS, i+2)
		}
	}
}

func TestSummarizeSkipsFailuresInLatency(t *testing.T) {
	now := time.Now()
	w := summarize([]Sample{
		{At: now, MS: 10, OK: true},
		{At: now, MS: 30, OK: true},
		{At: now.Add(time.Second), MS: 4000, OK: false},
	})
	if w.Count != 3 || w.Fail != 1 {
		t.Fatalf("count=%d fail=%d", w.Count, w.Fail)
	}
	if w.AvgMS != 20 {
		t.Fatalf("avg=%d want 20（失败样本的耗时不能计入延迟）", w.AvgMS)
	}
	if w.LastFailAt.IsZero() {
		t.Fatal("LastFailAt 未记录")
	}
}

func TestAlertFiresAfterConsecutiveFailuresAndRecovers(t *testing.T) {
	m := New()
	var notes []string
	m.Notify = func(s string) { notes = append(notes, s) }

	for i := 0; i < DefaultAlertAfter+2; i++ {
		m.recordProbe("hinet", false, 4000)
	}
	if len(notes) != 1 {
		t.Fatalf("连续失败应只告警一次，got %d: %v", len(notes), notes)
	}
	m.recordProbe("hinet", true, 40)
	if len(notes) != 2 {
		t.Fatalf("恢复应通知一次，got %d", len(notes))
	}
	// 恢复后再次少量失败：未达阈值不告警。
	m.recordProbe("hinet", false, 4000)
	if len(notes) != 2 {
		t.Fatalf("单次失败不应告警，got %d", len(notes))
	}
}

func TestRecordForwardDefaultsToDirect(t *testing.T) {
	m := New()
	m.RecordForward("", true, 5)
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
		m.recordProbe("sb", true, 10)
	}
	m.recordProbe("sb", true, 900) // 明显慢
	m.recordProbe("sb", false, 4000)
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
		m2.recordProbe("x", true, 10)
	}
	m2.recordProbe("x", true, 120)
	if got := m2.Anomalies("x", 10); len(got) != 0 {
		t.Fatalf("120ms 不应算异常: %+v", got)
	}
}

func TestProbeOnceUsesInjectedDialer(t *testing.T) {
	m := New()
	m.Targets = func() []Target {
		return []Target{{Name: "a", Addr: "10.0.0.1:1"}, {Name: "b", Addr: "10.0.0.2:1"}}
	}
	m.dial = func(_ context.Context, addr string, _ bool) (time.Duration, error) {
		if addr == "10.0.0.1:1" {
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
	if byName["b"].Probe1h.Fail != 1 {
		t.Fatalf("b: %+v", byName["b"].Probe1h)
	}
}
