package stats

import (
	"path/filepath"
	"testing"
	"time"
)

func TestIncrementalTrafficAndConnectionCategories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	s := New(path)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	// 连接建立/失败时立即入账；字节由转发循环独立、增量上报。
	s.Conn("video.example", "proxy", false)
	s.Conn("direct.example", "direct", true)
	s.Conn("blocked.example", "block", false)
	s.Traffic("Video.Example.", 123, 0)
	s.Traffic("video.example", 0, 456)
	s.Traffic("192.0.2.1", 99, 0) // 总量应统计，裸 IP 不进入域名榜
	s.Traffic("ignored.example", -1, -2)

	got := s.Summary(7, 10)
	if got.Today.Conns != 3 || got.Today.DirectConns != 1 || got.Today.ProxyConns != 1 || got.Today.Blocked != 1 {
		t.Fatalf("unexpected connection categories: %+v", got.Today)
	}
	if got.Today.Failed != 1 {
		t.Fatalf("failed=%d, want 1", got.Today.Failed)
	}
	if got.Today.Up != 222 || got.Today.Down != 456 {
		t.Fatalf("traffic up/down=%d/%d, want 222/456", got.Today.Up, got.Today.Down)
	}
	if len(got.TopDomain) != 1 || got.TopDomain[0].Host != "video.example" || got.TopDomain[0].Bytes != 579 {
		t.Fatalf("unexpected domain aggregation: %+v", got.TopDomain)
	}

	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded := New(path)
	reloaded.now = func() time.Time { return now }
	persisted := reloaded.Summary(7, 10)
	if persisted.Today.Up != 222 || persisted.Today.Down != 456 || persisted.Today.Conns != 3 {
		t.Fatalf("incremental statistics did not survive reload: %+v", persisted.Today)
	}
}

func TestTrafficUsesShanghaiDateAtUTCMidnightBoundary(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "traffic.json"))
	now := time.Date(2026, 8, 17, 15, 59, 59, 0, time.UTC) // 北京 8 月 17 日 23:59:59
	s.now = func() time.Time { return now }
	s.Traffic("edge.example", 10, 0)

	now = time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC) // 北京 8 月 18 日 00:00:00
	s.Traffic("edge.example", 0, 20)

	got := s.Summary(7, 10)
	if got.Today.Date != "2026-08-18" || got.Today.Up != 0 || got.Today.Down != 20 {
		t.Fatalf("today must follow Asia/Shanghai: %+v", got.Today)
	}
	if got.Days7.Up != 10 || got.Days7.Down != 20 {
		t.Fatalf("cross-midnight increments were not assigned to their actual days: %+v", got.Days7)
	}
}

func TestSummaryUsesNaturalCalendarWindows(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "traffic.json"))
	var now time.Time
	s.now = func() time.Time { return now }
	add := func(year int, month time.Month, day int, bytes int64) {
		now = time.Date(year, month, day, 12, 0, 0, 0, trafficLocation)
		s.Traffic("window.example", bytes, 0)
	}

	add(2026, time.August, 17, 1)
	add(2026, time.August, 11, 2) // 7 日窗口起点，计入
	add(2026, time.August, 10, 4) // 仅计入 30 日
	add(2026, time.July, 18, 8)   // 30 日窗口外
	now = time.Date(2026, time.August, 17, 12, 0, 0, 0, trafficLocation)

	got := s.Summary(90, 10)
	if got.Days7.Up != 3 || got.Days30.Up != 7 || got.AllTime.Up != 15 {
		t.Fatalf("calendar windows incorrect: days7=%d days30=%d all=%d", got.Days7.Up, got.Days30.Up, got.AllTime.Up)
	}
}
