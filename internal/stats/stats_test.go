package stats

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestAdBlockSuccessPersistsCountsAndRecentRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	s := New(path)

	s.AdBlockSuccess("Ads.Example.")
	s.AdBlockSuccess("ads.example")
	s.AdBlockSuccess("tracker.example")
	s.AdBlockSuccess("   ") // 空域名不得污染统计

	got := s.AdBlockSummary(10, 10)
	if got.Today != 3 || got.Days7 != 3 || got.Days30 != 3 || got.Total != 3 {
		t.Fatalf("unexpected counters: %+v", got)
	}
	if len(got.Recent) != 3 || got.Recent[0].Host != "tracker.example" || got.Recent[1].Host != "ads.example" {
		t.Fatalf("recent records not newest-first/normalized: %+v", got.Recent)
	}
	if len(got.Top) != 2 || got.Top[0].Host != "ads.example" || got.Top[0].Count != 2 {
		t.Fatalf("unexpected top domains: %+v", got.Top)
	}

	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded := New(path)
	got = reloaded.AdBlockSummary(10, 10)
	if got.Total != 3 || got.Today != 3 || len(got.Recent) != 3 || got.Top[0].Count != 2 {
		t.Fatalf("ad-block statistics did not survive reload: %+v", got)
	}
}

func TestAdBlockRecentRecordsAreBounded(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "traffic.json"))
	for i := 0; i < 125; i++ {
		s.AdBlockSuccess(fmt.Sprintf("ad-%03d.example", i))
	}

	got := s.AdBlockSummary(200, 5)
	if got.Total != 125 || got.Today != 125 {
		t.Fatalf("unexpected counters: %+v", got)
	}
	if len(got.Recent) != 100 {
		t.Fatalf("recent record count=%d, want 100", len(got.Recent))
	}
	if got.Recent[0].Host != "ad-124.example" || got.Recent[len(got.Recent)-1].Host != "ad-025.example" {
		t.Fatalf("unexpected retained range: first=%q last=%q", got.Recent[0].Host, got.Recent[len(got.Recent)-1].Host)
	}
	if len(got.Top) != 5 {
		t.Fatalf("top count=%d, want 5", len(got.Top))
	}
}
