package manage

import (
	"testing"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/monitor"
)

func TestHealthReportHidesDeletedEgress(t *testing.T) {
	cfg := config.Default()
	m := New("/tmp/unused.json", cfg, nil, nil)
	mon := monitor.New()
	mon.RecordForward("DIRECT", true, 20_000)
	mon.RecordForward("gone", true, 40_000)
	m.Health = mon

	h, ok := m.HealthReport()
	if !ok {
		t.Fatal("health disabled")
	}
	for _, e := range h.Egress {
		if e.Name == "gone" {
			t.Fatal("deleted egress still in HealthReport")
		}
	}
	found := false
	for _, e := range h.Egress {
		if e.Name == "DIRECT" {
			found = true
		}
	}
	if !found {
		t.Fatal("DIRECT missing")
	}
}
