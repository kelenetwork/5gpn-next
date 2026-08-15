package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/manage"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/stats"
)

func testPanel(t *testing.T) (*Panel, *manage.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	mgr := manage.New(path, cfg, policy.New(), egress.NewRegistry())
	mgr.Traffic = stats.New(filepath.Join(dir, "traffic.json"))
	panel, err := New(mgr, "v-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return panel, mgr
}

func TestStatusExposesSuccessfulAdBlockRecords(t *testing.T) {
	panel, mgr := testPanel(t)
	mgr.Traffic.AdBlockSuccess("ads.example")
	mgr.Traffic.AdBlockSuccess("ads.example")

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	panel.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got manage.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AdBlock.Hits.Total != 2 || len(got.AdBlock.Hits.Recent) != 2 {
		t.Fatalf("unexpected ad-block status: %+v", got.AdBlock.Hits)
	}
}

func TestAdBlockAPIManagesAllowlist(t *testing.T) {
	panel, mgr := testPanel(t)
	h := panel.Handler()

	postJSON := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/adblock", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := postJSON(`{"action":"allow","domain":"safe.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("allow status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := mgr.AdAllowlist(); len(got) != 1 || got[0] != "safe.example" {
		t.Fatalf("unexpected allowlist: %v", got)
	}

	rec = postJSON(`{"action":"remove_allow","index":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := mgr.AdAllowlist(); len(got) != 0 {
		t.Fatalf("allowlist not removed: %v", got)
	}

	rec = postJSON(`{"action":"nope"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action status=%d, want 400", rec.Code)
	}
}

func TestLandingPageUsesCurrentProductCopy(t *testing.T) {
	panel, _ := testPanel(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	panel.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"广告拦截", "最近命中", "国外默认出口"} {
		if !strings.Contains(text, want) {
			t.Fatalf("landing page missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(text), "relay") {
		t.Fatal("landing page still contains retired relay wording")
	}
}
