package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/manage"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/stats"
	"github.com/w0ven/5gpn-next/internal/trace"
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

func TestAPIRejectsCrossSiteAndNonJSONWrites(t *testing.T) {
	panel, mgr := testPanel(t)
	h := panel.Handler()

	cross := httptest.NewRequest(http.MethodPost, "https://gateway.example/api/adblock",
		bytes.NewBufferString(`{"action":"allow","domain":"evil.example"}`))
	cross.Host = "gateway.example"
	cross.Header.Set("Content-Type", "application/json")
	cross.Header.Set("Origin", "https://evil.example")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	crossRec := httptest.NewRecorder()
	h.ServeHTTP(crossRec, cross)
	if crossRec.Code != http.StatusForbidden {
		t.Fatalf("cross-site status=%d, want 403", crossRec.Code)
	}

	plain := httptest.NewRequest(http.MethodPost, "https://gateway.example/api/adblock",
		strings.NewReader(`{"action":"allow","domain":"evil.example"}`))
	plain.Host = "gateway.example"
	plain.Header.Set("Content-Type", "text/plain")
	plainRec := httptest.NewRecorder()
	h.ServeHTTP(plainRec, plain)
	if plainRec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("plain write status=%d, want 415", plainRec.Code)
	}
	if got := mgr.AdAllowlist(); len(got) != 0 {
		t.Fatalf("rejected writes mutated allowlist: %v", got)
	}
}

func TestAPIAcceptsSameOriginJSONWrite(t *testing.T) {
	panel, mgr := testPanel(t)
	req := httptest.NewRequest(http.MethodPost, "https://gateway.example/api/adblock",
		bytes.NewBufferString(`{"action":"allow","domain":"safe.example"}`))
	req.Host = "gateway.example"
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Origin", "https://gateway.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	panel.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := mgr.AdAllowlist(); len(got) != 1 || got[0] != "safe.example" {
		t.Fatalf("same-origin write not applied: %v", got)
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

func stubOKTrace(target string) *trace.Trace {
	tr := trace.New("test", target, "")
	tr.Step(trace.StageConnect, trace.StatusOK, "ok")
	return tr
}

func TestProbeRejectsWhenTooFrequent(t *testing.T) {
	panel, _ := testPanel(t)
	var calls atomic.Int32
	panel.probeFn = func(ctx context.Context, target string) *trace.Trace {
		calls.Add(1)
		return stubOKTrace(target)
	}
	h := panel.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first probe status=%d body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second probe status=%d, want 429 body=%s", rec2.Code, rec2.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("rate-limited request still probed: calls=%d", calls.Load())
	}
}

func TestProbeAllowsAfterInterval(t *testing.T) {
	panel, _ := testPanel(t)
	panel.probeMinInterval = 20 * time.Millisecond
	var calls atomic.Int32
	panel.probeFn = func(ctx context.Context, target string) *trace.Trace {
		calls.Add(1)
		return stubOKTrace(target)
	}
	h := panel.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first probe status=%d body=%s", rec.Code, rec.Body.String())
	}
	time.Sleep(30 * time.Millisecond)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("second probe status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

func TestProbeRejectsWhenOverConcurrent(t *testing.T) {
	panel, _ := testPanel(t)
	panel.probeMinInterval = -1
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	panel.probeFn = func(ctx context.Context, target string) *trace.Trace {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return stubOKTrace(target)
	}
	h := panel.Handler()

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("in-flight probe status=%d body=%s", rec.Code, rec.Body.String())
			}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("in-flight probes did not start")
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/probe?target=example.test", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third probe status=%d, want 429 body=%s", rec.Code, rec.Body.String())
	}
	close(release)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("over-limit request still probed: calls=%d", calls.Load())
	}
}
