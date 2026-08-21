package trace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTrace(r *JSONLRecorder, i int) {
	t := New("id", "video.example.com:443", "172.22.1.2")
	t.Step(StageIngress, StatusOK, "entry-%d-%s", i, strings.Repeat("x", 80))
	r.Record(t)
}

func assertValidJSONL(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		lines++
		var x map[string]any
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			t.Fatalf("%s line %d is partial/invalid JSON: %v", path, lines, err)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if lines == 0 {
		t.Fatalf("%s has no JSON lines", path)
	}
}

func TestJSONLRecorderRotatesAndBoundsArchives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	const max = int64(900)
	r, err := NewJSONLRecorder(path, max, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		writeTrace(r, i)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing rotation file %s: %v", p, err)
		}
		if st.Size() > max {
			t.Fatalf("%s size=%d exceeds max=%d", p, st.Size(), max)
		}
		assertValidJSONL(t, p)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected archive beyond retention: %v", err)
	}
}

func TestJSONLRecorderReopensAfterTransientFileLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	r, err := NewJSONLRecorder(path, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟轮转中关闭成功、重新打开暂时失败后的状态。下一条记录必须
	// 主动重开，而不是因 f=nil 永久静默丢日志。
	r.mu.Lock()
	if err := r.f.Close(); err != nil {
		r.mu.Unlock()
		t.Fatal(err)
	}
	r.f = nil
	r.mu.Unlock()
	writeTrace(r, 1)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	assertValidJSONL(t, path)
}

func TestJSONLRecorderCompactsOversizedLegacyFileAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(`{"ts":"2026-08-21T00:00:00Z","id":"x","target":"example.com:443"}`)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	const max = int64(1024)
	r, err := NewJSONLRecorder(path, max, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > max {
		t.Fatalf("compacted archive size=%d exceeds max=%d", st.Size(), max)
	}
	assertValidJSONL(t, path+".1")
	if st, err := os.Stat(path); err != nil || st.Size() != 0 {
		t.Fatalf("new active file should be empty: stat=%v err=%v", st, err)
	}
}
