package update

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func touchDir(t *testing.T, path string, mod time.Time, transaction bool) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if transaction {
		if err := os.WriteFile(filepath.Join(path, "transaction.sh"), []byte("#!/bin/bash\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStateRemovesLeaksButPreservesLiveTransaction(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 21, 15, 0, 0, 0, time.UTC)
	touchDir(t, filepath.Join(root, "update-old"), now.Add(-2*time.Hour), false)
	touchDir(t, filepath.Join(root, "update-fresh-old-style"), now, false)
	touchDir(t, filepath.Join(root, "update-live"), now, true)
	touchDir(t, filepath.Join(root, "unrelated"), now.Add(-24*time.Hour), false)

	versions := filepath.Join(root, "versions")
	if err := os.MkdirAll(versions, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"v0.9.4", "v0.10.0", "v0.13.8", "v0.13.9", "v0.13.10", "v0.13.11"} {
		if err := os.WriteFile(filepath.Join(versions, "5gpnd-"+tag), []byte(tag), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := cleanupState(root, now, 3); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"update-old", "update-fresh-old-style"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be removed, err=%v", name, err)
		}
	}
	for _, name := range []string{"update-live", "unrelated"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("%s should remain: %v", name, err)
		}
	}

	entries, err := os.ReadDir(versions)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("live transaction must preserve all fallback candidates, got %d", len(entries))
	}

	// 事务结束后的下一次启动才允许裁剪。
	if err := os.RemoveAll(filepath.Join(root, "update-live")); err != nil {
		t.Fatal(err)
	}
	if err := cleanupState(root, now, 3); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(versions)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{"5gpnd-v0.13.10", "5gpnd-v0.13.11", "5gpnd-v0.13.9"}
	if len(got) != len(want) {
		t.Fatalf("versions=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("versions=%v, want %v", got, want)
		}
	}
}

func TestPruneVersionsZeroRemovesAllBackups(t *testing.T) {
	dir := t.TempDir()
	for _, tag := range []string{"v1.0.0", "v1.1.0"} {
		if err := os.WriteFile(filepath.Join(dir, "5gpnd-"+tag), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneVersions(dir, 0); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries remain: %v", entries)
	}
}
