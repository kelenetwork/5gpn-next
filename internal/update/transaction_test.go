package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransactionScriptIsSyntacticallyValidAndContainsRealRollback(t *testing.T) {
	script := transactionScript(
		"/var/lib/5gpn-next/update-1/new binary",
		"/var/lib/5gpn-next/versions/5gpnd-v0.13.10",
		"v0.13.10", "v0.13.11",
		"/var/lib/5gpn-next/update-1",
	)
	path := filepath.Join(t.TempDir(), "transaction.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n failed: %v: %s", err, out)
	}
	for _, want := range []string{
		"systemctl restart 5gpn-next.service",
		"install_one \"$FALLBACK\"",
		"write_result rolled_back",
		"version_ok \"$TO\"",
		"sleep 5",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("transaction script missing %q", want)
		}
	}
}

func TestShellQuoteHandlesSingleQuote(t *testing.T) {
	got := shellQuote("/tmp/a'b")
	if got != `'/tmp/a'\''b'` {
		t.Fatalf("shellQuote=%q", got)
	}
	cmd := exec.Command("/bin/bash", "-c", "printf %s "+got)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "/tmp/a'b" {
		t.Fatalf("round trip=%q", out)
	}
}

func TestVersionsSortSemantically(t *testing.T) {
	// Comparator regression: lexical reverse incorrectly put v0.9 above v0.13.
	in := []string{"v0.9.4", "v0.13.9", "v0.10.0", "v0.13.10"}
	for i := 0; i < len(in); i++ {
		for j := i + 1; j < len(in); j++ {
			if Newer(in[j], in[i]) {
				in[i], in[j] = in[j], in[i]
			}
		}
	}
	want := []string{"v0.13.10", "v0.13.9", "v0.10.0", "v0.9.4"}
	for i := range want {
		if in[i] != want[i] {
			t.Fatalf("order=%v, want %v", in, want)
		}
	}
}
