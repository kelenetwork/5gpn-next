package fw

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanPortsDeduplicatesAndRejectsInvalid(t *testing.T) {
	got := cleanPorts([]int{443, 80, 443, 0, -1, 65536, 853})
	want := []int{80, 443, 853}
	if len(got) != len(want) {
		t.Fatalf("ports=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports=%v, want %v", got, want)
		}
	}
}

func TestEnsureIngressRestrictionsMigratesLegacyAllowOnlyRules(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
if [ "$1" = "-a" ]; then
cat <<'EOF'
table inet fgpn {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    ip saddr 172.22.0.0/16 tcp dport 20443 accept comment "5gpn-next" # handle 2
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 443, 853 } accept comment "5gpn-android" # handle 4
    ip saddr 172.22.0.0/16 udp dport 443 accept comment "5gpn-quic-takeover" # handle 7
  }
}
EOF
exit 0
fi
printf '%s\n' "$*" >> "$NFT_TEST_LOG"
`
	fake := filepath.Join(dir, "nft")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Setenv("NFT_TEST_LOG", logPath)

	changed, err := EnsureIngressRestrictions(context.Background(), "172.22.0.0/16",
		[]int{20443, 80, 443, 853}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy allow-only rules should receive public drop rules")
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(b)
	for _, port := range []string{"80", "443", "853", "20443"} {
		if !strings.Contains(calls, "tcp dport "+port+" drop") {
			t.Fatalf("missing tcp/%s drop in calls:\n%s", port, calls)
		}
	}
	if !strings.Contains(calls, "udp dport 443 drop") {
		t.Fatalf("missing udp/443 drop in calls:\n%s", calls)
	}
	if strings.Contains(calls, " accept ") {
		t.Fatalf("legacy client allows should not be duplicated:\n%s", calls)
	}
}
