package manage

import (
	"testing"

	"github.com/kelenetwork/5gpn-next/internal/config"
)

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"https://ipinfo.io/ip":                    "ipinfo.io",
		"http://user:pass@example.com:8080/p?q=1": "example.com:8080",
		"youtube.com":                             "youtube.com",
		"youtube.com:443":                         "youtube.com:443",
		"[2606:4700::1]:443":                      "[2606:4700::1]:443",
		"https://[2606:4700::1]/cdn-cgi/trace":    "[2606:4700::1]",
		"  chatgpt.com/  ":                        "chatgpt.com",
		"wss://example.org/socket":                "example.org",
	}
	for in, want := range cases {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDisplayOfDirectUsesKFCName(t *testing.T) {
	e := config.EgressConfig{Name: "DIRECT", Type: "direct"}
	if got, want := displayOf(e), "KFC 本机出口"; got != want {
		t.Fatalf("displayOf(DIRECT)=%q, want %q", got, want)
	}
}

func TestProfileDownloadURLFromManager(t *testing.T) {
	c := config.Default()
	c.Gateway.Host = "kfc.example.com"
	c.Gateway.Listen = ":20443"
	c.Gateway.ProfilePath = "/dl/aabbccddeeff/5gpn-next.mobileconfig"
	c.DNS.Enabled = true
	m := New("/tmp/unused.json", c, nil, nil)
	want := "https://kfc.example.com:20443/dl/aabbccddeeff/5gpn-next.mobileconfig"
	if got := m.ProfileDownloadURL(); got != want {
		t.Fatalf("url=%q, want %q", got, want)
	}
	c.DNS.Enabled = false
	if m.ProfileDownloadURL() != "" {
		t.Fatal("disabled dns must hide profile url")
	}
	if (*Manager)(nil).ProfileDownloadURL() != "" {
		t.Fatal("nil manager must hide profile url")
	}
}
