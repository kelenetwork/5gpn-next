package manage

import "testing"

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
