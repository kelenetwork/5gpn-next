package config

import "testing"

func TestListenPort(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{":20443", 20443},
		{"0.0.0.0:443", 443},
		{":80", 80},
		{"", 443},
		{":0", 443},
		{":abc", 443},
		{"20443", 443},
	}
	for _, tc := range cases {
		if got := ListenPort(tc.in); got != tc.want {
			t.Errorf("ListenPort(%q)=%d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestProfileDownloadURL(t *testing.T) {
	c := Default()
	c.Gateway.Host = "kfc.example.com"
	c.Gateway.Listen = ":20443"
	c.Gateway.ProfilePath = "/dl/aabbccddeeff/5gpn-next.mobileconfig"
	c.DNS.Enabled = true

	got := c.ProfileDownloadURL()
	want := "https://kfc.example.com:20443/dl/aabbccddeeff/5gpn-next.mobileconfig"
	if got != want {
		t.Fatalf("url=%q, want %q", got, want)
	}

	c.Gateway.Listen = ":443"
	got = c.ProfileDownloadURL()
	want = "https://kfc.example.com/dl/aabbccddeeff/5gpn-next.mobileconfig"
	if got != want {
		t.Fatalf("default https port url=%q, want %q", got, want)
	}

	c.Gateway.ProfilePath = "dl/x/5gpn-next.mobileconfig"
	got = c.ProfileDownloadURL()
	want = "https://kfc.example.com/dl/x/5gpn-next.mobileconfig"
	if got != want {
		t.Fatalf("missing slash url=%q, want %q", got, want)
	}

	c.DNS.Enabled = false
	if c.ProfileDownloadURL() != "" {
		t.Fatal("disabled dns must not expose profile url")
	}
	c.DNS.Enabled = true
	c.Gateway.Host = ""
	if c.ProfileDownloadURL() != "" {
		t.Fatal("empty host must not expose profile url")
	}
	if (*Config)(nil).ProfileDownloadURL() != "" {
		t.Fatal("nil config must not expose profile url")
	}
}
