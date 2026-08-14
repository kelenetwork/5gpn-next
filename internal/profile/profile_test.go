package profile

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildIncludesPhoneSideDomesticBypass(t *testing.T) {
	if got := len(EffectiveExcludedDomains(nil)); got < 100 {
		t.Fatalf("builtin phone-side bypass list too small: %d", got)
	}

	o := Default("kfc.example.com", 20443)
	o.Token = "stable-token"
	o.ExcludedDomains = []string{"custom.example.cn", "douyin.com"}

	b, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	xml := string(b)
	for _, want := range []string{
		"<key>ExcludedDomains</key>",
		"<string>cn</string>",
		"<string>douyin.com</string>",
		"<string>douyinvod.com</string>",
		"<string>snssdk.com</string>",
		"<string>custom.example.cn</string>",
		"<string>stable-token</string>",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("profile missing %s", want)
		}
	}
	if got := strings.Count(xml, "<string>douyin.com</string>"); got != 1 {
		t.Fatalf("douyin.com should be deduplicated, got %d", got)
	}
	if len(b) > 64<<10 {
		t.Fatalf("profile unexpectedly large: %d bytes", len(b))
	}
}

func TestBuildKeepsStableIdentity(t *testing.T) {
	o := Default("kfc.example.com", 20443)
	o.Token = "same-token"
	first, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	second, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same host/token must produce byte-identical profile with stable UUIDs")
	}
}

func TestMatchDomainsTestModeDoesNotInjectExclusions(t *testing.T) {
	o := Default("kfc.example.com", 20443)
	o.MatchDomains = []string{"example.com"}
	b, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "<key>ExcludedDomains</key>") {
		t.Fatal("MatchDomains test mode must not inject production exclusions")
	}
}
