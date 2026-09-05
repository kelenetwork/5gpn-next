package bot

import "testing"

func TestPageHeadAndCard(t *testing.T) {
	got := pageHead("📊", "运行总览")
	if got == "" || got[:1] == "━" {
		t.Fatalf("pageHead should not use ascii rules: %q", got)
	}
	if card("  a\nb  ") != "<blockquote>a\nb</blockquote>" {
		t.Fatalf("card=%q", card("  a\nb  "))
	}
	if btnHome().Data != "menu" || btnBack("egress").Data != "egress" {
		t.Fatal("nav buttons")
	}
}
