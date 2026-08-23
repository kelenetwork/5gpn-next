package qrcode

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodePNG(t *testing.T) {
	url := "https://kfc.example.com:20443/dl/aabbccddeeff/5gpn-next.mobileconfig"
	png, err := EncodePNG(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 200 {
		t.Fatalf("png too small: %d", len(png))
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("not a PNG")
	}
}

func TestEncodePNGRejectsEmpty(t *testing.T) {
	if _, err := EncodePNG(""); err == nil {
		t.Fatal("empty content must fail")
	}
	if _, err := EncodePNG(strings.Repeat("x", 3000)); err == nil {
		t.Fatal("oversized content must fail")
	}
}
