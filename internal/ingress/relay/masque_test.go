package relay

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestParseMasqueUDPPath(t *testing.T) {
	cases := map[string]string{
		"/.well-known/masque/udp/142.250.72.36/443/":         "142.250.72.36:443",
		"/.well-known/masque/udp/example.com/8443/":          "example.com:8443",
		"/.well-known/masque/udp/2606%3A4700%3A%3A1111/443/": "[2606:4700::1111]:443",
	}
	for in, want := range cases {
		got, err := parseMasqueUDPPath(in)
		if err != nil {
			t.Fatalf("parseMasqueUDPPath(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseMasqueUDPPath(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"/", "/.well-known/masque/udp/", "/.well-known/masque/udp/host/"} {
		if _, err := parseMasqueUDPPath(bad); err == nil {
			t.Errorf("parseMasqueUDPPath(%q) should fail", bad)
		}
	}
}

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1 << 29, 1 << 31} {
		b := appendVarint(nil, v)
		got, err := readVarint(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			t.Fatalf("readVarint(%d): %v", v, err)
		}
		if got != v {
			t.Errorf("varint round trip %d -> %d", v, got)
		}
		got2, n, err := parseVarintPrefix(b)
		if err != nil || got2 != v || n != len(b) {
			t.Errorf("parseVarintPrefix(%d) = %d,%d,%v", v, got2, n, err)
		}
	}
}

// capsule 必须是 type(0) + length + [ContextID(0) + payload]
func TestBuildDatagramCapsule(t *testing.T) {
	payload := []byte("quic-initial")
	c := buildDatagramCapsule(payload)

	br := bufio.NewReader(bytes.NewReader(c))
	typ, err := readVarint(br)
	if err != nil || typ != 0 {
		t.Fatalf("capsule type = %d, %v; want 0", typ, err)
	}
	length, err := readVarint(br)
	if err != nil {
		t.Fatal(err)
	}
	inner := make([]byte, length)
	if _, err := br.Read(inner); err != nil {
		t.Fatal(err)
	}
	ctxID, n, err := parseVarintPrefix(inner)
	if err != nil || ctxID != 0 {
		t.Fatalf("context id = %d, %v; want 0", ctxID, err)
	}
	if !bytes.Equal(inner[n:], payload) {
		t.Fatalf("payload = %q, want %q", inner[n:], payload)
	}
	if br.Buffered() != 0 {
		t.Fatal("capsule length mismatch: trailing bytes")
	}
}

func TestParseMasqueUDPPathRejectsTraversal(t *testing.T) {
	if got, err := parseMasqueUDPPath("/.well-known/masque/udp/..%2Fetc/443/"); err == nil {
		if strings.Contains(got, "/") {
			t.Fatalf("path traversal leaked into host: %q", got)
		}
	}
}
