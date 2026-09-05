package node

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseSSPlainSIP002(t *testing.T) {
	n, err := Parse("ss://aes-256-gcm:p%40ss@127.0.0.1:8388#demo")
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "ss" || n.Server != "127.0.0.1" || n.Port != 8388 {
		t.Fatalf("ss host: %+v", n)
	}
	if n.Cipher != "aes-256-gcm" || n.Password != "p@ss" {
		t.Fatalf("ss creds cipher=%q pass=%q", n.Cipher, n.Password)
	}
	if n.Name != "demo" || !n.UDP {
		t.Fatalf("ss meta name=%q udp=%v", n.Name, n.UDP)
	}
}

func TestParseSSLegacyBase64(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:oldpass@127.0.0.1:8388"))
	n, err := Parse("ss://" + body + "#legacy")
	if err != nil {
		t.Fatal(err)
	}
	if n.Cipher != "aes-256-gcm" || n.Password != "oldpass" || n.Server != "127.0.0.1" || n.Port != 8388 {
		t.Fatalf("legacy ss: %+v", n)
	}
}

func TestParseSSPluginRejected(t *testing.T) {
	_, err := Parse("ss://aes-256-gcm:password@127.0.0.1:8388?plugin=obfs-local#x")
	if err == nil || !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("plugin should be rejected, err=%v", err)
	}
}

func TestParseVLESS(t *testing.T) {
	raw := "vless://11111111-1111-1111-1111-111111111111@example.test:443?type=ws&security=tls&sni=example.test&path=/vless&host=example.test#vless-demo"
	n, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "vless" || n.UUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("vless identity: %+v", n)
	}
	if n.Server != "example.test" || n.Port != 443 || n.Network != "ws" {
		t.Fatalf("vless endpoint: %+v", n)
	}
	if !n.TLS || n.SNI != "example.test" {
		t.Fatalf("vless tls: %+v", n)
	}
}

func TestParseTrojan(t *testing.T) {
	n, err := Parse("trojan://secret@example.test:443?sni=example.test#trojan-demo")
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "trojan" || n.Password != "secret" || n.Server != "example.test" || n.Port != 443 {
		t.Fatalf("trojan: %+v", n)
	}
	if !n.TLS {
		t.Fatal("trojan should default to TLS")
	}
}

func TestParseHysteria2DefaultPort(t *testing.T) {
	for _, raw := range []string{
		"hysteria2://secret@example.test?sni=example.test#hy2",
		"hy2://secret@example.test?sni=example.test#hy2",
	} {
		n, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if n.Type != "hysteria2" || n.Password != "secret" || n.Port != 443 {
			t.Fatalf("%s => %+v", raw, n)
		}
	}
}

func TestParseVMessJSON(t *testing.T) {
	payload := `{"ps":"vmess-demo","add":"example.test","port":443,"id":"11111111-1111-1111-1111-111111111111","aid":0,"scy":"auto","net":"tcp","tls":"tls","sni":"example.test"}`
	raw := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	n, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "vmess" || n.Server != "example.test" || n.Port != 443 {
		t.Fatalf("vmess endpoint: %+v", n)
	}
	if n.UUID != "11111111-1111-1111-1111-111111111111" || !n.TLS {
		t.Fatalf("vmess identity: %+v", n)
	}
}

func TestParseSocks5(t *testing.T) {
	n, err := Parse("socks5://user:pass@127.0.0.1:1080#socks")
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "socks5" || n.Server != "127.0.0.1" || n.Port != 1080 {
		t.Fatalf("socks5: %+v", n)
	}
	if n.Username != "user" || n.Password != "pass" || !n.UDP {
		t.Fatalf("socks5 creds: %+v", n)
	}
}

func TestParseRejectsEmptyUnknownAndMissingScheme(t *testing.T) {
	cases := []string{"", "   ", "example.test:443", "ftp://example.test:21"}
	for _, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) should fail", raw)
		}
	}
}

func TestMihomoConfigSSSmoke(t *testing.T) {
	n, err := Parse("ss://aes-256-gcm:pass%3Aword@127.0.0.1:8388#demo")
	if err != nil {
		t.Fatal(err)
	}
	yaml, err := n.MihomoConfig(7891)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"socks-port: 7891",
		`name: "node"`,
		"type: ss",
		`password: "pass:word"`,
		"mode: rule",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("yaml missing %q:\n%s", want, yaml)
		}
	}
}
