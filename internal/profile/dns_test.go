package profile

import (
	"bytes"
	"strings"
	"testing"
)

func TestDNSProfileCellularOnly(t *testing.T) {
	o := DefaultDNS("kfc.example.com")
	o.ServerAddresses = []string{"177.0.143.37"}
	b, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	xml := string(b)
	for _, want := range []string{
		"<string>com.apple.dnsSettings.managed</string>",
		"<key>DNSProtocol</key>",
		"<string>TLS</string>",
		"<key>ServerName</key>",
		"<string>kfc.example.com</string>",
		"<string>177.0.143.37</string>",
		"<key>OnDemandRules</key>",
		"<key>InterfaceTypeMatch</key>",
		"<string>Cellular</string>",
		"<string>Connect</string>",
		"<string>Disconnect</string>",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("dns profile missing %s", want)
		}
	}
	// 规则顺序必须是 Cellular Connect 在前、兜底 Disconnect 在后。
	if strings.Index(xml, "<string>Connect</string>") > strings.Index(xml, "<string>Disconnect</string>") {
		t.Fatal("OnDemandRules order broken: Connect must precede fallback Disconnect")
	}
	// DNS 模式不属于 Relay，不能包含 Relay 字段或国内域名排除名单。
	for _, banned := range []string{"HTTP2RelayURL", "ExcludedDomains", "RelayUUID"} {
		if strings.Contains(xml, banned) {
			t.Errorf("dns profile must not contain %s", banned)
		}
	}
}

func TestDNSProfileStableIdentity(t *testing.T) {
	o := DefaultDNS("kfc.example.com")
	first, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	second, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same host must produce byte-identical dns profile")
	}
	// 与 Relay 描述文件的 UUID/Identifier 必须不同，否则会互相顶掉。
	relay := Default("kfc.example.com", 20443)
	rb, err := relay.Build()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rb), o.ProfileIdentifier) {
		t.Fatal("dns profile identifier must differ from relay profile")
	}
}

func TestDNSProfileRequiresHost(t *testing.T) {
	if _, err := (DNSOptions{}).Build(); err == nil {
		t.Fatal("empty host must fail")
	}
}
