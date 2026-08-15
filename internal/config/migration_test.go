package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyConfigMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{
  "relay": {
    "listen": ":20443",
    "host": "gateway.example.com",
    "cert_file": "/cert.pem",
    "key_file": "/key.pem",
    "token": "retired",
    "profile_path": "/dl/random/5gpn-next.mobileconfig"
  },
  "android": {
    "enabled": true,
    "dot_listen": ":853",
    "gateway_ip": "172.22.0.1",
    "http_listen": ":80",
    "tls_listen": ":443",
    "upstream": ["223.5.5.5:53"]
  },
  "location": {"enabled": true, "lat": 31.2, "lon": 121.4, "has_fix": true},
  "excluded_domains": ["example.cn"],
  "egress": [{"name": "DIRECT", "type": "direct"}],
  "rules": [],
  "final": "direct",
  "client_cidr": "172.22.0.0/16"
}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Host != "gateway.example.com" || cfg.Gateway.ProfilePath == "" {
		t.Fatalf("legacy relay was not mapped: %+v", cfg.Gateway)
	}
	if !cfg.DNS.Enabled || cfg.DNS.GatewayIP != "172.22.0.1" {
		t.Fatalf("legacy android was not mapped: %+v", cfg.DNS)
	}

	changed, err := MigrateLegacyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy file was not reported as changed")
	}

	var got map[string]json.RawMessage
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"relay", "android", "location", "excluded_domains"} {
		if _, ok := got[retired]; ok {
			t.Errorf("retired key %q survived migration", retired)
		}
	}
	for _, current := range []string{"gateway", "dns"} {
		if _, ok := got[current]; !ok {
			t.Errorf("current key %q missing after migration", current)
		}
	}

	changed, err = MigrateLegacyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("current config should migrate idempotently")
	}
}
