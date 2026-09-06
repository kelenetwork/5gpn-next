package manage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/w0ven/5gpn-next/internal/config"
	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/ruleset"
)

func TestSetAdBlockRetriesWhenEnabledButRuntimeIsEmpty(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "ads.list")
	if err := os.WriteFile(rulesPath, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	cfg.RuleSets = append(cfg.RuleSets, config.RuleSetConfig{
		Name: config.AdBlockRuleSetName,
		Kind: "domain",
		Path: rulesPath,
	})
	m := New(filepath.Join(dir, "config.json"), cfg, policy.New(), egress.NewRegistry())

	reloads := 0
	m.Reload = func() (*policy.Engine, *egress.Registry, error) {
		reloads++
		ds, err := ruleset.LoadDomainFile(rulesPath)
		if err != nil {
			return nil, nil, err
		}
		eng := policy.New()
		eng.RegisterDomainSet(config.AdBlockRuleSetName, ds)
		if err := eng.AddRule(policy.Rule{
			Kind:   policy.KindRuleSet,
			Value:  config.AdBlockRuleSetName,
			Action: policy.ActionBlock,
		}); err != nil {
			return nil, nil, err
		}
		return eng, egress.NewRegistry(), nil
	}

	msg, err := m.SetAdBlock(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 retry", reloads)
	}
	if got := m.adBlockDomains(); got != 1 {
		t.Fatalf("loaded domains=%d, want 1", got)
	}
	if !strings.Contains(msg, "已载入 1 条") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestEffectiveRuleSetsIncludesImplicitAdBlock(t *testing.T) {
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	m := New("", cfg, policy.New(), egress.NewRegistry())

	found := false
	for _, rs := range m.EffectiveRuleSets() {
		if rs.Name == config.AdBlockRuleSetName {
			found = true
			if rs.URL != config.DefaultAdBlockURL {
				t.Fatalf("unexpected ad-block URL: %q", rs.URL)
			}
		}
	}
	if !found {
		t.Fatal("implicit ad-block ruleset missing from refresh list")
	}
}

func TestAllowAdAcceptsURLAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	m := New(path, cfg, policy.New(), egress.NewRegistry())
	if err := m.AllowAd("https://Ads.Example.com/tracker?x=1"); err != nil {
		t.Fatal(err)
	}
	got := m.AdAllowlist()
	if len(got) != 1 || got[0] != "ads.example.com" {
		t.Fatalf("allowlist=%v", got)
	}
	if err := m.AllowAd("ADS.EXAMPLE.COM"); err != nil {
		t.Fatal(err)
	}
	if len(m.AdAllowlist()) != 1 {
		t.Fatal("duplicate allow should be idempotent")
	}
	if err := m.AllowAd("https://bad,comma.example"); err == nil {
		t.Fatal("malformed domain must fail")
	}
}
