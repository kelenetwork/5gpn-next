package main

import (
	"net/netip"
	"testing"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/ruleset"
)

func readyEngine() *policy.Engine {
	e := policy.New()
	ds := ruleset.NewDomainSet()
	ds.AddRule("baidu.com")
	e.RegisterDomainSet("cn-domain", ds)
	cs := ruleset.NewCIDRSet()
	cs.AddRule("39.156.0.0/16")
	cs.Finalize()
	e.RegisterCIDRSet("geoip:cn", cs)
	return e
}

func target(t *testing.T, s string) policy.Target {
	t.Helper()
	got, err := policy.ParseTarget(s)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// 切换国外默认出口只改变 FINAL：自定义分流、国内域名和国内 IP
// 都必须保持原有决策，不得跟着 FINAL 一起切换。
func TestForeignEgressDoesNotOverrideRulesOrDomestic(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []string{
		"DOMAIN-SUFFIX,openai.com,proxy:special",
		"DOMAIN-SUFFIX,example.org,direct",
	}
	cfg.Final = "proxy:hinet"

	e := readyEngine()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		target string
		action policy.Action
		egress string
	}{
		{"国内域名仍直连", "www.baidu.com:443", policy.ActionDirect, ""},
		{"国内裸 IP 仍直连", "39.156.66.10:443", policy.ActionDirect, ""},
		{"自定义指定出口不变", "api.openai.com:443", policy.ActionProxy, "special"},
		{"自定义 DIRECT 不变", "www.example.org:443", policy.ActionDirect, ""},
		{"仅国外未命中流量走 hinet", "www.google.com:443", policy.ActionProxy, "hinet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Match(target(t, tc.target))
			if d.Action != tc.action || d.Egress != tc.egress {
				t.Fatalf("%s => action=%s egress=%q rule=%s; want %s %q",
					tc.target, d.Action, d.Egress, d.Rule, tc.action, tc.egress)
			}
		})
	}
}

func TestResolvedGeoIPKeepsCustomRulesFirst(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []string{
		"DOMAIN-SUFFIX,override.example,proxy:special",
	}
	cfg.Final = "proxy:hinet"

	e := readyEngine()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	cn := []netip.Addr{netip.MustParseAddr("39.156.66.10")}
	foreign := []netip.Addr{netip.MustParseAddr("142.250.72.36")}

	cases := []struct {
		name   string
		host   string
		addrs  []netip.Addr
		action policy.Action
		egress string
		rule   string
	}{
		{"未收录国内域名由 GEOIP 兜底", "unknown.example:443", cn, policy.ActionDirect, "", "GEOIP,cn"},
		{"自定义规则覆盖 GEOIP", "api.override.example:443", cn, policy.ActionProxy, "special", "DOMAIN-SUFFIX,override.example"},
		{"国外 IP 落到国外默认出口", "foreign.example:443", foreign, policy.ActionProxy, "hinet", "FINAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.MatchResolved(target(t, tc.host), tc.addrs)
			if d.Action != tc.action || d.Egress != tc.egress || d.Rule != tc.rule {
				t.Fatalf("got action=%s egress=%q rule=%q; want %s %q %q",
					d.Action, d.Egress, d.Rule, tc.action, tc.egress, tc.rule)
			}
		})
	}
}

// 国内规则缺失时宁可 DIRECT，也不能静默退化为全局代理。
func TestProxyFinalFallsBackDirectWhenDomesticRulesMissing(t *testing.T) {
	cfg := config.Default()
	cfg.Final = "proxy:hinet"
	e := policy.New()
	if err := applyRules(cfg, e); err != nil {
		t.Fatal(err)
	}
	d := e.Match(target(t, "www.google.com:443"))
	if d.Action != policy.ActionDirect {
		t.Fatalf("missing domestic rules must fail closed to DIRECT, got %s %q", d.Action, d.Egress)
	}
}
