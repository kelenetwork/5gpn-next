package config

import (
	"strings"
	"testing"
)

func TestAdBlockDisabledProducesNothing(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = false
	if got := c.BuiltinAdBlock(); len(got) != 0 {
		t.Fatalf("disabled ad block must emit no rules, got %v", got)
	}
	// 关闭时也不应加载规则集，避免白占内存与带宽
	for _, rs := range c.EffectiveRuleSets() {
		if rs.Name == AdBlockRuleSetName {
			t.Fatal("disabled ad block must not load its ruleset")
		}
	}
}

func TestAdBlockEnabledEmitsRuleSetAndAllowlist(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = true
	c.AdBlock.Allowlist = []string{"good.example", ".dot-prefixed.example", "  spaced.example  "}

	rules := c.BuiltinAdBlock()
	if len(rules) != 4 {
		t.Fatalf("want 3 allow + 1 block, got %v", rules)
	}
	// 白名单必须全部排在 block 之前，否则永远不会命中
	blockIdx := -1
	for i, r := range rules {
		if strings.HasPrefix(r, "RULE-SET,") {
			blockIdx = i
		}
	}
	if blockIdx != len(rules)-1 {
		t.Fatalf("RULE-SET block must be last, got index %d in %v", blockIdx, rules)
	}
	for _, want := range []string{
		"DOMAIN-SUFFIX,good.example,direct",
		"DOMAIN-SUFFIX,dot-prefixed.example,direct",
		"DOMAIN-SUFFIX,spaced.example,direct",
		"RULE-SET," + AdBlockRuleSetName + ",block",
	} {
		found := false
		for _, r := range rules {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing rule %q in %v", want, rules)
		}
	}

	// 启用时必须自动补上规则集
	var got *RuleSetConfig
	for _, rs := range c.EffectiveRuleSets() {
		if rs.Name == AdBlockRuleSetName {
			r := rs
			got = &r
		}
	}
	if got == nil {
		t.Fatal("enabled ad block must add its ruleset")
	}
	if got.Kind != "domain" || got.URL != DefaultAdBlockURL {
		t.Fatalf("unexpected ruleset: %+v", *got)
	}
}

// 白名单里的脏数据不能污染规则串（逗号会破坏 TYPE,VALUE,ACTION 解析）
func TestAdBlockAllowlistRejectsMalformed(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = true
	c.AdBlock.Allowlist = []string{"", "  ", "bad,comma.example", "has space.example", "a/b.example"}

	rules := c.BuiltinAdBlock()
	if len(rules) != 1 {
		t.Fatalf("malformed entries must be dropped, got %v", rules)
	}
	if !strings.HasPrefix(rules[0], "RULE-SET,") {
		t.Fatalf("only the block rule should remain, got %v", rules)
	}
}

// 用户显式配置了同名规则集时以用户配置为准，不重复追加
func TestAdBlockRespectsExplicitRuleSet(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = true
	c.RuleSets = append(c.RuleSets, RuleSetConfig{
		Name: AdBlockRuleSetName, Kind: "domain", URL: "https://example.invalid/my.txt",
	})

	n := 0
	for _, rs := range c.EffectiveRuleSets() {
		if rs.Name == AdBlockRuleSetName {
			n++
			if rs.URL != "https://example.invalid/my.txt" {
				t.Errorf("user URL overridden: %s", rs.URL)
			}
		}
	}
	if n != 1 {
		t.Fatalf("ruleset duplicated %d times", n)
	}
}

func TestAdBlockCustomURL(t *testing.T) {
	c := Default()
	c.AdBlock.Enabled = true
	c.AdBlock.URL = "https://example.invalid/ads.txt"
	if got := c.AdBlockURLOrDefault(); got != "https://example.invalid/ads.txt" {
		t.Fatalf("custom URL ignored: %s", got)
	}
	c.AdBlock.URL = ""
	if got := c.AdBlockURLOrDefault(); got != DefaultAdBlockURL {
		t.Fatalf("default URL wrong: %s", got)
	}
}
