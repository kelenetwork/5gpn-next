package config

import (
	"strings"
	"testing"
)

func TestBuiltinGoogleFix(t *testing.T) {
	rules := BuiltinGoogleFix()
	if len(rules) == 0 {
		t.Fatal("BuiltinGoogleFix 不应为空")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		parts := strings.Split(r, ",")
		if len(parts) != 3 {
			t.Fatalf("规则格式应为 类型,值,动作: %q", r)
		}
		if parts[0] != "DOMAIN-SUFFIX" {
			t.Fatalf("Google 修复规则应为 DOMAIN-SUFFIX: %q", r)
		}
		if parts[2] != "proxy" {
			t.Fatalf("动作必须是不带出口名的 proxy（运行时跟随默认出口）: %q", r)
		}
		if seen[parts[1]] {
			t.Fatalf("域名重复: %q", parts[1])
		}
		seen[parts[1]] = true
	}
	for _, must := range []string{"dl.google.com", "gvt1.com", "googleapis.com"} {
		if !seen[must] {
			t.Fatalf("缺少关键下载域名 %s", must)
		}
	}
}

func TestStripBuiltinRemovesGoogleFix(t *testing.T) {
	user := []string{
		"DOMAIN-SUFFIX,dl.google.com,proxy",
		"domain-suffix, gvt1.com ,PROXY",
		"DOMAIN-SUFFIX,openai.com,proxy:node",
	}
	out := stripBuiltin(user)
	if len(out) != 1 || out[0] != "DOMAIN-SUFFIX,openai.com,proxy:node" {
		t.Fatalf("与内置 Google 修复重复的用户规则应被剔除，got %v", out)
	}
}
