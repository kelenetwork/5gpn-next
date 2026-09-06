package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/ruleset"
)

func mustTarget(t *testing.T, s string) Target {
	t.Helper()
	tg, err := ParseTarget(s)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", s, err)
	}
	return tg
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := New()

	cn := ruleset.NewDomainSet()
	for _, d := range []string{"weibo.com", "qq.com", "douyin.com", "bilibili.com"} {
		cn.AddRule(d)
	}
	e.RegisterDomainSet("cn-domain", cn)

	geo := ruleset.NewCIDRSet()
	// 国内段样本
	for _, c := range []string{"223.5.5.0/24", "39.156.0.0/16", "180.101.49.0/24"} {
		geo.AddRule(c)
	}
	geo.Finalize()
	e.RegisterCIDRSet("geoip:cn", geo)

	rules := []Rule{
		{Kind: KindIPCIDR, Value: "10.0.0.0/8", Action: ActionDirect},
		{Kind: KindIPCIDR, Value: "192.168.0.0/16", Action: ActionDirect},
		{Kind: KindDomainSuffix, Value: "ads.example.com", Action: ActionBlock},
		{Kind: KindRuleSet, Value: "cn-domain", Action: ActionDirect},
		{Kind: KindGeoIP, Value: "cn", Action: ActionDirect},
		{Kind: KindDomainSuffix, Value: "openai.com", Action: ActionProxy, Egress: "us-1"},
	}
	for _, r := range rules {
		if err := e.AddRule(r); err != nil {
			t.Fatalf("AddRule %v: %v", r, err)
		}
	}
	e.SetFinal(ActionProxy, "")
	return e
}

func TestMatchDomainRules(t *testing.T) {
	e := newTestEngine(t)

	cases := []struct {
		target string
		want   Action
		egress string
		why    string
	}{
		{"weibo.com:443", ActionDirect, "", "国内域名应直连"},
		{"api.weibo.com:443", ActionDirect, "", "国内域名的子域应直连"},
		{"douyin.com:443", ActionDirect, "", "抖音应直连"},
		{"chatgpt.com:443", ActionProxy, "", "未命中规则应走 FINAL 代理"},
		{"openai.com:443", ActionProxy, "us-1", "显式规则应选中指定出口"},
		{"chat.openai.com:443", ActionProxy, "us-1", "子域应继承后缀规则"},
		{"ads.example.com:443", ActionBlock, "", "拦截规则应生效"},
		{"tracker.ads.example.com:80", ActionBlock, "", "拦截规则应覆盖子域"},
	}
	for _, c := range cases {
		got := e.Match(mustTarget(t, c.target))
		if got.Action != c.want {
			t.Errorf("%s: %s → 期望 %s，实际 %s（命中 %s）",
				c.target, c.why, c.want, got.Action, got.Rule)
		}
		if c.egress != "" && got.Egress != c.egress {
			t.Errorf("%s: 期望出口 %s，实际 %s", c.target, c.egress, got.Egress)
		}
	}
}

// TestMatchBareIP 覆盖裸 IP 目标的硬约束：这类流量没有域名可匹配，
// 必须靠 GEOIP 判定。
func TestMatchBareIP(t *testing.T) {
	e := newTestEngine(t)

	cases := []struct {
		target string
		want   Action
		why    string
	}{
		{"223.5.5.5:443", ActionDirect, "国内 IP 应直连"},
		{"39.156.66.10:443", ActionDirect, "国内 IP 段应直连"},
		{"104.244.46.185:443", ActionProxy, "境外裸 IP 应走代理"},
		{"10.1.2.3:22", ActionDirect, "私有地址不得出网关"},
		{"192.168.1.1:80", ActionDirect, "私有地址不得出网关"},
	}
	for _, c := range cases {
		tg := mustTarget(t, c.target)
		if !tg.IsIP() {
			t.Fatalf("%s 应被识别为裸 IP", c.target)
		}
		got := e.Match(tg)
		if got.Action != c.want {
			t.Errorf("%s: %s → 期望 %s，实际 %s（命中 %s）",
				c.target, c.why, c.want, got.Action, got.Rule)
		}
	}
}

func TestRuleOrderFirstMatch(t *testing.T) {
	e := New()
	_ = e.AddRule(Rule{Kind: KindDomainSuffix, Value: "example.com", Action: ActionDirect})
	_ = e.AddRule(Rule{Kind: KindDomainSuffix, Value: "example.com", Action: ActionBlock})
	e.SetFinal(ActionProxy, "")

	got := e.Match(mustTarget(t, "example.com:443"))
	if got.Action != ActionDirect {
		t.Errorf("first-match 语义被破坏：期望 direct，实际 %s", got.Action)
	}
	if got.Index != 0 {
		t.Errorf("期望命中第 0 条，实际第 %d 条", got.Index)
	}
}

func TestParseTargetIPv6(t *testing.T) {
	tg := mustTarget(t, "[2a03:2880:f10d:183:face:b00c:0:25de]:443")
	if !tg.IsIP() {
		t.Fatal("IPv6 字面量应被识别为 IP")
	}
	if !tg.Addr().Is6() {
		t.Fatal("应识别为 IPv6")
	}
	if tg.Port != 443 {
		t.Errorf("端口解析错误: %d", tg.Port)
	}
}

func TestParseTargetWithoutPort(t *testing.T) {
	tg := mustTarget(t, "example.com")
	if tg.Host != "example.com" {
		t.Errorf("主机解析错误: %s", tg.Host)
	}
	if tg.Port != 443 {
		t.Errorf("应回退到 443，实际 %d", tg.Port)
	}
}

func TestResolveSaturationFallsBackImmediately(t *testing.T) {
	e := New()
	for i := 0; i < cap(e.resolveSlots); i++ {
		e.resolveSlots <- struct{}{}
	}
	start := time.Now()
	if got := e.resolve(context.Background(), "would-block.invalid"); got != nil {
		t.Fatalf("saturated resolver should return nil, got %v", got)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("saturated resolver blocked for %s", elapsed)
	}
}

func TestResolveCacheIsBounded(t *testing.T) {
	e := New()
	past := time.Now().Add(-time.Minute)
	for i := 0; i < 4096; i++ {
		e.resolveCache[fmt.Sprintf("expired-%d.example", i)] = resolveEntry{expire: past}
	}
	got := e.resolve(context.Background(), "localhost")
	if len(got) == 0 {
		t.Fatal("localhost should resolve")
	}
	if n := len(e.resolveCache); n >= 4096 {
		t.Fatalf("resolver cache was not pruned: %d", n)
	}
}
