package dot

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/kelenetwork/5gpn-next/internal/policy"
)

func TestAnswerAddrsAndCachedLookup(t *testing.T) {
	qname := "unknown.example."
	cached := new(dns.Msg)
	cached.SetQuestion(qname, dns.TypeA)
	cached.Id = 1
	cached.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("39.156.66.10").To4(),
	}}

	s := &Server{cache: map[string]cacheEntry{
		"unknown.example|1": {msg: cached, expire: time.Now().Add(time.Minute)},
	}}
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	req.Id = 4242

	resp, err := s.lookup(req, "unknown.example")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("cached response ID=%d, want %d", resp.Id, req.Id)
	}
	addrs := answerAddrs(resp)
	want := netip.MustParseAddr("39.156.66.10")
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("answerAddrs=%v, want [%s]", addrs, want)
	}
}

// FINAL 兜底的 direct（Index=-1）语义是“国外流量从网关本机出去”，
// 绝不能向手机返回真实 IP；否则国外域名会在国内蜂窝上直连失败
// （YouTube/TikTok 全挂的事故根因）。
func TestRealIPOnlyForExplicitDirectRules(t *testing.T) {
	cases := []struct {
		name string
		dec  policy.Decision
		want bool
	}{
		{"国内规则命中→真实 IP", policy.Decision{Action: policy.ActionDirect, Rule: "GEOIP,cn", Index: 6}, true},
		{"自定义 direct→真实 IP", policy.Decision{Action: policy.ActionDirect, Rule: "DOMAIN-SUFFIX,example.cn", Index: 0}, true},
		{"FINAL direct→改写到网关", policy.Decision{Action: policy.ActionDirect, Rule: "FINAL", Index: -1}, false},
		{"FINAL proxy→改写到网关", policy.Decision{Action: policy.ActionProxy, Egress: "hinet", Rule: "FINAL", Index: -1}, false},
		{"规则 proxy→改写到网关", policy.Decision{Action: policy.ActionProxy, Egress: "hinet", Rule: "DOMAIN-SUFFIX,openai.com", Index: 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := realIPForClient(tc.dec); got != tc.want {
				t.Fatalf("realIPForClient(%+v)=%v, want %v", tc.dec, got, tc.want)
			}
		})
	}
}
