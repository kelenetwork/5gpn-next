package dot

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
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
