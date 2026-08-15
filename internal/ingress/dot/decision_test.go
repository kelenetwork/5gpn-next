package dot

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/kelenetwork/5gpn-next/internal/policy"
)

type decisionWriter struct {
	err error
	msg *dns.Msg
}

func (w *decisionWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 853}
}
func (w *decisionWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
}
func (w *decisionWriter) WriteMsg(m *dns.Msg) error {
	if w.err != nil {
		return w.err
	}
	w.msg = m.Copy()
	return nil
}
func (w *decisionWriter) Write([]byte) (int, error) { return 0, w.err }
func (w *decisionWriter) Close() error              { return nil }
func (w *decisionWriter) TsigStatus() error         { return nil }
func (w *decisionWriter) TsigTimersOnly(bool)       {}
func (w *decisionWriter) Hijack()                   {}

func TestWriteResponseReportsOnlySuccessfulResponses(t *testing.T) {
	var reports []string
	s := &Server{OnResponse: func(qname, action string) {
		reports = append(reports, qname+":"+action)
	}}
	m := new(dns.Msg)
	m.SetRcode(&dns.Msg{}, dns.RcodeNameError)

	failed := &decisionWriter{err: errors.New("client disconnected")}
	if s.writeResponse(failed, m, "ads.example", "block") {
		t.Fatal("writeResponse returned success for failed writer")
	}
	if len(reports) != 0 {
		t.Fatalf("failed response was counted: %v", reports)
	}

	ok := &decisionWriter{}
	if !s.writeResponse(ok, m, "ads.example", "block") {
		t.Fatal("writeResponse returned failure for successful writer")
	}
	if len(reports) != 1 || reports[0] != "ads.example:block" {
		t.Fatalf("successful response was not counted exactly once: %v", reports)
	}
	if ok.msg == nil || ok.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("unexpected DNS response: %+v", ok.msg)
	}
}

func TestBlockedQueryCountsDecisionAndSuccessfulResponseSeparately(t *testing.T) {
	eng := policy.New()
	if err := eng.AddRule(policy.Rule{
		Kind: policy.KindDomainSuffix, Value: "ads.example", Action: policy.ActionBlock,
	}); err != nil {
		t.Fatal(err)
	}

	cached := new(dns.Msg)
	cached.SetQuestion("ads.example.", dns.TypeA)
	cached.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ads.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("203.0.113.8").To4(),
	}}
	decisions, responses := 0, 0
	s := &Server{
		ClientCIDR: netip.MustParsePrefix("127.0.0.0/8"),
		Policy:     func() *policy.Engine { return eng },
		cache: map[string]cacheEntry{
			"ads.example|1": {msg: cached, expire: time.Now().Add(time.Minute)},
		},
		OnDecision: func(_, action string) {
			if action == "block" {
				decisions++
			}
		},
		OnResponse: func(_, action string) {
			if action == "block" {
				responses++
			}
		},
	}
	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)

	ok := &decisionWriter{}
	s.handle(ok, req)
	if decisions != 1 || responses != 1 || ok.msg == nil || ok.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("successful block: decisions=%d responses=%d msg=%+v", decisions, responses, ok.msg)
	}

	failed := &decisionWriter{err: errors.New("client disconnected")}
	s.handle(failed, req)
	if decisions != 2 || responses != 1 {
		t.Fatalf("failed delivery must remain decision-only: decisions=%d responses=%d", decisions, responses)
	}
}
