package quicfwd

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
)

func TestStatsActionUsesPolicyCategory(t *testing.T) {
	cases := []struct {
		in   policy.Action
		want string
	}{
		{policy.ActionDirect, "direct"},
		{policy.ActionProxy, "proxy"},
		{policy.ActionBlock, "block"},
	}
	for _, tc := range cases {
		if got := statsAction(tc.in); got != tc.want {
			t.Errorf("statsAction(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSessionReportsConnectionOnceAndTrafficIncrementally(t *testing.T) {
	var conns int
	var gotHost, gotAction string
	var gotFailed bool
	var up, down int64
	srv := &Server{
		sessions: map[string]*session{},
		OnConn: func(host, action string, failed bool) {
			conns++
			gotHost, gotAction, gotFailed = host, action, failed
		},
		OnTraffic: func(host string, u, d int64) {
			if host != "quic.example" {
				t.Errorf("traffic host=%q", host)
			}
			up += u
			down += d
		},
	}
	sc := &session{srv: srv, key: "client", host: "quic.example", action: "proxy"}
	srv.sessions[sc.key] = sc

	sc.reportTraffic(sc.host, 1200, 0)
	sc.reportTraffic(sc.host, 0, 800)
	sc.finish("", "", false)
	sc.finish("", "", false) // 幂等：不得重复计连接

	if conns != 1 || gotHost != "quic.example" || gotAction != "proxy" || gotFailed {
		t.Fatalf("connection callback count=%d host=%q action=%q failed=%v", conns, gotHost, gotAction, gotFailed)
	}
	if up != 1200 || down != 800 {
		t.Fatalf("traffic callbacks up/down=%d/%d, want 1200/800", up, down)
	}
}

func TestEstablishedSessionFinishDoesNotDoubleCount(t *testing.T) {
	conns := 0
	srv := &Server{
		sessions: map[string]*session{},
		OnConn:   func(string, string, bool) { conns++ },
	}
	sc := &session{
		srv:     srv,
		key:     "established",
		host:    "quic.example",
		action:  "direct",
		counted: true, // connect 已经立即上报过
	}
	srv.sessions[sc.key] = sc
	sc.finish("", "", false)
	if conns != 0 {
		t.Fatalf("finish duplicated an already reported connection: %d", conns)
	}
}

type sinkConn struct{}

func (sinkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (sinkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (sinkConn) Close() error                     { return nil }
func (sinkConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (sinkConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (sinkConn) SetDeadline(time.Time) error      { return nil }
func (sinkConn) SetReadDeadline(time.Time) error  { return nil }
func (sinkConn) SetWriteDeadline(time.Time) error { return nil }

func TestEstablishedDatagramReportsSuccessfulWriteImmediately(t *testing.T) {
	var gotHost string
	var gotUp, gotDown int64
	srv := &Server{OnTraffic: func(host string, up, down int64) {
		gotHost = host
		gotUp += up
		gotDown += down
	}}
	sc := &session{srv: srv, host: "play.example", remote: sinkConn{}}
	payload := make([]byte, 1200)

	sc.onDatagram(context.Background(), nil, payload)
	if gotHost != "play.example" || gotUp != 1200 || gotDown != 0 {
		t.Fatalf("traffic callback host=%q up/down=%d/%d", gotHost, gotUp, gotDown)
	}
	if sc.up.Load() != 1200 {
		t.Fatalf("session up=%d, want 1200", sc.up.Load())
	}
}

func TestSelectDialerUsesDirectForDirectPolicy(t *testing.T) {
	reg := egress.NewRegistry()
	d, ok := selectDialer(reg, policy.Decision{
		Action: policy.ActionDirect,
		Egress: "missing-proxy-must-be-ignored",
	})
	if !ok || d == nil || d.Name() != "DIRECT" {
		t.Fatalf("direct policy selected dialer=%v ok=%v", d, ok)
	}

	fallback, ok := selectDialer(reg, policy.Decision{
		Action: policy.ActionProxy,
		Egress: "missing-proxy",
	})
	if ok || fallback == nil || fallback.Name() != "DIRECT" {
		t.Fatalf("missing proxy should return DIRECT fallback with ok=false: dialer=%v ok=%v", fallback, ok)
	}
}
