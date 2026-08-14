// Package probe 提供端到端诊断：逐层判定并输出可读结论。
//
// 存在理由（P0 实测教训）：WhatsApp 商业版注册失败时，用户只看到
// "没有互联网连接"，真实原因是「出口无 IPv6 + 拨号超时过长」。
// 没有分层诊断，这类问题无法自助定位，全部变成售后成本。
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/trace"
)

// Prober 执行诊断。
type Prober struct {
	Policy *policy.Engine
	Egress *egress.Registry
}

// Run 对目标做一次全链路诊断。target 形如 "chatgpt.com" 或 "chatgpt.com:443"。
func (p *Prober) Run(ctx context.Context, target string) *trace.Trace {
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	tr := trace.New("probe", target, "local")

	// [1] 入口
	tr.Step(trace.StageIngress, trace.StatusOK, "probe 本地发起（跳过 Relay 鉴权）")

	// [2] 策略
	t, _ := policy.ParseTarget(target)
	dec := p.Policy.Match(t)
	kind := "域名"
	if t.IsIP() {
		kind = "裸 IP（无域名，按 GEOIP 判定）"
	}
	switch dec.Action {
	case policy.ActionBlock:
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s [%s] → 拦截", dec.Rule, kind)
		tr.Step(trace.StageEgress, trace.StatusSkipped, "策略为拦截，不建立连接")
		return tr
	case policy.ActionDirect:
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s [%s] → 直连", dec.Rule, kind)
	default:
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s [%s] → 代理:%s",
			dec.Rule, kind, orDefault(dec.Egress, "默认"))
	}

	// [3] 出口
	var d egress.Dialer
	if dec.Action == policy.ActionDirect {
		d = p.Egress.Direct()
	} else {
		got, ok := p.Egress.Get(dec.Egress)
		if !ok {
			tr.Fail(trace.StageEgress, fmt.Errorf("出口 %q 未配置", dec.Egress),
				"出口缺失，回退 %s", got.Name())
		}
		d = got
	}
	tr.Step(trace.StageEgress, trace.StatusOK, "%s（IPv6 能力=%v）", d.Name(), d.HasIPv6())

	// [4] 连接
	dctx, cancel := context.WithTimeout(ctx, egress.DialTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", target)
	if err != nil {
		tr.Fail(trace.StageConnect, err, "TCP 拨号失败")
		return tr
	}
	defer conn.Close()
	tr.Step(trace.StageConnect, trace.StatusOK, "TCP %s 已建立", conn.RemoteAddr())

	// [5] 应用层：TLS 握手
	host, _, _ := net.SplitHostPort(target)
	if net.ParseIP(host) != nil {
		tr.Step(trace.StageApp, trace.StatusSkipped, "目标为 IP，跳过 TLS SNI 校验")
		return tr
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		tr.Fail(trace.StageApp, err, "TLS 握手失败 SNI=%s", host)
		return tr
	}
	st := tc.ConnectionState()
	tr.Step(trace.StageApp, trace.StatusOK, "TLS %s ALPN=%s 证书校验通过",
		tlsVersionName(st.Version), orDefault(st.NegotiatedProtocol, "-"))
	return tr
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
