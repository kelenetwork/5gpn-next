// Package probe 提供端到端诊断：逐层判定并输出可读结论。
//
// 存在理由（P0 实测教训）：WhatsApp 商业版注册失败时，用户只看到
// "没有互联网连接"，真实原因是「出口无 IPv6 + 拨号超时过长」。
// 没有分层诊断，这类问题无法自助定位，全部变成售后成本。
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/trace"
)

// nonTLSSuffixes 列出已知不使用标准 TLS 的服务。
//
// WhatsApp 的聊天服务器在 443 上跑自研 Noise 握手，不是 TLS：
// 发送 ClientHello 会直接被 RST。若把这种情况报成失败，
// 会得到"WhatsApp 坏了"的假警报——P0 期间就踩过这个坑。
var nonTLSSuffixes = []string{
	"g.whatsapp.net",
	"e1.whatsapp.net",
	"e2.whatsapp.net",
	"e3.whatsapp.net",
	"e4.whatsapp.net",
	"e5.whatsapp.net",
	"e6.whatsapp.net",
	"e7.whatsapp.net",
	"e8.whatsapp.net",
	"e9.whatsapp.net",
	"e10.whatsapp.net",
	"e11.whatsapp.net",
	"e12.whatsapp.net",
	"e13.whatsapp.net",
	"e14.whatsapp.net",
	"e15.whatsapp.net",
	"e16.whatsapp.net",
}

// nonTLSPorts 列出通常不跑标准 TLS 的端口。
var nonTLSPorts = map[int]string{
	5222: "XMPP（推送通道）",
	5223: "XMPP over 私有 TLS",
	5228: "GMS/FCM 推送",
	5229: "GMS/FCM 推送",
	5230: "GMS/FCM 推送",
	80:   "明文 HTTP",
}

// Prober 执行诊断。
type Prober struct {
	Policy *policy.Engine
	Egress *egress.Registry
}

// Run 对目标做一次全链路诊断。target 形如 "chatgpt.com" 或 "chatgpt.com:443"。
func (p *Prober) Run(ctx context.Context, target string) *trace.Trace {
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}

	tr := trace.New("probe", target, "local")

	// [1] 入口
	tr.Step(trace.StageIngress, trace.StatusOK, "probe 本地发起（跳过 Relay 鉴权）")

	// [2] 策略
	t, _ := policy.ParseTarget(target)
	dec := p.Policy.MatchContext(ctx, t)
	kind := "域名"
	if t.IsIP() {
		kind = "裸 IP，按 IP/GEOIP 判定"
	} else if strings.HasPrefix(dec.Rule, "GEOIP,") || strings.HasPrefix(dec.Rule, "IP-CIDR,") {
		kind = "域名已解析为目标 IP，再按 IP/GEOIP 判定"
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
	switch {
	case dec.Action == policy.ActionDirect:
		d = p.Egress.Direct()
		tr.Step(trace.StageEgress, trace.StatusOK, "%s（IPv6 能力=%v）", d.Name(), d.HasIPv6())

	default:
		got, ok := p.Egress.Get(dec.Egress)
		d = got
		switch {
		case !ok:
			// 规则指名的出口不存在：这是配置错误，必须显式报出，
			// 不能静默退到直连让用户以为一切正常。
			tr.Fail(trace.StageEgress,
				fmt.Errorf("出口 %q 未在配置中定义", dec.Egress),
				"出口缺失，已回退 %s（请检查 egress 配置）", got.Name())
		case !p.Egress.HasProxy():
			// 策略要求走代理，但根本没配任何非直连出口。
			// 此时流量实际从网关本机出海，被墙目标必然失败。
			tr.Step(trace.StageEgress, trace.StatusWarn,
				"未配置任何代理出口，实际由 %s 本机直出", got.Name())
		default:
			tr.Step(trace.StageEgress, trace.StatusOK, "%s（IPv6 能力=%v）", d.Name(), d.HasIPv6())
		}
	}

	// [4] 连接
	dctx, cancel := context.WithTimeout(ctx, egress.DialTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", target)
	if err != nil {
		hint := "目标不可达"
		if errors.Is(err, egress.ErrNoIPv6) {
			hint = "出口无 IPv6，已快速失败以促使客户端回落 IPv4"
		} else if !p.Egress.HasProxy() && dec.Action == policy.ActionProxy {
			hint = "本机直出无法到达该目标；配置代理出口后应可恢复"
		}
		tr.Fail(trace.StageConnect, err, "TCP 拨号失败 —— %s", hint)
		return tr
	}
	defer conn.Close()
	tr.Step(trace.StageConnect, trace.StatusOK, "TCP %s 已建立", conn.RemoteAddr())

	// [5] 应用层
	p.checkAppLayer(ctx, tr, conn, t)
	return tr
}

// checkAppLayer 尽力校验应用层，但区分"真故障"与"非标准 TLS"。
func (p *Prober) checkAppLayer(ctx context.Context, tr *trace.Trace, conn net.Conn, t policy.Target) {
	if t.IsIP() {
		tr.Step(trace.StageApp, trace.StatusSkipped, "目标为裸 IP，无 SNI 可校验")
		return
	}
	if why, ok := nonTLSPorts[t.Port]; ok {
		tr.Step(trace.StageApp, trace.StatusSkipped, "端口 %d 通常为 %s，跳过 TLS 校验", t.Port, why)
		return
	}
	if isKnownNonTLS(t.Host) {
		tr.Step(trace.StageApp, trace.StatusSkipped,
			"%s 使用私有握手（非标准 TLS），TCP 可达即视为正常", t.Host)
		return
	}

	tc := tls.Client(conn, &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		// TCP 已经通了，只是握不上标准 TLS。这多半是私有协议或
		// 端口用途不同，不应等同于"网络不可用"。
		if isBenignTLSError(err) {
			tr.Step(trace.StageApp, trace.StatusWarn,
				"TCP 可达但非标准 TLS（私有协议或非 HTTPS 端口，通常正常）")
			return
		}
		tr.Fail(trace.StageApp, err, "TLS 握手失败 SNI=%s", t.Host)
		return
	}
	st := tc.ConnectionState()
	tr.Step(trace.StageApp, trace.StatusOK, "TLS %s ALPN=%s 证书校验通过",
		tlsVersionName(st.Version), orDefault(st.NegotiatedProtocol, "-"))
}

func isKnownNonTLS(host string) bool {
	h := strings.ToLower(host)
	for _, s := range nonTLSSuffixes {
		if h == s {
			return true
		}
	}
	return false
}

// isBenignTLSError 判断 TLS 失败是否属于"对端不说 TLS"而非真故障。
func isBenignTLSError(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false // 超时更像真不通
	}
	msg := err.Error()
	for _, s := range []string{
		"connection reset by peer",
		"unexpected EOF",
		"EOF",
		"first record does not look like a TLS handshake",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
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
