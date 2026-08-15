// Package dot 实现 iOS/Android 加密 DNS 接入：DNS over TLS + A 记录改写。
//
// 系统加密 DNS 入口拿不到应用层目的地，因此这里采用：
//
//	国内域名  → 返回真实 IP，手机直连
//	代理域名  → A 记录改写为网关自身 IP，流量因此回到网关，
//	            再由 sniff 包嗅探 SNI/Host 还原目的地
//
// 安全边界：只对配置的客户端网段改写。其它来源按普通递归 DNS 处理，
// 避免把网关变成开放的污染型解析器。
package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/kelenetwork/5gpn-next/internal/policy"
)

// Server 是 DoT 服务端。
type Server struct {
	// Listen 通常为 ":853"
	Listen string
	// GatewayIP 是改写后返回给客户端的地址
	GatewayIP netip.Addr
	// ClientCIDR 限定哪些来源启用改写
	ClientCIDR netip.Prefix
	// Upstream 是上游解析器，形如 "223.5.5.5:53"
	Upstream []string
	// TLS 证书
	CertFile, KeyFile string

	// Policy 用于判断域名该直连还是走代理
	Policy func() *policy.Engine

	// OnDecision 记录策略判定分布（可为空）；为兼容既有统计，响应写入失败
	// 或 direct 上游解析失败时仍会记录判定。
	OnDecision func(qname, action string)

	// OnResponse 仅在 DNS 响应成功写回客户端后调用（可为空）。
	// 广告“成功拦截”必须使用这个回调，不能把规则命中误当成交付成功。
	OnResponse func(qname, action string)

	// OnRewrite 在 A 记录被改写到网关时回调（client 为客户端 IP）。
	// 供 sniff 在无 SNI 协议上做“DNS 线索回退”还原目的地（可为空）。
	OnRewrite func(client, qname string)

	client   *dns.Client
	cacheMu  sync.RWMutex
	cache    map[string]cacheEntry
	stopOnce sync.Once
	srvTCP   *dns.Server
}

type cacheEntry struct {
	msg    *dns.Msg
	expire time.Time
}

// ListenAndServe 启动 DoT 监听。
func (s *Server) ListenAndServe(ctx context.Context) error {
	if !s.GatewayIP.IsValid() {
		return fmt.Errorf("网关 IP 无效，无法启用 DoT")
	}
	if len(s.Upstream) == 0 {
		s.Upstream = []string{"223.5.5.5:53", "119.29.29.29:53"}
	}
	s.cache = make(map[string]cacheEntry)
	s.client = &dns.Client{Net: "udp", Timeout: 4 * time.Second}

	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return fmt.Errorf("DoT 加载证书失败: %w", err)
	}

	s.srvTCP = &dns.Server{
		Addr: s.Listen,
		Net:  "tcp-tls",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: dns.HandlerFunc(s.handle),
	}

	go func() {
		<-ctx.Done()
		s.stopOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.srvTCP.ShutdownContext(shutdownCtx)
		})
	}()

	go s.gcLoop(ctx)

	log.Printf("DoT 已启动 listen=%s 网关IP=%s 客户端网段=%s",
		s.Listen, s.GatewayIP, s.ClientCIDR)
	return s.srvTCP.ListenAndServe()
}

func (s *Server) gcLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			s.cacheMu.Lock()
			for k, v := range s.cache {
				if now.After(v.expire) {
					delete(s.cache, k)
				}
			}
			s.cacheMu.Unlock()
		}
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}
	q := req.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	fromClient := s.isClient(w.RemoteAddr())

	// AAAA / HTTPS / SVCB：对客户端一律返回 NODATA。
	//
	// 网关数据面为 IPv4-only。若放行 AAAA，客户端会拿到源站真实 IPv6
	// 并与改写后的 IPv4 竞速，一旦 IPv6 侧先完成握手就不会再回退，
	// 而网关无法接管那条连接。代价是只发布 AAAA 的站点不可达，
	// 这是明确接受的取舍。
	if fromClient && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeHTTPS || q.Qtype == dns.TypeSVCB) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		_ = w.WriteMsg(m)
		return
	}

	// 非客户端来源：普通转发，不做任何改写
	if !fromClient {
		s.forwardAndWrite(w, req, false, qname)
		return
	}

	if q.Qtype != dns.TypeA {
		s.forwardAndWrite(w, req, false, qname)
		return
	}

	// 先向国内 DNS 上游解析真实 A 记录，再把目标 IP 交给 GEOIP。
	// 这样不在 cn-domain 列表里的国内域名也能返回真实 IP，让 Android
	// 手机本地直连；自定义域名规则仍按原顺序优先于内置 GEOIP。
	tgt, _ := policy.ParseTarget(net.JoinHostPort(qname, "443"))
	resolved, resolveErr := s.lookup(req, qname)
	dec := s.Policy().Match(tgt)
	if resolved != nil {
		dec = s.Policy().MatchResolved(tgt, answerAddrs(resolved))
	}

	if dec.Action == policy.ActionBlock {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		s.writeResponse(w, m, qname, "block")
		s.report(qname, "block")
		return
	}

	if realIPForClient(dec) {
		if resolveErr != nil || resolved == nil {
			dns.HandleFailed(w, req)
		} else {
			s.writeResponse(w, resolved, qname, "direct")
		}
		s.report(qname, "direct")
		return
	}

	// 其余（proxy 或 FINAL 兜底）：A 记录改写为网关 IP，
	// 由网关嗅探 SNI 后按当前国外出口（含 KFC 本机出口）转发
	if s.OnRewrite != nil {
		if h, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			s.OnRewrite(h, qname)
		}
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name: q.Name, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 60,
		},
		A: net.IP(s.GatewayIP.AsSlice()),
	})
	s.writeResponse(w, m, qname, "proxy")
	s.report(qname, "proxy")
}

// writeResponse 只在 DNS 响应已成功写回客户端后上报响应成功。
// 广告“成功拦截次数”据此统计，避免把断开的 DoT 连接或写失败误报为成功。
func (s *Server) writeResponse(w dns.ResponseWriter, m *dns.Msg, qname, action string) bool {
	if err := w.WriteMsg(m); err != nil {
		return false
	}
	if s.OnResponse != nil {
		s.OnResponse(qname, action)
	}
	return true
}

// realIPForClient 报告是否应向客户端返回真实 IP（手机本地直连）。
//
// 只有命中明确的直连规则（国内域名/GEOIP、私网、自定义 direct，
// 即 Index >= 0）才返回真实 IP。FINAL 兜底的 direct 语义是
// “国外未命中流量从网关本机公网 IP 出去”，必须改写到网关；
// 否则国外域名会被手机在国内蜂窝上直连而全部失败
// （YouTube/TikTok 全挂就是这个原因）。
func realIPForClient(dec policy.Decision) bool {
	return dec.Action == policy.ActionDirect && dec.Index >= 0
}

func (s *Server) report(qname, action string) {
	if s.OnDecision != nil {
		s.OnDecision(qname, action)
	}
}

func (s *Server) isClient(addr net.Addr) bool {
	if !s.ClientCIDR.IsValid() {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return s.ClientCIDR.Contains(ip.Unmap())
}

func (s *Server) forwardAndWrite(w dns.ResponseWriter, req *dns.Msg, _ bool, qname string) {
	resp, err := s.lookup(req, qname)
	if err != nil || resp == nil {
		dns.HandleFailed(w, req)
		return
	}
	_ = w.WriteMsg(resp)
}

// lookup 使用本地 TTL 缓存查询上游，并把响应 ID 调整为当前请求。
func (s *Server) lookup(req *dns.Msg, qname string) (*dns.Msg, error) {
	key := fmt.Sprintf("%s|%d", qname, req.Question[0].Qtype)

	s.cacheMu.RLock()
	if e, ok := s.cache[key]; ok && time.Now().Before(e.expire) {
		m := e.msg.Copy()
		s.cacheMu.RUnlock()
		m.Id = req.Id
		m.Question = append([]dns.Question(nil), req.Question...)
		return m, nil
	}
	s.cacheMu.RUnlock()

	resp, err := s.query(req)
	if err != nil || resp == nil {
		return nil, err
	}

	ttl := 60
	if len(resp.Answer) > 0 {
		if t := int(resp.Answer[0].Header().Ttl); t > 0 && t < 3600 {
			ttl = t
		}
	}
	s.cacheMu.Lock()
	s.cache[key] = cacheEntry{msg: resp.Copy(), expire: time.Now().Add(time.Duration(ttl) * time.Second)}
	s.cacheMu.Unlock()
	return resp, nil
}

func answerAddrs(resp *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(a.A); ok {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// query 依次尝试上游，返回首个成功结果。
func (s *Server) query(req *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, up := range s.Upstream {
		resp, _, err := s.client.Exchange(req.Copy(), up)
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
