// Package dot 实现 Android 接入路径：DNS over TLS + A 记录改写。
//
// 与 iOS 的 Relay 路径不同，Android 系统只提供「私密 DNS」一个入口，
// 拿不到应用层目的地。因此这里沿用业界通行做法：
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

	// OnDecision 供统计与日志使用（可为空）
	OnDecision func(qname, action string)

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

	// 判断该域名走直连还是代理
	tgt, _ := policy.ParseTarget(net.JoinHostPort(qname, "443"))
	dec := s.Policy().Match(tgt)

	if dec.Action == policy.ActionBlock {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		s.report(qname, "block")
		return
	}

	if dec.Action == policy.ActionDirect {
		s.forwardAndWrite(w, req, false, qname)
		s.report(qname, "direct")
		return
	}

	// 代理域名：A 记录改写为网关 IP
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
	_ = w.WriteMsg(m)
	s.report(qname, "proxy")
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
	key := fmt.Sprintf("%s|%d", qname, req.Question[0].Qtype)

	s.cacheMu.RLock()
	if e, ok := s.cache[key]; ok && time.Now().Before(e.expire) {
		m := e.msg.Copy()
		m.SetReply(req)
		m.Answer = e.msg.Answer
		s.cacheMu.RUnlock()
		_ = w.WriteMsg(m)
		return
	}
	s.cacheMu.RUnlock()

	resp, err := s.query(req)
	if err != nil || resp == nil {
		dns.HandleFailed(w, req)
		return
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

	_ = w.WriteMsg(resp)
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
