// Package relay 实现 Apple Network Relay 服务端（RFC 9298 / HTTP CONNECT）。
//
// P0 实测结论（iOS 26 真机）：
//   - iOS 通过 HTTP/2 发起标准 CONNECT，authority 携带明确目的地，
//     因此无需 SNI 嗅探，WhatsApp 这类无 SNI 协议从根上不再是问题。
//   - iOS 安装 Relay 后会主动 GET /.well-known/pvd（RFC 8801），
//     必须正确响应，否则会反复重试。
//   - iOS 会把 IPv6 字面量交给 Relay；出口无 v6 时必须快速失败。
package relay

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/trace"
)

// TokenHeader 是描述文件 AdditionalHTTPHeaderFields 下发的鉴权头。
const TokenHeader = "X-5gpn-Token"

// LocationSpoofer 提供 Apple 网络定位改写。
//
// 由 cmd 层注入，relay 包不直接依赖 mitm 实现细节；功能关闭时注入 nil，
// 连接路径上零开销、零解密。
type LocationSpoofer interface {
	// Active 报告是否已启用且已设置目标坐标。
	Active() bool
	// Handles 报告该主机是否在中间人白名单内（硬编码，不可配置）。
	Handles(host string) bool
	// Serve 在客户端连接上终止 TLS、改写响应；upstream 为到真实服务器的连接。
	Serve(client, upstream net.Conn, host string) error
}

// Recorder 接收每条连接的决策记录。
type Recorder interface {
	Record(t *trace.Trace)
}

// Stats 是运行时计数。
type Stats struct {
	Connect    atomic.Int64
	Blocked    atomic.Int64
	AuthFail   atomic.Int64
	DialFail   atomic.Int64
	V6FastFail atomic.Int64
	PvD        atomic.Int64
	UDPAttempt atomic.Int64
}

// Server 是 Relay 入口。
type Server struct {
	Token    string
	Recorder Recorder
	Identity string // PvD identifier，通常为 Relay 主机名

	// 策略与出口用原子指针持有：热重载时整体替换指针，
	// 绝不复制含 sync.RWMutex 的结构体（那会造成数据竞争）。
	pol atomic.Pointer[policy.Engine]
	eg  atomic.Pointer[egress.Registry]

	// ProfilePath / ProfileBytes 提供 Relay 描述文件下载端点（可为空）
	ProfilePath  string
	ProfileBytes []byte

	// DNSProfilePath / DNSProfileBytes 提供「蜂窝 DNS 模式」描述文件（可为空）
	DNSProfilePath  string
	DNSProfileBytes []byte

	// LocationSpoof 提供 Apple 网络定位改写；为 nil 时所有流量正常透传，
	// 不做任何 TLS 解密。
	LocationSpoof LocationSpoofer

	// OnConn 在每条连接结束时上报流量与结果，供统计使用（可为空）。
	// host 为域名或裸 IP，action 取 direct / proxy / block。
	OnConn func(host, action string, up, down int64, failed bool)

	Stats Stats

	seq atomic.Uint64
}

// SetRuntime 原子替换策略引擎与出口注册表，用于配置热重载。
func (s *Server) SetRuntime(p *policy.Engine, e *egress.Registry) {
	s.pol.Store(p)
	s.eg.Store(e)
}

// Policy 返回当前策略引擎。
func (s *Server) Policy() *policy.Engine { return s.pol.Load() }

// Egress 返回当前出口注册表。
func (s *Server) Egress() *egress.Registry { return s.eg.Load() }

// ServeHTTP 实现 http.Handler。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 描述文件下载：iOS 下载时不会带 token，故置于鉴权之前，
	// 路径含随机串本身即能力凭证。
	if s.ProfilePath != "" && r.Method == http.MethodGet && r.URL.Path == s.ProfilePath {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="5gpn-next.mobileconfig"`)
		w.Write(s.ProfileBytes)
		return
	}
	if s.DNSProfilePath != "" && r.Method == http.MethodGet && r.URL.Path == s.DNSProfilePath {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="5gpn-next-dns.mobileconfig"`)
		w.Write(s.DNSProfileBytes)
		return
	}

	if !s.authOK(r) {
		s.Stats.AuthFail.Add(1)
		http.Error(w, "forbidden", http.StatusProxyAuthRequired)
		return
	}

	// RFC 8801 Provisioning Domain：iOS 装上 Relay 后会主动请求
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/pvd" {
		s.Stats.PvD.Add(1)
		w.Header().Set("Content-Type", "application/pvd+json")
		json.NewEncoder(w).Encode(map[string]any{
			"identifier": s.Identity,
			"expires":    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			"prefixes":   []string{},
		})
		return
	}

	// RFC 9298 connect-udp：QUIC 等 UDP 流量（抖音/TikTok 短视频依赖）。
	// iOS 用 Extended CONNECT（:protocol=connect-udp）发起，数据面走
	// RFC 9297 capsule；旧版本此处直接 501，导致短视频刷不出下一条。
	if strings.HasPrefix(r.URL.Path, "/.well-known/masque/udp/") {
		s.Stats.UDPAttempt.Add(1)
		if r.Method != http.MethodConnect {
			http.Error(w, "expect CONNECT", http.StatusBadRequest)
			return
		}
		s.handleConnectUDP(w, r)
		return
	}

	if r.Method != http.MethodConnect {
		http.Error(w, "expect CONNECT", http.StatusBadRequest)
		return
	}

	// Extended CONNECT 的其它 :protocol 一律拒绝，避免被当成普通隧道
	if p := r.Header.Get(":protocol"); p != "" && p != "connect-udp" {
		http.Error(w, "unsupported connect protocol", http.StatusNotImplemented)
		return
	}

	s.handleConnect(w, r)
}

func (s *Server) authOK(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	got := r.Header.Get(TokenHeader)
	if got == "" {
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			got = strings.TrimPrefix(a, "Bearer ")
		}
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
	}

	id := fmt.Sprintf("c%d", s.seq.Add(1))
	tr := trace.New(id, target, clientIP(r.RemoteAddr))
	defer func() {
		if s.Recorder != nil {
			s.Recorder.Record(tr)
		}
	}()

	tr.Step(trace.StageIngress, trace.StatusOK, "relay/%s 已认证", r.Proto)

	// ---- 策略判定 ----
	t, _ := policy.ParseTarget(target)
	pol := s.Policy()
	reg := s.Egress()
	dec := pol.MatchContext(r.Context(), t)
	actionName := "proxy"

	switch dec.Action {
	case policy.ActionBlock:
		s.Stats.Blocked.Add(1)
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 拦截", dec.Rule)
		s.report(t.Host, "block", 0, 0, false)
		http.Error(w, "blocked by policy", http.StatusForbidden)
		return
	case policy.ActionDirect:
		actionName = "direct"
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 直连", dec.Rule)
	default:
		actionName = "proxy"
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 代理:%s", dec.Rule, orDefault(dec.Egress, "默认"))
	}

	// ---- 选出口 ----
	var dialer egress.Dialer
	if dec.Action == policy.ActionDirect {
		dialer = reg.Direct()
	} else {
		d, ok := reg.Get(dec.Egress)
		if !ok {
			tr.Fail(trace.StageEgress, fmt.Errorf("出口 %q 不存在", dec.Egress),
				"出口缺失，已回退 %s", d.Name())
		}
		dialer = d
	}
	if tr.OK() {
		tr.Step(trace.StageEgress, trace.StatusOK, "%s (ipv6=%v)", dialer.Name(), dialer.HasIPv6())
	}

	// ---- 拨号 ----
	s.Stats.Connect.Add(1)
	ctx, cancel := context.WithTimeout(r.Context(), egress.DialTimeout)
	defer cancel()

	up, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if errors.Is(err, egress.ErrNoIPv6) {
			s.Stats.V6FastFail.Add(1)
			tr.Fail(trace.StageConnect, err, "IPv6 目标快速失败，促使客户端回落 IPv4")
			s.report(t.Host, actionName, 0, 0, true)
			// 502 让 Happy Eyeballs 立刻改试 IPv4
			http.Error(w, "no ipv6 egress", http.StatusBadGateway)
			return
		}
		s.Stats.DialFail.Add(1)
		tr.Fail(trace.StageConnect, err, "拨号 %s 失败", target)
		s.report(t.Host, actionName, 0, 0, true)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer up.Close()
	tr.Step(trace.StageConnect, trace.StatusOK, "TCP %s 已建立", up.RemoteAddr())

	// ---- 定位改写（仅白名单域名，且功能已开启）----
	//
	// 命中时本地终止 TLS 并改写 WLOC 响应；其余流量一律走下方普通隧道，
	// 绝不解密。改写失败直接关闭连接，客户端会重试并退回真实定位。
	if sp := s.LocationSpoof; sp != nil && sp.Active() && sp.Handles(t.Host) {
		tr.Step(trace.StageApp, trace.StatusOK, "定位改写：终止 TLS 并重写坐标")
		s.serveLocationSpoof(w, r, up, tr, t.Host, actionName)
		return
	}

	// ---- 建立隧道 ----
	if r.ProtoMajor == 1 {
		s.tunnelH1(w, up, tr, t.Host, actionName)
		return
	}
	s.tunnelH2(w, r, up, tr, t.Host, actionName)
}

// serveLocationSpoof 在 CONNECT 隧道上执行定位改写。
//
// iOS Relay 走 HTTP/2，需要把 stream 适配成 net.Conn 交给 TLS 终止；
// HTTP/1.1 则 Hijack 后直接使用底层连接。
func (s *Server) serveLocationSpoof(w http.ResponseWriter, r *http.Request, up net.Conn, tr *trace.Trace, host, action string) {
	var client net.Conn
	if r.ProtoMajor == 1 {
		hj, ok := w.(http.Hijacker)
		if !ok {
			tr.Fail(trace.StageApp, errHijackUnsupported, "定位改写无法接管 h1 连接")
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		cli, buf, err := hj.Hijack()
		if err != nil {
			tr.Fail(trace.StageApp, err, "hijack 失败")
			return
		}
		defer cli.Close()
		if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			tr.Fail(trace.StageApp, err, "写 200 失败")
			return
		}
		buf.Flush()
		client = cli
	} else {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		sc := newStreamConn(r.Body, w)
		defer sc.Close()
		client = sc
	}

	if err := s.LocationSpoof.Serve(client, up, host); err != nil {
		tr.Fail(trace.StageApp, err, "定位改写失败，连接已关闭（客户端将退回真实定位）")
		s.report(host, action, 0, 0, true)
		return
	}
	tr.Step(trace.StageApp, trace.StatusOK, "定位改写完成")
	s.report(host, action, 0, 0, false)
}

// tunnelH2 处理 HTTP/2 CONNECT，这是 iOS Relay 的实际路径。
func (s *Server) tunnelH2(w http.ResponseWriter, r *http.Request, up net.Conn, tr *trace.Trace, host, action string) {
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	var upN, downN int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(up, r.Body)
		atomicAdd(&upN, n)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			nr, er := up.Read(buf)
			if nr > 0 {
				nw, ew := w.Write(buf[:nr])
				atomicAdd(&downN, int64(nw))
				if flusher != nil {
					flusher.Flush()
				}
				if ew != nil {
					break
				}
			}
			if er != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	<-done

	tr.Step(trace.StageApp, trace.StatusOK, "隧道关闭 up=%dB down=%dB", upN, downN)
	s.report(host, action, upN, downN, false)
}

// tunnelH1 处理 HTTP/1.1 CONNECT。
//
// Go 的 h1 服务端必须 Hijack 才能做双向隧道，
// 用 ResponseWriter 流式写会得到零字节隧道（P0 踩过）。
func (s *Server) tunnelH1(w http.ResponseWriter, up net.Conn, tr *trace.Trace, host, action string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		tr.Fail(trace.StageApp, errors.New("hijack unsupported"), "h1 隧道无法建立")
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cli, buf, err := hj.Hijack()
	if err != nil {
		tr.Fail(trace.StageApp, err, "hijack 失败")
		return
	}
	defer cli.Close()

	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		tr.Fail(trace.StageApp, err, "写 200 失败")
		return
	}
	buf.Flush()

	var upN, downN int64
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(up, buf); atomicAdd(&upN, n); closeWrite(up); done <- struct{}{} }()
	go func() { n, _ := io.Copy(cli, up); atomicAdd(&downN, n); closeWrite(cli); done <- struct{}{} }()
	<-done
	<-done

	tr.Step(trace.StageApp, trace.StatusOK, "隧道关闭 up=%dB down=%dB", upN, downN)
	s.report(host, action, upN, downN, false)
}

// report 上报一次连接结果；未设置回调时静默跳过。
func (s *Server) report(host, action string, up, down int64, failed bool) {
	if s.OnConn == nil {
		return
	}
	s.OnConn(host, action, up, down, failed)
}

func atomicAdd(dst *int64, n int64) { *dst += n }

func closeWrite(c io.Closer) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		x.CloseWrite()
	}
}

func clientIP(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
