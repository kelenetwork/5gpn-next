// Package sniff 实现 Android 路径的流量接管。
//
// Android 系统只提供「私密 DNS」一个入口，拿不到应用层目的地。
// DoT 把代理域名的 A 记录改写成网关 IP 后，流量会落到本包监听的
// 80 / 443 端口，这里从 TLS ClientHello 的 SNI 或 HTTP Host 还原目的地。
//
// 与 iOS 的 Relay 路径相比，这条路存在固有短板：
//   - 无 SNI 的私有协议（如 WhatsApp Noise）无法还原目的地
//   - QUIC 需要拒绝以促使客户端回落 TCP
//
// 这正是 iOS 优先使用 Relay 的原因；本路径仅为 Android 兼容而存在。
package sniff

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/trace"
)

// ErrNoHost 表示无法从首包还原目的地。
var ErrNoHost = errors.New("无法从首包识别目标域名")

// Recorder 接收连接决策记录。
type Recorder interface{ Record(t *trace.Trace) }

// ConnStat 供流量统计使用。
type ConnStat func(host, action string, up, down int64, failed bool)

// Server 是 SNI/Host 嗅探接管服务。
type Server struct {
	// Policy / Egress 用函数取值，便于配置热重载
	Policy func() *policy.Engine
	Egress func() *egress.Registry

	Recorder Recorder
	OnConn   ConnStat

	// LocationSpoof 提供定位改写；为 nil 时所有流量正常透传，不做任何解密。
	//
	// 蜂窝 DNS 模式下 gs-loc.apple.com 会被 DoT 改写到网关，
	// 流量落到本包监听的 443，此处从 SNI 还原域名后即可改写坐标。
	LocationSpoof LocationSpoofer

	// HintLookup 返回该客户端最近经 DoT 被改写到网关的域名（可为空）。
	// 无 SNI 私有协议（如 WhatsApp Noise）嗅探失败时用它回退还原目的地；
	// 只作兜底，绝不覆盖显式嗅探结果。
	HintLookup func(client string) (string, bool)

	Handled atomic.Int64
	Failed  atomic.Int64
	NoHost  atomic.Int64
	Hinted  atomic.Int64

	seq atomic.Uint64
}

// ListenAndServe 在指定端口接管流量。tls 为 true 时按 TLS ClientHello 解析。
func (s *Server) ListenAndServe(ctx context.Context, addr string, isTLS bool) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	kind := "HTTP"
	if isTLS {
		kind = "TLS"
	}
	log.Printf("Android 接管入口已启动 %s（%s 嗅探）", addr, kind)

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go s.handle(ctx, c, isTLS)
	}
}

func (s *Server) handle(ctx context.Context, cli net.Conn, isTLS bool) {
	defer cli.Close()

	id := fmt.Sprintf("s%d", s.seq.Add(1))
	_ = cli.SetReadDeadline(time.Now().Add(8 * time.Second))

	client := clientIP(cli.RemoteAddr())
	br := bufio.NewReaderSize(cli, 8*1024)
	host, port, err := peekHost(br, isTLS)
	hinted := false
	if err != nil {
		// 无 SNI/Host：用 DNS 线索回退。客户端建连前必然先经 DoT
		// 查询过目标域名且被改写到网关，那条查询就是目的地。
		if s.HintLookup != nil {
			if h, ok := s.HintLookup(client); ok {
				host, port, hinted = h, portOfConn(cli), true
				s.Hinted.Add(1)
			}
		}
		if !hinted {
			s.NoHost.Add(1)
			return
		}
	}
	_ = cli.SetReadDeadline(time.Time{})

	target := net.JoinHostPort(host, itoa(port))
	tr := trace.New(id, target, client)
	defer func() {
		if s.Recorder != nil {
			s.Recorder.Record(tr)
		}
	}()

	proto := "HTTP/Host"
	if isTLS {
		proto = "TLS/SNI"
	}
	if hinted {
		tr.Step(trace.StageIngress, trace.StatusOK, "无 SNI，由 DNS 线索还原目标（私有协议兜底）")
	} else {
		tr.Step(trace.StageIngress, trace.StatusOK, "android %s 嗅探成功", proto)
	}

	// 策略判定
	t, _ := policy.ParseTarget(target)
	dec := s.Policy().MatchContext(ctx, t)

	var actionName string
	switch dec.Action {
	case policy.ActionBlock:
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 拦截", dec.Rule)
		if s.OnConn != nil {
			s.OnConn(host, "block", 0, 0, false)
		}
		return
	case policy.ActionDirect:
		actionName = "direct"
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 直连", dec.Rule)
	default:
		actionName = "proxy"
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 代理:%s", dec.Rule, orDef(dec.Egress, "默认"))
	}

	reg := s.Egress()
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
	tr.Step(trace.StageEgress, trace.StatusOK, "%s", dialer.Name())

	dctx, cancel := context.WithTimeout(ctx, egress.DialTimeout)
	defer cancel()
	up, err := dialer.DialContext(dctx, "tcp", target)
	if err != nil {
		s.Failed.Add(1)
		tr.Fail(trace.StageConnect, err, "拨号 %s 失败", target)
		if s.OnConn != nil {
			s.OnConn(host, actionName, 0, 0, true)
		}
		return
	}
	defer up.Close()
	s.Handled.Add(1)
	tr.Step(trace.StageConnect, trace.StatusOK, "TCP %s 已建立", up.RemoteAddr())

	// ---- 定位改写（仅白名单域名，且功能已开启）----
	//
	// 命中时本地终止 TLS 并改写 WLOC 响应；其余流量走下方普通转发，
	// 绝不解密。预读的 ClientHello 字节需随 bufferedConn 交给 TLS 层。
	if sp := s.LocationSpoof; sp != nil && isTLS && !hinted && sp.Active() && sp.Handles(host) {
		tr.Step(trace.StageApp, trace.StatusOK, "定位改写：终止 TLS 并重写坐标")
		if err := sp.Serve(newBufferedConn(cli, br), up, host); err != nil {
			tr.Fail(trace.StageApp, err, "定位改写失败，连接已关闭（客户端将退回真实定位）")
			if s.OnConn != nil {
				s.OnConn(host, actionName, 0, 0, true)
			}
			return
		}
		tr.Step(trace.StageApp, trace.StatusOK, "定位改写完成")
		if s.OnConn != nil {
			s.OnConn(host, actionName, 0, 0, false)
		}
		return
	}

	// 双向转发；br 中已读出的首包（含无法解析的私有协议字节）需要一并送出
	var upN, downN int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(up, br)
		atomic.AddInt64(&upN, n)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(cli, up)
		atomic.AddInt64(&downN, n)
		closeWrite(cli)
		done <- struct{}{}
	}()
	<-done
	<-done

	tr.Step(trace.StageApp, trace.StatusOK, "连接关闭 up=%dB down=%dB", upN, downN)
	if s.OnConn != nil {
		s.OnConn(host, actionName, upN, downN, false)
	}
}

// portOfConn 返回本地监听端口（即客户端想连的端口）。
func portOfConn(c net.Conn) int {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok && a.Port > 0 {
		return a.Port
	}
	return 443
}

// peekHost 从首包解析目标域名，且不消费缓冲。
func peekHost(br *bufio.Reader, isTLS bool) (string, int, error) {
	if isTLS {
		h, err := peekSNI(br)
		if err != nil {
			return "", 0, err
		}
		return h, 443, nil
	}
	h, err := peekHTTPHost(br)
	if err != nil {
		return "", 0, err
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		p := atoiSafe(h[i+1:])
		if p > 0 {
			return h[:i], p, nil
		}
	}
	return h, 80, nil
}

// peekSNI 解析 TLS ClientHello 中的 server_name 扩展。
func peekSNI(br *bufio.Reader) (string, error) {
	head, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	// 0x16 = Handshake
	if head[0] != 0x16 {
		return "", ErrNoHost
	}
	recLen := int(binary.BigEndian.Uint16(head[3:5]))
	if recLen <= 0 || recLen > 16384 {
		return "", ErrNoHost
	}
	buf, err := br.Peek(5 + recLen)
	if err != nil {
		// 记录可能跨多个 TCP 段，尽力用已有数据解析
		if buf, err = br.Peek(br.Buffered()); err != nil || len(buf) < 45 {
			return "", ErrNoHost
		}
	}
	return parseSNI(buf[5:])
}

func parseSNI(b []byte) (string, error) {
	// handshake: type(1) len(3) version(2) random(32) ...
	if len(b) < 38 || b[0] != 0x01 {
		return "", ErrNoHost
	}
	p := 38

	// session id
	if p >= len(b) {
		return "", ErrNoHost
	}
	p += 1 + int(b[p])

	// cipher suites
	if p+2 > len(b) {
		return "", ErrNoHost
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))

	// compression methods
	if p >= len(b) {
		return "", ErrNoHost
	}
	p += 1 + int(b[p])

	// extensions
	if p+2 > len(b) {
		return "", ErrNoHost
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}

	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(b[p : p+2])
		elen := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		p += 4
		if p+elen > extEnd {
			return "", ErrNoHost
		}
		if etype == 0x0000 { // server_name
			e := b[p : p+elen]
			if len(e) < 5 {
				return "", ErrNoHost
			}
			nameLen := int(binary.BigEndian.Uint16(e[3:5]))
			if 5+nameLen > len(e) {
				return "", ErrNoHost
			}
			name := strings.ToLower(strings.TrimSpace(string(e[5 : 5+nameLen])))
			if name == "" {
				return "", ErrNoHost
			}
			return name, nil
		}
		p += elen
	}
	return "", ErrNoHost
}

// peekHTTPHost 解析明文 HTTP 的 Host 头。
func peekHTTPHost(br *bufio.Reader) (string, error) {
	buf, err := br.Peek(minInt(br.Size(), 4096))
	if err != nil && len(buf) == 0 {
		return "", err
	}
	text := string(buf)
	end := strings.Index(text, "\r\n\r\n")
	if end < 0 {
		end = len(text)
	}
	for _, line := range strings.Split(text[:end], "\r\n") {
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			h := strings.ToLower(strings.TrimSpace(line[5:]))
			if h != "" {
				return h, nil
			}
		}
	}
	return "", ErrNoHost
}

// RejectUDP 在指定端口拒绝 UDP，促使客户端回落 TCP。
//
// QUIC 无法被本路径接管：它的首包已加密，没有明文 SNI 可读。
// 直接丢弃会让客户端静默等待超时，因此这里主动读取并忽略，
// 由 nftables 侧的 reject 规则回送 ICMP 端口不可达。
func (s *Server) RejectUDP(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		if _, _, err := pc.ReadFrom(buf); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		// 不回应：配合 nftables reject 让客户端尽快回落 TCP
	}
}

// ---------- 小工具 ----------

func closeWrite(c io.Closer) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
	}
}

func clientIP(a net.Addr) string {
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

func orDef(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
