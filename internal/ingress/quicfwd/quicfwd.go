// Package quicfwd 接管客户端发往网关的 QUIC（UDP）流量。
//
// 背景：DoT 把代理域名的 A 记录改写到网关后，走 HTTP/3 的客户端会
// 对网关发 QUIC。旧架构在 nftables 层 reject UDP 443，指望客户端
// 回落 TCP —— 浏览器会回落，但 Google Play 下载器（Cronet）不会，
// 它只是无限重试 QUIC，表现为「下载永远等待中」。
//
// 本包从 QUIC Initial 包解出 SNI，按策略选出口，然后以 UDP 中继
// 的方式转发整条 QUIC 会话。网关只读首包的 SNI，不解密、不改写
// 任何应用数据：客户端与真实服务器之间的 TLS 依旧端到端。
//
// 边界：无法还原目的地（非 QUIC、无 SNI 且无 DNS 线索、未知版本）
// 的数据报一律丢弃并计数，不做任何猜测转发。
package quicfwd

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/ingress/quicsni"
	"github.com/w0ven/5gpn-next/internal/policy"
	"github.com/w0ven/5gpn-next/internal/trace"
)

const (
	// maxDatagram 是单个 UDP 数据报缓冲上限。QUIC 要求路径至少支持
	// 1200 字节，实际不会超过以太网 MTU；2048 留足余量。
	maxDatagram = 2048
	// idleTimeout 是会话空闲上限。下载中的连接持续有流量，
	// 空闲这么久基本可判定已结束。
	idleTimeout = 90 * time.Second
	// maxSessions 限制并发会话数，防止伪造源地址耗尽内存。
	//
	// 上限不能只看 Go 侧开销。每个被接管的 QUIC 会话都要向出口建立一个
	// UDP socket，内核按 net.core.{r,w}mem_default 为其预留收发缓冲
	// （典型 208KB + 208KB）。这部分计入 cgroup 的 slab_unreclaimable，
	// 既不受 GOMEMLIMIT 约束，也无法由应用侧回收。
	//
	// 按旧值 4096 计算，仅内核缓冲上界就达 1664MB，而目标机总内存只有
	// 941MB、cgroup 上限 512MB。生产 OOM 现场印证了这一点：
	//   anon 222MB + slab_unreclaimable 260MB ≈ 512MB（正好顶破）
	// 健康态 slab_unreclaimable 仅 0.23MB，相差三个数量级。
	//
	// 512 个并发 QUIC 会话对单网关的家庭/小团队场景绰绰有余，对应内核
	// 缓冲上界约 208MB、Go 侧 pending 上界 16MB，留足安全边界。
	maxSessions = 512
	// maxPendingDatagrams / maxPendingBytes 限制 SNI 尚未确定时
	// 每个会话可缓冲的数据量。
	maxPendingDatagrams = 16
	// 字节上限必须小于「个数 × 单报上限」，否则永远不会触发，等于没有。
	// 旧值 64KB 大于 16×2048=32KB，字节这道防线形同虚设。
	maxPendingBytes = 32 << 10
)

// Recorder 接收连接决策记录。
type Recorder interface{ Record(t *trace.Trace) }

// ConnStat / TrafficStat 供实时流量统计使用，签名与 sniff 包一致。
type ConnStat func(host, action string, failed bool)
type TrafficStat func(host string, up, down int64)

// Server 是 QUIC 接管服务。
type Server struct {
	// Policy / Egress 用函数取值，便于配置热重载
	Policy func() *policy.Engine
	Egress func() *egress.Registry

	Recorder  Recorder
	OnConn    ConnStat
	OnTraffic TrafficStat

	// HintLookup 返回该客户端最近经 DoT 被改写到网关的域名（可为空）。
	// 仅在 QUIC 首包无 SNI 时兜底，绝不覆盖已解析出的 SNI。
	HintLookup func(client string) (string, bool)

	// ClientCIDR 限定可接管的客户端网段；零值表示不限制。
	ClientCIDR netip.Prefix

	Handled atomic.Int64 // 成功建立中继的会话数
	NoHost  atomic.Int64 // 无法还原目的地而丢弃的会话数
	Failed  atomic.Int64 // 策略/出口/拨号失败的会话数

	// OnDial 在每次出口拨号完成后回调（可为空），供健康监控埋点。耗时为微秒。
	OnDial func(egress string, ok bool, ms int64)

	// OnEgressTraffic 按出口维度累计真实转发字节数（可为空）。
	OnEgressTraffic func(egress string, up, down int64)

	seq atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*session
}

// ActiveSessions 返回 (当前会话数, 上限)，供健康监控展示水位。
func (s *Server) ActiveSessions() (int, int) {
	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	return n, maxSessions
}

type session struct {
	srv      *Server
	key      string
	client   net.Addr
	clientIP string
	port     int

	dec *quicsni.Decoder
	tr  *trace.Trace

	mu           sync.Mutex
	remote       net.Conn
	pending      [][]byte
	pendingBytes int
	resolving    bool
	closed       bool
	counted      bool
	host         string
	action       string
	egress       string

	lastSeen atomic.Int64 // UnixNano
	up       atomic.Int64
	down     atomic.Int64
}

// ListenAndServe 在 addr 上接管 QUIC 流量，直到 ctx 结束。
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()

	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]*session)
	}
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go s.janitor(ctx)

	log.Printf("QUIC 接管入口已启动 %s（Initial SNI 解析）", addr)

	buf := make([]byte, maxDatagram)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		if n <= 0 {
			continue
		}
		if !s.allowedClient(raddr) {
			continue
		}
		dg := make([]byte, n)
		copy(dg, buf[:n])
		s.dispatch(ctx, pc, raddr, dg)
	}
}

func (s *Server) allowedClient(a net.Addr) bool {
	if !s.ClientCIDR.IsValid() {
		return true
	}
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return false
	}
	return s.ClientCIDR.Contains(ip.Unmap())
}

// dispatch 把数据报交给对应会话；必要时新建会话。read 循环不得阻塞。
func (s *Server) dispatch(ctx context.Context, pc net.PacketConn, raddr net.Addr, dg []byte) {
	key := raddr.String()

	s.mu.Lock()
	sess, ok := s.sessions[key]
	if !ok {
		// 只有长包头（Initial/Handshake）才可能开启新会话；
		// 短包头属于已迁移或过期连接，直接丢弃。
		if !quicsni.IsLongHeader(dg) {
			s.mu.Unlock()
			return
		}
		if len(s.sessions) >= maxSessions {
			s.mu.Unlock()
			return
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		p, _ := net.LookupPort("udp", port)
		if p == 0 {
			p = 443
		}
		host, _, _ := net.SplitHostPort(key)
		sess = &session{
			srv:      s,
			key:      key,
			client:   raddr,
			clientIP: host,
			port:     p,
			dec:      quicsni.NewDecoder(),
			tr:       trace.New(idFor(s.seq.Add(1)), "quic://pending", host),
		}
		s.sessions[key] = sess
	}
	s.mu.Unlock()

	sess.lastSeen.Store(time.Now().UnixNano())
	sess.onDatagram(ctx, pc, dg)
}

func idFor(n uint64) string {
	return "q" + itoa(int(n))
}

// onDatagram 处理一个客户端数据报。
func (sc *session) onDatagram(ctx context.Context, pc net.PacketConn, dg []byte) {
	sc.mu.Lock()

	if sc.closed {
		sc.mu.Unlock()
		return
	}

	// 中继已建立：直接转发。
	if sc.remote != nil {
		remote := sc.remote
		host := sc.host
		sc.mu.Unlock()
		n, _ := remote.Write(dg)
		if n > 0 {
			sc.up.Add(int64(n))
			sc.reportTraffic(host, int64(n), 0)
		}
		return
	}

	// 正在解析目的地：缓冲，等中继建立后补发。
	if sc.resolving {
		sc.bufferLocked(dg)
		sc.mu.Unlock()
		return
	}

	sc.bufferLocked(dg)
	host, ok, err := sc.dec.Feed(dg)
	if err != nil && !errors.Is(err, quicsni.ErrNoSNI) {
		// 非 Initial / 未知版本 / 结构异常：本会话无法接管。
		if sc.dec.Packets() == 0 {
			sc.mu.Unlock()
			sc.abort("无法解析 QUIC Initial：%v", err)
			return
		}
		sc.mu.Unlock()
		return
	}
	if !ok {
		// ClientHello 尚未收齐（分片），等待后续数据报。
		if errors.Is(err, quicsni.ErrNoSNI) || sc.dec.Packets() >= quicsni.MaxInitialPackets {
			if h, hok := sc.hint(); hok {
				host, ok = h, true
			}
		}
		if !ok {
			sc.mu.Unlock()
			return
		}
	}

	sc.resolving = true
	sc.host = host
	sc.mu.Unlock()

	go sc.connect(ctx, pc, host)
}

func (sc *session) hint() (string, bool) {
	if sc.srv.HintLookup == nil {
		return "", false
	}
	return sc.srv.HintLookup(sc.clientIP)
}

func (sc *session) bufferLocked(dg []byte) {
	if len(sc.pending) >= maxPendingDatagrams || sc.pendingBytes+len(dg) > maxPendingBytes {
		return
	}
	sc.pending = append(sc.pending, dg)
	sc.pendingBytes += len(dg)
}

// connect 完成策略判定、出口选择与 UDP 中继建立。
func (sc *session) connect(ctx context.Context, pc net.PacketConn, host string) {
	target := net.JoinHostPort(host, itoa(sc.port))
	sc.tr.Target = target
	sc.tr.Step(trace.StageIngress, trace.StatusOK, "QUIC Initial SNI 解析成功")

	t, _ := policy.ParseTarget(target)
	dec := sc.srv.Policy().MatchContext(ctx, t)
	actionName := statsAction(dec.Action)

	switch dec.Action {
	case policy.ActionBlock:
		sc.tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 拦截", dec.Rule)
		sc.finish(host, "block", false)
		return
	case policy.ActionDirect:
		// 直连语义下客户端本应拿到真实 IP 自行连接；既然流量到了
		// 网关，仍按网关本机出口转发，避免会话悬空。
		sc.tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 直连（网关出口）", dec.Rule)
	default:
		sc.tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 代理:%s", dec.Rule, orDef(dec.Egress, "默认"))
	}

	reg := sc.srv.Egress()
	d, ok := selectDialer(reg, dec)
	if !ok || d == nil {
		sc.tr.Fail(trace.StageEgress, nil, "出口 %q 不存在", dec.Egress)
		sc.srv.Failed.Add(1)
		sc.finish(host, actionName, true)
		return
	}
	if !egress.SupportsUDP(d) {
		// 出口无法承载 UDP：放弃接管，让客户端自行回落 TCP。
		sc.tr.Fail(trace.StageEgress, egress.ErrNoUDP, "%s 不支持 UDP，放弃接管 QUIC", d.Name())
		sc.srv.Failed.Add(1)
		sc.finish(host, actionName, true)
		return
	}
	sc.tr.Step(trace.StageEgress, trace.StatusOK, "%s", d.Name())

	dialCtx, cancel := context.WithTimeout(ctx, egress.DialTimeout)
	defer cancel()
	dialStart := time.Now()
	remote, err := egress.DialUDPVia(dialCtx, d, target)
	if sc.srv.OnDial != nil {
		sc.srv.OnDial(d.Name(), err == nil, time.Since(dialStart).Microseconds())
	}
	if err != nil {
		sc.tr.Fail(trace.StageConnect, err, "QUIC 出口拨号 %s 失败", target)
		sc.srv.Failed.Add(1)
		sc.finish(host, actionName, true)
		return
	}
	sc.tr.Step(trace.StageConnect, trace.StatusOK, "UDP 会话 %s 已建立", remote.RemoteAddr())

	sc.mu.Lock()
	if sc.closed {
		sc.mu.Unlock()
		_ = remote.Close()
		return
	}
	sc.remote = remote
	sc.action = actionName
	sc.egress = d.Name()
	reportConn := !sc.counted
	sc.counted = true
	pending := sc.pending
	sc.pending = nil
	sc.pendingBytes = 0
	sc.mu.Unlock()

	if reportConn && sc.srv.OnConn != nil {
		sc.srv.OnConn(host, actionName, false)
	}
	sc.srv.Handled.Add(1)

	// 补发握手期间缓冲的数据报，顺序与到达顺序一致。
	for _, dg := range pending {
		n, err := remote.Write(dg)
		if n > 0 {
			sc.up.Add(int64(n))
			sc.reportTraffic(host, int64(n), 0)
		}
		if err != nil {
			break
		}
	}

	go sc.pump(pc, remote, host, actionName)
}

// pump 把出口返回的数据报回送给客户端。
func (sc *session) pump(pc net.PacketConn, remote net.Conn, host, action string) {
	buf := make([]byte, maxDatagram)
	for {
		_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := remote.Read(buf)
		if n > 0 {
			sc.lastSeen.Store(time.Now().UnixNano())
			written, werr := pc.WriteTo(buf[:n], sc.client)
			if written > 0 {
				sc.down.Add(int64(written))
				sc.reportTraffic(host, 0, int64(written))
			}
			if werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	sc.tr.Step(trace.StageApp, trace.StatusOK, "QUIC 会话结束 up=%dB down=%dB",
		sc.up.Load(), sc.down.Load())
	sc.finish(host, action, false)
}

// abort 记录无法接管的会话并清理。
func (sc *session) abort(format string, args ...any) {
	sc.srv.NoHost.Add(1)
	sc.tr.Fail(trace.StageIngress, nil, format, args...)
	sc.finish("", "nohost", true)
}

// finish 收尾：记录 trace、统计并从会话表移除。
func (sc *session) finish(host, action string, failed bool) {
	sc.mu.Lock()
	if sc.closed {
		sc.mu.Unlock()
		return
	}
	sc.closed = true
	if host == "" {
		host = sc.host
	}
	if action == "" {
		action = sc.action
	}
	reportConn := !sc.counted && host != "" && action != ""
	if reportConn {
		sc.counted = true
	}
	remote := sc.remote
	sc.remote = nil
	sc.pending = nil
	sc.mu.Unlock()

	if remote != nil {
		_ = remote.Close()
	}
	sc.srv.mu.Lock()
	delete(sc.srv.sessions, sc.key)
	sc.srv.mu.Unlock()

	if sc.srv.Recorder != nil {
		sc.srv.Recorder.Record(sc.tr)
	}
	if reportConn && sc.srv.OnConn != nil {
		sc.srv.OnConn(host, action, failed)
	}
}

func (sc *session) reportTraffic(host string, up, down int64) {
	if up <= 0 && down <= 0 {
		return
	}
	if sc.srv.OnTraffic != nil {
		sc.srv.OnTraffic(host, up, down)
	}
	if sc.srv.OnEgressTraffic != nil {
		sc.mu.Lock()
		eg := sc.egress
		sc.mu.Unlock()
		if eg != "" {
			sc.srv.OnEgressTraffic(eg, up, down)
		}
	}
}

func statsAction(action policy.Action) string {
	switch action {
	case policy.ActionBlock:
		return "block"
	case policy.ActionDirect:
		return "direct"
	default:
		return "proxy"
	}
}

func selectDialer(reg *egress.Registry, dec policy.Decision) (egress.Dialer, bool) {
	if dec.Action == policy.ActionDirect {
		return reg.Direct(), true
	}
	return reg.Get(dec.Egress)
}

// janitor 周期清理空闲会话。
func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.closeAll()
			return
		case <-t.C:
			cutoff := time.Now().Add(-idleTimeout).UnixNano()
			var stale []*session
			s.mu.Lock()
			for _, sc := range s.sessions {
				if sc.lastSeen.Load() < cutoff {
					stale = append(stale, sc)
				}
			}
			s.mu.Unlock()
			for _, sc := range stale {
				sc.finish("", "", false)
			}
		}
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	all := make([]*session, 0, len(s.sessions))
	for _, sc := range s.sessions {
		all = append(all, sc)
	}
	s.mu.Unlock()
	for _, sc := range all {
		sc.finish("", "", false)
	}
}

// ---------- 小工具 ----------

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
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
