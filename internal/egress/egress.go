// Package egress 管理出口拨号：本机直出或经上游代理。
//
// 设计取舍：本包只负责"把连接送出去"，协议实现交给 mihomo。
// 我们通过 SOCKS5 与 mihomo 对接，因此绝不 fork mihomo，
// 避免长期 rebase 负担（moooyo/5gpn 的教训）。
package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DialTimeout 是单次拨号上限。
//
// P0 实测：10s 会让 WhatsApp 判定"没有互联网连接"，必须收紧。
const DialTimeout = 4 * time.Second

// Dialer 是一个具名出口。
type Dialer interface {
	Name() string
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// HasIPv6 报告该出口能否处理 IPv6 目标。
	HasIPv6() bool
}

// ErrNoIPv6 表示出口不具备 IPv6 能力，应让客户端快速回落 IPv4。
var ErrNoIPv6 = errors.New("出口无 IPv6 能力")

// ---------- 本机直出 ----------

// Direct 是本机直出出口。
type Direct struct {
	name   string
	hasV6  bool
	dialer *net.Dialer
}

// NewDirect 构造直出出口，并探测本机 IPv6 能力。
func NewDirect(name string) *Direct {
	if name == "" {
		name = "DIRECT"
	}
	return &Direct{
		name:   name,
		hasV6:  probeLocalIPv6(),
		dialer: &net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second},
	}
}

func (d *Direct) Name() string  { return d.name }
func (d *Direct) HasIPv6() bool { return d.hasV6 }

func (d *Direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := guardIPv6(addr, d.hasV6); err != nil {
		return nil, err
	}
	c, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return c, nil
}

// probeLocalIPv6 检测本机是否有可用 IPv6 出口。
//
// 用 UDP dial 不产生实际流量，仅让内核做路由选择。
func probeLocalIPv6() bool {
	c, err := net.DialTimeout("udp6", "[2001:4860:4860::8888]:53", 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// guardIPv6 在出口无 v6 能力时对 IPv6 字面量目标快速失败。
//
// 这是 P0 实测得到的硬约束：iOS 会主动把 IPv6 字面量交给 Relay，
// 若不快速失败，Happy Eyeballs 无法及时回落，App 会报"无网络连接"。
func guardIPv6(addr string, hasV6 bool) error {
	if hasV6 {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil // 域名目标交给 DNS 解析处理
	}
	if ip.Unmap().Is6() {
		return fmt.Errorf("%w: %s", ErrNoIPv6, host)
	}
	return nil
}

// ---------- SOCKS5 上游（对接 mihomo） ----------

// Socks5 通过 SOCKS5 上游出海，通常指向本机 mihomo 监听。
type Socks5 struct {
	name   string
	addr   string
	hasV6  bool
	dialer *net.Dialer
}

// NewSocks5 构造 SOCKS5 出口。hasV6 由运维声明或探测得出。
func NewSocks5(name, addr string, hasV6 bool) *Socks5 {
	return &Socks5{
		name:   name,
		addr:   addr,
		hasV6:  hasV6,
		dialer: &net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second},
	}
}

func (s *Socks5) Name() string  { return s.name }
func (s *Socks5) HasIPv6() bool { return s.hasV6 }

func (s *Socks5) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// 节点无 v6 能力时对 IPv6 字面量快速失败，促使客户端 Happy Eyeballs
	// 立即回落 IPv4；有 v6 能力则由节点代拨（SOCKS ATYP=4）。
	if err := guardIPv6(addr, s.hasV6); err != nil {
		return nil, err
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 上游 %s 失败: %w", s.addr, err)
	}
	if err := socks5Handshake(c, addr); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// socks5Handshake 执行无认证 SOCKS5 CONNECT。
func socks5Handshake(c net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("目标 %q 格式错误: %w", target, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("端口 %q 无效: %w", portStr, err)
	}
	_ = c.SetDeadline(time.Now().Add(DialTimeout))
	defer c.SetDeadline(time.Time{})

	// 1) 方法协商：仅 NO AUTH
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := readFull(c, rep); err != nil {
		return err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return fmt.Errorf("SOCKS5 方法协商失败: %v", rep)
	}

	// 2) CONNECT 请求
	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			req = append(req, 0x01)
			req = append(req, a[:]...)
		} else {
			a := ip.As16()
			req = append(req, 0x04)
			req = append(req, a[:]...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("域名过长: %d", len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}

	// 3) 响应
	head := make([]byte, 4)
	if _, err := readFull(c, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 上游拒绝（rep=0x%02x）", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFull(c, l); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("SOCKS5 未知地址类型 0x%02x", head[3])
	}
	if _, err := readFull(c, make([]byte, skip)); err != nil {
		return err
	}
	return nil
}

// ProbeSocks5IPv6 探测 SOCKS5 上游（mihomo 节点）能否真正代拨 IPv6 目标。
//
// ⚠️ 只看 SOCKS 应答会得到假阳性：mihomo 收到 CONNECT 后会**先乐观回复
// 成功**，再去连上游；上游不可达时不回错误，连接静默挂死。生产实测中
// hinet 因此被误判为有 IPv6，导致 Relay 把手机流量灌进一条从未建立的
// 连接（表现为 up=517B down=0B 挂 30 秒）。
//
// 因此必须做端到端验证：完成一次真实 TLS 握手，证明**双向**有数据流动。
func ProbeSocks5IPv6(addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	rep := make([]byte, 2)
	if _, err := readFull(c, rep); err != nil || rep[0] != 0x05 || rep[1] != 0x00 {
		return false
	}
	ip := netip.MustParseAddr(probeV6Addr).As16()
	req := append([]byte{0x05, 0x01, 0x00, 0x04}, ip[:]...)
	req = append(req, 0x01, 0xbb) // 443
	if _, err := c.Write(req); err != nil {
		return false
	}
	head := make([]byte, 4)
	if _, err := readFull(c, head); err != nil || head[1] != 0x00 {
		return false
	}
	// 读掉 BND.ADDR/BND.PORT，之后字节流才属于目标
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFull(c, l); err != nil {
			return false
		}
		skip = int(l[0]) + 2
	default:
		return false
	}
	if _, err := readFull(c, make([]byte, skip)); err != nil {
		return false
	}

	// 关键一步：真实 TLS 握手。握手成功 = 上游确实连通且双向可传数据。
	// 只验证「通」，不验证证书链（探测目标固定且不传输任何敏感数据）。
	tc := tls.Client(c, &tls.Config{
		ServerName:         probeV6SNI,
		InsecureSkipVerify: true, //nolint:gosec // 连通性探测，非信任判定
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return tc.HandshakeContext(ctx) == nil
}

const (
	// probeV6Addr 是 IPv6 连通性探测目标（Cloudflare anycast，全球可达）
	probeV6Addr = "2606:4700:4700::1111"
	probeV6SNI  = "one.one.one.one"
)

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ---------- 出口注册表 ----------

// Registry 保存所有具名出口。
type Registry struct {
	mu      sync.RWMutex
	dialers map[string]Dialer
	direct  Dialer
}

// NewRegistry 构造注册表，并注册默认 DIRECT。
func NewRegistry() *Registry {
	d := NewDirect("DIRECT")
	return &Registry{
		dialers: map[string]Dialer{"DIRECT": d},
		direct:  d,
	}
}

// Register 加入一个出口。
func (r *Registry) Register(d Dialer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dialers[d.Name()] = d
}

// Get 按名字取出口；找不到时返回 DIRECT 与 false。
func (r *Registry) Get(name string) (Dialer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if name == "" {
		return r.direct, true
	}
	d, ok := r.dialers[name]
	if !ok {
		return r.direct, false
	}
	return d, true
}

// HasProxy 报告是否存在任何非直连出口。
//
// 用于区分两种情况：策略判定为 proxy 且真有落地节点，
// 还是策略判定为 proxy 但实际只能本机直出（被墙目标必然失败）。
func (r *Registry) HasProxy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.dialers {
		if _, isDirect := d.(*Direct); !isDirect {
			return true
		}
	}
	return false
}

// Direct 返回直出出口。
func (r *Registry) Direct() Dialer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.direct
}

// Names 返回所有出口名。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.dialers))
	for n := range r.dialers {
		out = append(out, n)
	}
	return out
}
