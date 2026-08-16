package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ErrNoUDP 表示该出口不具备承载 UDP（QUIC）的能力。
//
// 调用方收到此错误应放弃接管该 QUIC 会话，让客户端自行回落 TCP，
// 绝不能静默丢包——那会让客户端一直等待。
var ErrNoUDP = errors.New("出口不支持 UDP")

// UDPDialer 是出口的可选能力：建立一条到目标的 UDP 会话。
//
// 返回的 net.Conn 已与目标绑定：Write 发送单个数据报，Read 读取
// 单个数据报，语义与已连接的 *net.UDPConn 一致。
type UDPDialer interface {
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// DialUDPVia 在出口支持时建立 UDP 会话，否则返回 ErrNoUDP。
func DialUDPVia(ctx context.Context, d Dialer, addr string) (net.Conn, error) {
	u, ok := d.(UDPDialer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoUDP, d.Name())
	}
	return u.DialUDP(ctx, addr)
}

// SupportsUDP 报告出口是否具备 UDP 能力。
func SupportsUDP(d Dialer) bool {
	_, ok := d.(UDPDialer)
	return ok
}

// ---------- 本机直出 ----------

// udpSocketBuffer 是每条转发 UDP 会话的内核收发缓冲上限。
//
// 不显式设置时，内核按 net.core.{r,w}mem_default 预留，典型各 208KB。
// 这部分内存计入 cgroup 的 slab_unreclaimable，既不受 GOMEMLIMIT 约束，
// 也无法由应用侧回收——生产 OOM 现场即为 anon 222MB + slab 260MB 顶破
// 512MB 上限，而健康态 slab 仅 0.23MB。
//
// QUIC 单个数据报不超过约 1500 字节，64KB 可缓冲约 40 个数据报，对
// 转发场景足够；相比默认值可把每会话内核开销降到约三分之一。
const udpSocketBuffer = 64 << 10

// DialUDP 直接从本机发出 UDP。
func (d *Direct) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	// 与 TCP 同理：QUIC 接管监听 UDP 443，连回自身会形成环路。
	if IsSelfTakeover(addr) {
		return nil, ErrSelfConnect
	}
	if err := guardIPv6(addr, d.hasV6); err != nil {
		return nil, err
	}
	// 复用 Direct 的 dialer：其 ControlContext 会在 DNS 解析完成后检查
	// 实际目标 IP，防止域名/CNAME 解析回网关 UDP 443 形成 QUIC 环路。
	c, err := d.dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	limitUDPBuffers(c)
	return c, nil
}

// limitUDPBuffers 收紧 UDP socket 的内核收发缓冲。
// 设置失败不影响功能，仅退化为内核默认值。
func limitUDPBuffers(c net.Conn) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	_ = uc.SetReadBuffer(udpSocketBuffer)
	_ = uc.SetWriteBuffer(udpSocketBuffer)
}

// ---------- SOCKS5 UDP ASSOCIATE（对接 mihomo） ----------

// DialUDP 通过 SOCKS5 UDP ASSOCIATE 承载 UDP。
//
// 流程（RFC 1928 §7）：先用 TCP 控制连接申请 UDP 中继，拿到中继
// 地址后本地起 UDP socket 与之通信；控制连接必须在整个会话期间
// 保持打开，一旦断开中继即失效。
func (s *Socks5) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	// SOCKS5 UDP 的目标域名由上游解析，必须在封装请求前先挡住网关自身。
	if IsSelfTakeover(addr) {
		return nil, ErrSelfConnect
	}
	if err := guardIPv6(addr, s.hasV6); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("目标 %q 格式错误: %w", addr, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, fmt.Errorf("端口 %q 无效: %w", portStr, err)
	}

	ctrl, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 上游 %s 失败: %w", s.addr, err)
	}

	relayAddr, err := socks5UDPAssociate(ctrl)
	if err != nil {
		ctrl.Close()
		return nil, err
	}

	// 中继地址若为通配地址，按惯例回落到 SOCKS 服务器自身 IP。
	relayAddr = fixRelayAddr(relayAddr, s.addr)

	var lc net.Dialer
	lc.Timeout = DialTimeout
	pc, err := lc.DialContext(ctx, "udp", relayAddr)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("连接 SOCKS5 UDP 中继 %s 失败: %w", relayAddr, err)
	}

	return &socks5UDPConn{
		Conn: pc,
		ctrl: ctrl,
		host: host,
		port: port,
	}, nil
}

// socks5UDPAssociate 发起 UDP ASSOCIATE 并返回中继地址。
func socks5UDPAssociate(c net.Conn) (string, error) {
	_ = c.SetDeadline(time.Now().Add(DialTimeout))
	defer c.SetDeadline(time.Time{})

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return "", err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return "", fmt.Errorf("SOCKS5 方法协商失败: %v", rep)
	}

	// CMD=0x03 UDP ASSOCIATE；本地地址填 0.0.0.0:0 表示由中继自行判断。
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		return "", err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("SOCKS5 响应版本异常: 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		return "", fmt.Errorf("SOCKS5 拒绝 UDP ASSOCIATE（rep=0x%02x）", head[1])
	}

	var hostPart string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		hostPart = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		hostPart = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		hostPart = string(b)
	default:
		return "", fmt.Errorf("SOCKS5 响应地址类型未知: 0x%02x", head[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	return net.JoinHostPort(hostPart, fmt.Sprint(binary.BigEndian.Uint16(pb))), nil
}

// fixRelayAddr 把通配的中继地址替换为 SOCKS 服务器地址。
func fixRelayAddr(relay, server string) string {
	host, port, err := net.SplitHostPort(relay)
	if err != nil {
		return relay
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsUnspecified() {
		return relay
	}
	sh, _, err := net.SplitHostPort(server)
	if err != nil {
		return relay
	}
	return net.JoinHostPort(sh, port)
}

// socks5UDPConn 在 SOCKS5 UDP 中继上封装出面向单一目标的 net.Conn。
type socks5UDPConn struct {
	net.Conn // 到中继的已连接 UDP socket

	ctrl net.Conn // 控制连接：必须保持打开
	host string
	port int

	once sync.Once
}

// Write 按 RFC 1928 §7 给数据报加上 SOCKS5 UDP 请求头。
func (c *socks5UDPConn) Write(b []byte) (int, error) {
	head := make([]byte, 0, 262+len(b))
	head = append(head, 0x00, 0x00, 0x00) // RSV RSV FRAG
	if ip, err := netip.ParseAddr(c.host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			head = append(head, 0x01)
			head = append(head, a[:]...)
		} else {
			a := ip.As16()
			head = append(head, 0x04)
			head = append(head, a[:]...)
		}
	} else {
		if len(c.host) > 255 {
			return 0, fmt.Errorf("域名过长: %d", len(c.host))
		}
		head = append(head, 0x03, byte(len(c.host)))
		head = append(head, c.host...)
	}
	head = append(head, byte(c.port>>8), byte(c.port))
	head = append(head, b...)

	if _, err := c.Conn.Write(head); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read 剥掉 SOCKS5 UDP 响应头，只返回载荷。
func (c *socks5UDPConn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+262)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 10 {
		return 0, fmt.Errorf("SOCKS5 UDP 响应过短: %d", n)
	}
	if buf[2] != 0x00 {
		return 0, errors.New("SOCKS5 UDP 分片不支持")
	}
	var off int
	switch buf[3] {
	case 0x01:
		off = 4 + 4 + 2
	case 0x04:
		off = 4 + 16 + 2
	case 0x03:
		off = 4 + 1 + int(buf[4]) + 2
	default:
		return 0, fmt.Errorf("SOCKS5 UDP 地址类型未知: 0x%02x", buf[3])
	}
	if off > n {
		return 0, errors.New("SOCKS5 UDP 响应头越界")
	}
	return copy(b, buf[off:n]), nil
}

// Close 同时关闭中继 socket 与控制连接。
func (c *socks5UDPConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.ctrl != nil {
			_ = c.ctrl.Close()
		}
	})
	return err
}
