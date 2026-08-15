package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// UDPDialer 是支持 UDP 目标的出口。
//
// Relay 的 connect-udp（masque）需要把手机的 UDP 数据报送到目标：
//   - Direct：本机 UDP socket 直出
//   - Socks5：RFC 1928 UDP ASSOCIATE，经 mihomo 节点转发（udp: true）
type UDPDialer interface {
	// DialUDPContext 返回一个"已连接"语义的 UDP 会话：
	// Write 发往固定目标，Read 收该目标的回包。
	DialUDPContext(ctx context.Context, addr string) (net.Conn, error)
}

// DialUDPContext 实现 Direct 的 UDP 直出。
func (d *Direct) DialUDPContext(ctx context.Context, addr string) (net.Conn, error) {
	if err := guardIPv6(addr, d.hasV6); err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, "udp", addr)
}

// DialUDPContext 通过 SOCKS5 UDP ASSOCIATE 建立 UDP 会话。
//
// 生命周期：ASSOCIATE 的有效期与发起它的 TCP 连接绑定，
// 因此返回的 conn 同时持有 TCP 控制连接与 UDP 数据套接字。
func (s *Socks5) DialUDPContext(ctx context.Context, target string) (net.Conn, error) {
	if err := guardIPv6(target, s.hasV6); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("目标 %q 格式错误: %w", target, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, fmt.Errorf("端口 %q 无效: %w", portStr, err)
	}

	tcp, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 上游 %s 失败: %w", s.addr, err)
	}
	ok := false
	defer func() {
		if !ok {
			tcp.Close()
		}
	}()

	_ = tcp.SetDeadline(time.Now().Add(DialTimeout))
	if _, err := tcp.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := readFull(tcp, rep); err != nil {
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 方法协商失败: %v", rep)
	}

	// UDP ASSOCIATE：DST 填零值，表示由 socket 源地址决定
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcp.Write(req); err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := readFull(tcp, head); err != nil {
		return nil, err
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE 被拒（rep=0x%02x）", head[1])
	}
	var bndHost string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := readFull(tcp, b); err != nil {
			return nil, err
		}
		bndHost = netip.AddrFrom4([4]byte(b)).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := readFull(tcp, b); err != nil {
			return nil, err
		}
		bndHost = netip.AddrFrom16([16]byte(b)).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFull(tcp, l); err != nil {
			return nil, err
		}
		b := make([]byte, int(l[0]))
		if _, err := readFull(tcp, b); err != nil {
			return nil, err
		}
		bndHost = string(b)
	default:
		return nil, fmt.Errorf("SOCKS5 未知 BND 地址类型 0x%02x", head[3])
	}
	pb := make([]byte, 2)
	if _, err := readFull(tcp, pb); err != nil {
		return nil, err
	}
	bndPort := int(pb[0])<<8 | int(pb[1])
	_ = tcp.SetDeadline(time.Time{})

	// mihomo 常回 0.0.0.0：意味着与 TCP 同地址
	if bndHost == "0.0.0.0" || bndHost == "::" {
		if h, _, err := net.SplitHostPort(s.addr); err == nil {
			bndHost = h
		}
	}

	udp, err := net.Dial("udp", net.JoinHostPort(bndHost, fmt.Sprintf("%d", bndPort)))
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 UDP 中继失败: %w", err)
	}

	hdr := buildSocksUDPHeader(host, port)
	ok = true
	return &socks5UDPConn{tcp: tcp, udp: udp, header: hdr}, nil
}

// buildSocksUDPHeader 构造 RFC 1928 UDP 请求头（RSV+FRAG+ATYP+ADDR+PORT）。
func buildSocksUDPHeader(host string, port int) []byte {
	h := []byte{0x00, 0x00, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			h = append(h, 0x01)
			h = append(h, a[:]...)
		} else {
			a := ip.As16()
			h = append(h, 0x04)
			h = append(h, a[:]...)
		}
	} else {
		h = append(h, 0x03, byte(len(host)))
		h = append(h, host...)
	}
	return append(h, byte(port>>8), byte(port))
}

// stripSocksUDPHeader 剥掉响应数据报的 SOCKS 头，返回 payload 偏移。
func stripSocksUDPHeader(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("SOCKS UDP 响应过短")
	}
	if b[2] != 0x00 {
		return 0, fmt.Errorf("不支持分片的 SOCKS UDP 响应")
	}
	switch b[3] {
	case 0x01:
		if len(b) < 4+4+2 {
			return 0, fmt.Errorf("SOCKS UDP v4 头不完整")
		}
		return 4 + 4 + 2, nil
	case 0x04:
		if len(b) < 4+16+2 {
			return 0, fmt.Errorf("SOCKS UDP v6 头不完整")
		}
		return 4 + 16 + 2, nil
	case 0x03:
		if len(b) < 5 {
			return 0, fmt.Errorf("SOCKS UDP 域名头不完整")
		}
		n := 5 + int(b[4]) + 2
		if len(b) < n {
			return 0, fmt.Errorf("SOCKS UDP 域名头不完整")
		}
		return n, nil
	}
	return 0, fmt.Errorf("SOCKS UDP 未知地址类型 0x%02x", b[3])
}

// socks5UDPConn 是经 SOCKS5 中继的"已连接" UDP 会话。
type socks5UDPConn struct {
	tcp    net.Conn // 控制连接：关闭即终止 ASSOCIATE
	udp    net.Conn
	header []byte
}

func (c *socks5UDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 64*1024)
	for {
		n, err := c.udp.Read(buf)
		if err != nil {
			return 0, err
		}
		off, err := stripSocksUDPHeader(buf[:n])
		if err != nil {
			continue // 畸形包丢弃，继续等下一个
		}
		return copy(p, buf[off:n]), nil
	}
}

func (c *socks5UDPConn) Write(p []byte) (int, error) {
	pkt := make([]byte, 0, len(c.header)+len(p))
	pkt = append(pkt, c.header...)
	pkt = append(pkt, p...)
	if _, err := c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPConn) Close() error {
	_ = c.udp.Close()
	return c.tcp.Close()
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.udp.RemoteAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }
