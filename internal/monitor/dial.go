package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// dialProbe 是默认探测实现。
//
// 三种语义（见 ProbeKind）：
//
//   - 裸 TCP 建连：非 SOCKS5 出口直接连节点服务器，测网关到节点的 RTT。
//   - SOCKS5 版本协商：只跟本机 mihomo 桥握手，证明代理进程活着。
//     耗时是 loopback 级别（几十微秒），不代表任何链路延迟。
//   - 端到端：经 mihomo CONNECT 到远端目标并完成 TLS 握手，计时只取
//     握手往返——这才是用户关心的「走这条出口有多快」。
//
// 为什么端到端要做 TLS 而不止 CONNECT：mihomo 会先乐观回复 CONNECT 成功
// 再去连上游，上游不可达时 CONNECT 照样返回 0x00。只有真正收到对端的
// ServerHello，才能证明整条链路通且拿到真实往返时间。
func dialProbe(ctx context.Context, t Target) (time.Duration, error) {
	if t.Socks5 && t.Remote != "" {
		return dialEndToEnd(ctx, t.Addr, t.Remote)
	}

	d := net.Dialer{}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return time.Since(start), err
	}
	defer c.Close()
	if !t.Socks5 {
		return time.Since(start), nil
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return time.Since(start), fmt.Errorf("socks5 greeting: %w", err)
	}
	var resp [2]byte
	if _, err := readFullConn(c, resp[:]); err != nil {
		return time.Since(start), fmt.Errorf("socks5 method reply: %w", err)
	}
	if resp[0] != 0x05 {
		return time.Since(start), fmt.Errorf("socks5 版本异常: %d", resp[0])
	}
	return time.Since(start), nil
}

// dialEndToEnd 经本机 SOCKS5 桥连到 remote 并完成 TLS 握手。
//
// 计时从 CONNECT 发出前开始：建到本机桥的那一小段（几十微秒）相对
// 跨境往返可以忽略，但 CONNECT 与 TLS 必须整体计入，否则测不到真实链路。
func dialEndToEnd(ctx context.Context, bridge, remote string) (time.Duration, error) {
	host, portStr, err := net.SplitHostPort(remote)
	if err != nil {
		return 0, fmt.Errorf("探测目标 %q 格式错误: %w", remote, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, fmt.Errorf("探测目标端口 %q 无效: %w", portStr, err)
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", bridge)
	if err != nil {
		return 0, fmt.Errorf("连接 SOCKS5 桥 %s 失败: %w", bridge, err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	start := time.Now()
	if err := socks5Connect(c, host, port); err != nil {
		return time.Since(start), err
	}
	// TLS 握手：只验证握手能完成，不校验证书链。
	// 探测目标是我们自己选的固定 IP，此处不承载任何数据，
	// 校验失败率反而会把链路问题误报成安全问题。
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 — 仅用于测量握手往返，不传输数据
		ServerName:         host,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return time.Since(start), fmt.Errorf("TLS 握手失败: %w", err)
	}
	el := time.Since(start)
	_ = tc.Close()
	return el, nil
}

// socks5Connect 执行无认证 SOCKS5 方法协商 + CONNECT。
func socks5Connect(c net.Conn, host string, port int) error {
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	var rep [2]byte
	if _, err := readFullConn(c, rep[:]); err != nil {
		return fmt.Errorf("socks5 method reply: %w", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return fmt.Errorf("socks5 方法协商失败: %v", rep)
	}

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
		return fmt.Errorf("socks5 connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err := readFullConn(c, head); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5 版本异常: %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT 被拒绝: rep=%d", head[1])
	}
	// 丢弃 BND.ADDR/BND.PORT
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := readFullConn(c, l[:]); err != nil {
			return fmt.Errorf("socks5 bnd len: %w", err)
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("socks5 ATYP 异常: %d", head[3])
	}
	if _, err := readFullConn(c, make([]byte, skip)); err != nil {
		return fmt.Errorf("socks5 bnd addr: %w", err)
	}
	return nil
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
