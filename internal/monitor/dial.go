package monitor

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dialProbe 是默认探测实现：TCP 建连；socks5 为 true 时额外做一次
// SOCKS5 版本协商（VER=5, NMETHODS=1, NO AUTH），比裸建连更接近
// 用户流量的真实可用性——端口活着但代理进程挂了的情况能被识别出来。
//
// 只协商版本、不发 CONNECT：不产生任何代理流量，也不打扰目标站点。
func dialProbe(ctx context.Context, addr string, socks5 bool) (time.Duration, error) {
	d := net.Dialer{}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return time.Since(start), err
	}
	defer c.Close()
	if !socks5 {
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
