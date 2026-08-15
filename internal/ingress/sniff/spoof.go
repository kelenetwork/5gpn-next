package sniff

import (
	"bufio"
	"net"
	"time"
)

// LocationSpoofer 提供 Apple 网络定位改写。
//
// 与 relay 包同名接口保持一致：由 cmd 层注入同一个实现，
// 两条入口路径（Relay / 蜂窝 DNS）共用一份坐标与证书。
type LocationSpoofer interface {
	Active() bool
	Handles(host string) bool
	Serve(client, upstream net.Conn, host string) error
}

// bufferedConn 让 TLS 层能读到已被 bufio 预读的首包字节。
//
// 嗅探阶段为了取 SNI 已经把 ClientHello 读进了 bufio.Reader；
// 若直接把裸 conn 交给 TLS，握手会因为缺失首包而失败。
// 因此 Read 走 bufio，其余方法透传底层连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) *bufferedConn {
	return &bufferedConn{Conn: c, r: r}
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// SetDeadline 等由内嵌 net.Conn 提供，无需重写。
var _ interface {
	SetDeadline(time.Time) error
} = (*bufferedConn)(nil)
