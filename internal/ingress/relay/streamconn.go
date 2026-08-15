package relay

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// streamConn 把 HTTP/2 CONNECT 的 stream 适配成 net.Conn。
//
// 定位改写需要在客户端连接上做 TLS 终止，而 TLS 要求 net.Conn；
// H2 CONNECT 给到的是 (r.Body, ResponseWriter) 一对半双工通道，
// 因此这里做一层适配。
//
// Deadline 系列为空实现：H2 stream 的生命周期由 http.Server 与
// 请求 context 管理，单独设 deadline 既无效也无意义。
type streamConn struct {
	r io.ReadCloser
	w io.Writer
	f http.Flusher

	closeOnce sync.Once
	closed    chan struct{}
}

func newStreamConn(r io.ReadCloser, w io.Writer) *streamConn {
	f, _ := w.(http.Flusher)
	return &streamConn{r: r, w: w, f: f, closed: make(chan struct{})}
}

func (c *streamConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	return c.r.Read(p)
}

func (c *streamConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	n, err := c.w.Write(p)
	// 必须逐块 flush：TLS 握手是严格的一问一答，缓冲会直接导致握手挂死
	if c.f != nil {
		c.f.Flush()
	}
	return n, err
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.r.Close()
	})
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "h2" }
func (pipeAddr) String() string  { return "h2-stream" }

func (c *streamConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (c *streamConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// errHijackUnsupported 表示 h1 隧道无法接管连接。
var errHijackUnsupported = errors.New("hijack unsupported")
