package egress

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// FirstByteTimeout 是"客户端已发数据后，上游必须给出首个响应字节"的上限。
//
// 生产实测（WhatsApp）：mihomo 收到 SOCKS CONNECT 后会**先乐观回复成功**，
// 再去连上游；上游不可达时它既不回错误也不关闭连接，隧道就一直挂着，
// 直到客户端自己 30 秒超时。而 WhatsApp 会轮询多个 Meta edge IP
// （2a03:2880:f10d / f127 / f131 ...，其中只有部分经出口可达），
// 每个坏 edge 都白挂 30 秒的话，App 在轮到可用 edge 之前就已经放弃。
//
// 6 秒足够覆盖"跨洋 + 节点转发 + TLS 握手"（实测可用 edge 均在 1s 内出首字节），
// 又能让客户端迅速换下一个地址——这正是 Happy Eyeballs 生效的前提。
const FirstByteTimeout = 6 * time.Second

// FirstByteGuard 包装出口连接：客户端发出数据后若上游迟迟没有任何响应，
// 主动关闭连接，促使客户端快速重试其它地址。
//
// 只在"上行已发送 && 尚未收到任何下行字节"的窗口内计时；一旦收到首个
// 下行字节就永久解除，不影响长连接（如 XMPP 推送通道）的空闲保持。
type FirstByteGuard struct {
	net.Conn
	timeout time.Duration

	// OnTimeout 在上游静默超时（判定为坏目标）时回调，可为 nil。
	OnTimeout func()
	// OnFirstByte 在收到首个下行字节（判定为可用目标）时回调，可为 nil。
	OnFirstByte func()

	gotFirst atomic.Bool
	timedOut atomic.Bool

	mu    sync.Mutex
	timer *time.Timer
}

// NewFirstByteGuard 包装 conn；timeout <= 0 时使用 FirstByteTimeout。
func NewFirstByteGuard(c net.Conn, timeout time.Duration) *FirstByteGuard {
	if timeout <= 0 {
		timeout = FirstByteTimeout
	}
	return &FirstByteGuard{Conn: c, timeout: timeout}
}

// Write 转发上行数据，并在首次写入时开始等待上游首字节。
func (g *FirstByteGuard) Write(p []byte) (int, error) {
	n, err := g.Conn.Write(p)
	if n > 0 {
		g.arm()
	}
	return n, err
}

// Read 转发下行数据；收到首个字节即解除计时。
func (g *FirstByteGuard) Read(p []byte) (int, error) {
	n, err := g.Conn.Read(p)
	if n > 0 && g.gotFirst.CompareAndSwap(false, true) {
		g.disarm()
		if g.OnFirstByte != nil {
			g.OnFirstByte()
		}
	}
	return n, err
}

func (g *FirstByteGuard) arm() {
	if g.gotFirst.Load() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil || g.gotFirst.Load() {
		return
	}
	g.timer = time.AfterFunc(g.timeout, func() {
		if g.gotFirst.Load() {
			return
		}
		g.timedOut.Store(true)
		if g.OnTimeout != nil {
			g.OnTimeout()
		}
		// 关闭底层连接：两侧 io.Copy 随即返回，隧道整体收敛
		_ = g.Conn.Close()
	})
}

func (g *FirstByteGuard) disarm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
}

// Close 释放定时器并关闭底层连接。
func (g *FirstByteGuard) Close() error {
	g.disarm()
	return g.Conn.Close()
}

// CloseWrite 透传半关闭。
//
// FirstByteGuard 只嵌入 net.Conn，CloseWrite 不会被自动提升；若不透传，
// relay 隧道里的 `conn.(interface{ CloseWrite() error })` 断言会失败，
// 上行结束时无法向上游发 FIN，部分服务端会一直等待请求结束（表现为长挂）。
func (g *FirstByteGuard) CloseWrite() error {
	if cw, ok := g.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// TimedOut 报告连接是否因上游无响应而被主动断开。
func (g *FirstByteGuard) TimedOut() bool { return g.timedOut.Load() }
