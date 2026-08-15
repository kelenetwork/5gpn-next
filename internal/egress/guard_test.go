package egress

import (
	"errors"
	"net"
	"testing"
	"time"
)

// pipeConn 用 net.Pipe 模拟一条出口连接，便于精确控制"上游是否回数据"。
func pipeConn(t *testing.T) (client, upstream net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c, s
}

// 上游始终不回数据 → 看门狗必须主动断开，而不是让客户端白等 30 秒。
func TestFirstByteGuardClosesSilentUpstream(t *testing.T) {
	c, up := pipeConn(t)
	g := NewFirstByteGuard(c, 120*time.Millisecond)

	// 消费上行，模拟 mihomo 收下数据却从不回应
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := up.Read(buf); err != nil {
				return
			}
		}
	}()

	if _, err := g.Write([]byte("client hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := time.Now()
	_, err := g.Read(make([]byte, 64))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("silent upstream must not read successfully")
	}
	if !g.TimedOut() {
		t.Fatal("TimedOut() should report the watchdog fired")
	}
	if elapsed > time.Second {
		t.Fatalf("watchdog too slow: %s", elapsed)
	}
}

// 上游正常回数据 → 看门狗解除，之后长时间空闲也不得断开。
// 这是 XMPP/推送类长连接的关键：不能误伤。
func TestFirstByteGuardDisarmsAfterFirstByte(t *testing.T) {
	c, up := pipeConn(t)
	g := NewFirstByteGuard(c, 100*time.Millisecond)

	go func() {
		buf := make([]byte, 64)
		if _, err := up.Read(buf); err != nil {
			return
		}
		_, _ = up.Write([]byte("ok"))
	}()

	if _, err := g.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := g.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("first byte read failed: n=%d err=%v", n, err)
	}
	if g.TimedOut() {
		t.Fatal("watchdog must not fire after first byte")
	}

	// 超过原超时窗口后连接仍应可用
	time.Sleep(250 * time.Millisecond)
	if g.TimedOut() {
		t.Fatal("watchdog fired on an established idle connection")
	}
	go func() { _, _ = up.Write([]byte("later")) }()
	_ = g.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := g.Read(buf); err != nil {
		t.Fatalf("idle long-lived connection broke: %v", err)
	}
}

// 从未写入过数据的连接不应被看门狗计时（例如等待服务端先说话的协议）。
func TestFirstByteGuardNotArmedWithoutWrite(t *testing.T) {
	c, _ := pipeConn(t)
	g := NewFirstByteGuard(c, 80*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if g.TimedOut() {
		t.Fatal("watchdog must not fire before any client data is sent")
	}
}

// CloseWrite 必须透传，否则隧道半关闭语义丢失。
func TestFirstByteGuardCloseWritePassthrough(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// 对端 CloseWrite 后应读到 EOF
		_, err = conn.Read(make([]byte, 8))
		done <- err
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	g := NewFirstByteGuard(c, time.Second)
	defer g.Close()

	if err := g.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("peer should observe EOF after CloseWrite")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CloseWrite did not propagate FIN")
	}
}

// 看门狗触发后关闭连接，后续 Write 必须返回错误而不是静默成功。
func TestFirstByteGuardWriteAfterTimeout(t *testing.T) {
	c, up := pipeConn(t)
	g := NewFirstByteGuard(c, 80*time.Millisecond)

	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := up.Read(buf); err != nil {
				return
			}
		}
	}()

	if _, err := g.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if !g.TimedOut() {
		t.Fatal("watchdog should have fired")
	}
	if _, err := g.Write([]byte("more")); err == nil || !errors.Is(err, net.ErrClosed) {
		// net.Pipe 关闭后返回 io.ErrClosedPipe，这里只要求"必须报错"
		if err == nil {
			t.Fatal("write on closed guard must fail")
		}
	}
}
