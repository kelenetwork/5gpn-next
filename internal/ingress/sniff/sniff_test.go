package sniff

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPeekHTTPHostDoesNotBlockOnShortRequest 锁定线上事故：
//
// 旧实现一次性 br.Peek(4096)，而 bufio.Peek(n) 会阻塞到凑满 n 字节。
// 普通 HTTP 请求头只有一两百字节，永远凑不满，于是每条 HTTP 连接都
// 干等到读超时（实测固定 8s）才继续，Play 的明文回源下载卡在“等待中”。
//
// 本用例用一条不再写入、也不关闭的真实连接复现该场景：若实现会阻塞，
// 测试超时失败；正确实现应立刻解析出 Host。
func TestPeekHTTPHostDoesNotBlockOnShortRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = c1.Write([]byte(
			"GET /generate_204 HTTP/1.1\r\n" +
				"Host: connectivitycheck.gstatic.com\r\n" +
				"User-Agent: probe\r\n" +
				"Connection: close\r\n\r\n"))
		// 关键：不再写入，也不关闭，模拟客户端等待响应。
	}()

	type result struct {
		host string
		port int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		br := bufio.NewReaderSize(c2, 8*1024)
		h, p, err := peekHost(br, false)
		done <- result{h, p, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("解析 Host 失败: %v", got.err)
		}
		if got.host != "connectivitycheck.gstatic.com" {
			t.Fatalf("Host = %q, 期望 connectivitycheck.gstatic.com", got.host)
		}
		if got.port != 80 {
			t.Fatalf("port = %d, 期望 80", got.port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peekHTTPHost 在短请求上阻塞了——4096 字节 Peek 回归")
	}
}

// TestPeekHTTPHostHeaderSplitAcrossSegments 头部跨 TCP 段到达时仍应解析成功。
func TestPeekHTTPHostHeaderSplitAcrossSegments(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = c1.Write([]byte("GET /path HTTP/1.1\r\n"))
		time.Sleep(30 * time.Millisecond)
		_, _ = c1.Write([]byte("Host: dl.goo"))
		time.Sleep(30 * time.Millisecond)
		_, _ = c1.Write([]byte("gle.com\r\n\r\n"))
	}()

	done := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReaderSize(c2, 8*1024)
		h, err := peekHTTPHost(br)
		if err != nil {
			errc <- err
			return
		}
		done <- h
	}()

	select {
	case h := <-done:
		if h != "dl.google.com" {
			t.Fatalf("Host = %q, 期望 dl.google.com", h)
		}
	case err := <-errc:
		t.Fatalf("解析失败: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("跨段头部解析阻塞")
	}
}

// TestPeekHTTPHostPortInHost Host 带端口时应拆出端口。
func TestPeekHTTPHostPortInHost(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader(
		"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"), 8*1024)
	h, p, err := peekHost(br, false)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if h != "example.com" || p != 8080 {
		t.Fatalf("得到 %s:%d, 期望 example.com:8080", h, p)
	}
}

// TestPeekHTTPHostNoHostHeader 无 Host 头应返回 ErrNoHost，交由 DNS 线索兜底。
func TestPeekHTTPHostNoHostHeader(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader(
		"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n"), 8*1024)
	_, err := peekHTTPHost(br)
	if !errors.Is(err, ErrNoHost) {
		t.Fatalf("err = %v, 期望 ErrNoHost", err)
	}
}

// TestPeekHTTPHostDoesNotConsume 窥探不得消费数据，否则转发给上游的请求会缺头。
func TestPeekHTTPHostDoesNotConsume(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: dl.google.com\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(raw), 8*1024)
	if _, err := peekHTTPHost(br); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rest, err := br.Peek(len(raw))
	if err != nil {
		t.Fatalf("窥探后数据缺失: %v", err)
	}
	if string(rest) != raw {
		t.Fatalf("窥探消费了数据：\n得到 %q\n期望 %q", string(rest), raw)
	}
}
