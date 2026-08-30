package monitor

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeSocks5 起一个只支持 NO-AUTH CONNECT 的最小 SOCKS5 服务端。
// delay 模拟上游往返（跨境链路的耗时来源）。
func fakeSocks5(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [3]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				var hostLen int
				switch head[3] {
				case 0x01:
					hostLen = 4
				case 0x04:
					hostLen = 16
				case 0x03:
					var l [1]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					hostLen = int(l[0])
				default:
					return
				}
				addr := make([]byte, hostLen+2)
				if _, err := io.ReadFull(c, addr); err != nil {
					return
				}
				target := net.JoinHostPort(
					net.IP(addr[:hostLen]).String(),
					itoa(binary.BigEndian.Uint16(addr[hostLen:])),
				)
				// 模拟上游 RTT：真实出口的延迟就产生在这一段。
				time.Sleep(delay)
				up, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// fakeHTTP 起一个连通性探针 HTTP 服务端，模拟 cp.cloudflare.com /generate_204。
func fakeHTTP(t *testing.T, statusLine string) string {
	t.Helper()
	if statusLine == "" {
		statusLine = "HTTP/1.1 204 No Content"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(c, statusLine+"\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().String()
}

// 端到端探测必须测到真实链路耗时，而不是本机 loopback 的几十微秒。
func TestDialProbeEndToEndMeasuresRealPath(t *testing.T) {
	const upstreamDelay = 60 * time.Millisecond
	bridge := fakeSocks5(t, upstreamDelay)
	remote := fakeHTTP(t, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d, err := dialProbe(ctx, Target{
		Addr: bridge, Socks5: true, Remote: remote, Path: DefaultProbePath, Kind: ProbeKindEndToEnd,
	})
	if err != nil {
		t.Fatalf("端到端探测失败: %v", err)
	}
	if d < upstreamDelay {
		t.Fatalf("耗时 %v 小于上游模拟延迟 %v——说明根本没测到链路", d, upstreamDelay)
	}
	if d > 3*time.Second {
		t.Fatalf("耗时 %v 异常", d)
	}
	if FormatUS(d.Microseconds()) == "0ms" {
		t.Fatal("端到端结果不应格式化为 0ms")
	}
}

// 没有 Remote 时退回桥探测：只做版本协商，耗时是 loopback 级别。
func TestDialProbeBridgeOnlyStaysLocal(t *testing.T) {
	bridge := fakeSocks5(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	d, err := dialProbe(ctx, Target{Addr: bridge, Socks5: true, Kind: ProbeKindBridge})
	if err != nil {
		t.Fatalf("桥探测失败: %v", err)
	}
	if d > 100*time.Millisecond {
		t.Fatalf("桥探测耗时 %v 过大", d)
	}
	// 亚毫秒必须能显示出来，不能再是 0ms。
	if got := FormatUS(d.Microseconds()); got == "0ms" {
		t.Fatalf("桥探测格式化为 %q，仍会被误判成监控故障", got)
	}
}

// 远端不可达时必须报错，而不是因为 mihomo 乐观回包就算成功。
func TestDialProbeEndToEndFailsWhenRemoteDown(t *testing.T) {
	bridge := fakeSocks5(t, 0)
	// 占一个端口再立刻释放，得到一个大概率无人监听的地址。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialProbe(ctx, Target{
		Addr: bridge, Socks5: true, Remote: dead, Kind: ProbeKindEndToEnd,
	}); err == nil {
		t.Fatal("远端不可达时探测必须失败")
	}
}

// HTTP 4xx/5xx 必须记失败：CONNECT 通了但应用层不通，不能当做出口正常。
func TestDialProbeEndToEndFailsOnHTTPError(t *testing.T) {
	bridge := fakeSocks5(t, 0)
	remote := fakeHTTP(t, "HTTP/1.1 502 Bad Gateway")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := dialProbe(ctx, Target{
		Addr: bridge, Socks5: true, Remote: remote, Path: DefaultProbePath, Kind: ProbeKindEndToEnd,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 状态异常") {
		t.Fatalf("err=%v", err)
	}
}

// 非 SOCKS5 出口保持裸 TCP 建连语义。
func TestDialProbePlainTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialProbe(ctx, Target{Addr: ln.Addr().String(), Kind: ProbeKindNode}); err != nil {
		t.Fatalf("裸 TCP 探测失败: %v", err)
	}
}

// 探测目标格式非法时必须早失败，且错误信息可定位。
func TestDialProbeRejectsBadRemote(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := dialProbe(ctx, Target{Addr: "127.0.0.1:1", Socks5: true, Remote: "no-port"})
	if err == nil || !strings.Contains(err.Error(), "格式错误") {
		t.Fatalf("err=%v", err)
	}
}
