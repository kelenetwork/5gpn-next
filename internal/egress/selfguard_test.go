package egress

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// TestSelfConnectGuard 锁定 OOM 事故根因：网关连回自身接管端口形成环路。
//
// 生产实测：trace 中 target=<网关IP>:80 累计 25 万次，系统 TIME_WAIT
// 被打满 tcp_max_tw_buckets(4096)，每个 socket 在内核 slab 各占一份，
// cgroup 内存由 51MB 暴涨至 511MB 触发 OOM kill。
func TestSelfConnectGuard(t *testing.T) {
	old, hadOld := GatewayIP()
	t.Cleanup(func() {
		if hadOld {
			SetGatewayIP(old)
		} else {
			SetGatewayIP(netip.Addr{})
		}
	})

	SetGatewayIP(netip.MustParseAddr("177.0.143.37"))

	blocked := []string{
		"177.0.143.37:80",  // HTTP 接管
		"177.0.143.37:443", // TLS/QUIC 接管
		"177.0.143.37:853", // DoT
	}
	for _, addr := range blocked {
		if !IsSelfTakeover(addr) {
			t.Errorf("%s 应被判定为自连接", addr)
		}
	}

	allowed := []string{
		"177.0.143.37:20443", // 内网面板，不发起出站，不构成环路
		"177.0.143.37:22",    // SSH
		"8.8.8.8:443",        // 外部地址
		"1.1.1.1:80",
		"example.com:80", // 域名形式在本层不判定
	}
	for _, addr := range allowed {
		if IsSelfTakeover(addr) {
			t.Errorf("%s 不应被拦截", addr)
		}
	}
}

// TestSelfConnectGuardIPv4MappedIPv6 内核常以 ::ffff:a.b.c.d 形式呈现，
// 必须同样识别，否则环路会从 IPv6 路径漏过去。
func TestSelfConnectGuardIPv4Mapped(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.MustParseAddr("177.0.143.37"))

	if !IsSelfTakeover("[::ffff:177.0.143.37]:80") {
		t.Fatal("IPv4-mapped IPv6 形式的自连接未被拦截 —— 环路会从此漏过")
	}
}

// TestSelfConnectGuardDisabledWhenUnset 未登记网关 IP 时不得误拦任何流量。
func TestSelfConnectGuardDisabledWhenUnset(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.Addr{})

	for _, addr := range []string{"177.0.143.37:80", "8.8.8.8:443"} {
		if IsSelfTakeover(addr) {
			t.Errorf("未登记网关 IP 时 %s 不应被拦截", addr)
		}
	}
}

// TestDirectDialRejectsSelfConnect 拨号层必须真正拒绝，而不只是判定函数正确。
func TestDirectDialRejectsSelfConnect(t *testing.T) {
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.MustParseAddr("127.0.0.1"))

	d := NewDirect("DIRECT")
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:80"); !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("TCP 拨号应返回 ErrSelfConnect, 得到 %v", err)
	}
	if _, err := d.DialUDP(context.Background(), "127.0.0.1:443"); !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("UDP 拨号应返回 ErrSelfConnect, 得到 %v", err)
	}
}

// TestMalformedAddrDoesNotPanic 畸形地址不得导致崩溃或误拦。
func TestMalformedAddrDoesNotPanic(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("177.0.143.37"))
	SetGatewayHost("kfc.ke1e.de")

	for _, addr := range []string{"", "no-port", "177.0.143.37", ":::", "177.0.143.37:abc"} {
		if IsSelfTakeover(addr) {
			t.Errorf("畸形地址 %q 不应被判定为自连接", addr)
		}
	}
}

// TestGatewayHostnameBlockedAcrossEgresses 锁定 v0.13.8 的残余环路：
// IsSelfTakeover 只识别 IP 字面量，域名直接返回 false；且注释声称
// “解析后再检查”，实际没有第二次检查。生产用网关自身域名各发一次
// HTTP/HTTPS 请求，分别递归 1024 条连接并撞上并发闸门，cgroup 峰值
// 从约 59MB 抬到 140MB。
func TestGatewayHostnameBlockedAcrossEgresses(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("177.0.143.37"))
	SetGatewayHost("KFC.KE1E.DE.")

	for _, addr := range []string{
		"kfc.ke1e.de:80",
		"KFC.KE1E.DE:443",
		"kfc.ke1e.de.:853",
	} {
		if !IsSelfTakeover(addr) {
			t.Errorf("网关域名 %s 应被判定为自连接", addr)
		}
	}
	if IsSelfTakeover("kfc.ke1e.de:20443") {
		t.Fatal("面板端口不发起出站，不应误拦")
	}
	if IsSelfTakeover("other.example:443") {
		t.Fatal("无关域名不应误拦")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	direct := NewDirect("DIRECT")
	socks := NewSocks5("proxy", "127.0.0.1:1", false)

	checks := []struct {
		name string
		call func() error
	}{
		{"direct_tcp", func() error {
			_, err := direct.DialContext(ctx, "tcp", "kfc.ke1e.de:443")
			return err
		}},
		{"direct_udp", func() error {
			_, err := direct.DialUDP(ctx, "kfc.ke1e.de:443")
			return err
		}},
		{"socks_tcp", func() error {
			_, err := socks.DialContext(ctx, "tcp", "kfc.ke1e.de:443")
			return err
		}},
		{"socks_udp", func() error {
			_, err := socks.DialUDP(ctx, "kfc.ke1e.de:443")
			return err
		}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrSelfConnect) {
				t.Fatalf("应在发起任何网络连接前返回 ErrSelfConnect，得到 %v", err)
			}
		})
	}
}

// TestDirectDialRejectsHostnameResolvedToSelf 验证 ControlContext 的关键语义：
// 传入的是域名，前置检查无法知道其 IP；net.Dialer 解析为 127.0.0.1 后，
// 必须在 socket connect 前用实际 IP 再检查。TCP 和 UDP 都要覆盖。
func TestDirectDialRejectsHostnameResolvedToSelf(t *testing.T) {
	t.Cleanup(func() {
		SetGatewayIP(netip.Addr{})
		SetGatewayHost("")
	})
	SetGatewayIP(netip.MustParseAddr("127.0.0.1"))
	SetGatewayHost("") // 故意不登记域名，确保命中的是解析后防线。

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	direct := NewDirect("DIRECT")

	conn, err := direct.DialContext(ctx, "tcp4", "localhost:80")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("TCP 域名解析回网关后应返回 ErrSelfConnect，得到 %v", err)
	}

	// 直接走同一个 dialer 的 udp4，避免测试机 localhost 同时含 ::1 时
	// 通用 udp 的地址选择不确定；生产 Direct.DialUDP 复用的正是该 dialer。
	conn, err = direct.dialer.DialContext(ctx, "udp4", "localhost:443")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, ErrSelfConnect) {
		t.Fatalf("UDP 域名解析回网关后应返回 ErrSelfConnect，得到 %v", err)
	}
}
