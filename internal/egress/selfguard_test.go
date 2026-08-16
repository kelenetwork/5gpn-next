package egress

import (
	"context"
	"errors"
	"net/netip"
	"testing"
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
	t.Cleanup(func() { SetGatewayIP(netip.Addr{}) })
	SetGatewayIP(netip.MustParseAddr("177.0.143.37"))

	for _, addr := range []string{"", "no-port", "177.0.143.37", ":::", "177.0.143.37:abc"} {
		if IsSelfTakeover(addr) {
			t.Errorf("畸形地址 %q 不应被判定为自连接", addr)
		}
	}
}
