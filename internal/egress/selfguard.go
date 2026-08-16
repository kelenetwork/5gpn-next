package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
)

// ErrSelfConnect 表示目标地址就是网关自身的接管端口，拨号会形成环路。
var ErrSelfConnect = errors.New("目标为网关自身接管端口，已阻断自连接环路")

// 接管端口：DoT 改写把域名指向网关 IP，客户端流量因而落到这些端口。
// 若出站再连回同一 IP 的同一端口，就会自己连自己。
var takeoverPorts = map[int]struct{}{
	80:  {},
	443: {},
	853: {},
}

var (
	selfMu   sync.RWMutex
	selfAddr netip.Addr
	selfHost string
)

// SetGatewayIP 登记网关自身 IP，供自连接防护使用。
//
// 事故背景：DoT 把代理域名的 A 记录改写成网关 IP，流量落到网关的
// 80/443 接管端口。若此后的出站拨号仍解析到同一个网关 IP（例如域名
// 在上游被解析回本机、或客户端把网关 IP 当作目标直接发起请求），
// 网关就会连回自己的接管端口，接管逻辑再次发起出站，如此往复。
//
// 生产实测：trace 中 target=<网关IP>:80 累计出现 25 万次，系统
// TIME_WAIT 被瞬间打满 tcp_max_tw_buckets(4096)，每个 socket 在内核
// slab 里各占一份，cgroup 内存从 51MB 暴涨到 511MB 触发 OOM kill。
// 这类内核记账既不受 GOMEMLIMIT 约束，也无法由应用侧回收。
func SetGatewayIP(ip netip.Addr) {
	selfMu.Lock()
	selfAddr = ip.Unmap()
	selfMu.Unlock()
}

// GatewayIP 返回已登记的网关 IP。
func GatewayIP() (netip.Addr, bool) {
	selfMu.RLock()
	defer selfMu.RUnlock()
	return selfAddr, selfAddr.IsValid()
}

// SetGatewayHost 登记网关自身域名，供所有出口在 DNS 解析前快速拦截。
// 域名统一转为小写并去掉尾点，避免大小写或 FQDN 尾点绕过。
func SetGatewayHost(host string) {
	selfMu.Lock()
	selfHost = normalizeHost(host)
	selfMu.Unlock()
}

// GatewayHost 返回已登记的规范化网关域名。
func GatewayHost() (string, bool) {
	selfMu.RLock()
	defer selfMu.RUnlock()
	return selfHost, selfHost != ""
}

// IsSelfTakeover 报告该地址是否明确指向网关自身的接管端口。
//
// 只拦截接管端口：网关本身可能合法地访问自己的其它服务（如面板），
// 一律拦截会误伤。非接管端口不构成环路，因为那些端口不会再发起出站。
//
// 域名先与已登记的网关域名精确比较；DIRECT 经过 DNS 解析后还会由
// guardResolvedSelfTakeover 对 net.Dialer 选中的实际 IP 再检查，防住
// CNAME/别名解析回网关 IP 的情况。
func IsSelfTakeover(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return false
	}
	if _, hit := takeoverPorts[port]; !hit {
		return false
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		self, ok := GatewayIP()
		return ok && ip.Unmap() == self
	}

	self, ok := GatewayHost()
	return ok && normalizeHost(host) == self
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(host, ".")
}

// guardResolvedSelfTakeover 是 DIRECT net.Dialer 的最后一道防线。
//
// ControlContext 在 DNS 解析完成、socket connect 发生前被调用；此时
// address 已是 net.Dialer 实际选中的 IP:port。原实现只在解析前检查
// addr，域名会直接放过，且注释声称“解析后再检查”但实际没有调用点。
// 生产验证中，对网关自身域名各发一次 HTTP/HTTPS 请求，就分别递归出
// 1024 条连接并撞上并发闸门，cgroup 峰值由 59MB 抬到约 140MB。
func guardResolvedSelfTakeover(_ context.Context, _ string, address string, _ syscall.RawConn) error {
	if IsSelfTakeover(address) {
		return ErrSelfConnect
	}
	return nil
}
