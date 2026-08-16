package egress

import (
	"errors"
	"net"
	"net/netip"
	"sync"
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

// IsSelfTakeover 报告该地址是否指向网关自身的接管端口。
//
// 只拦截接管端口：网关本身可能合法地访问自己的其它服务（如面板），
// 一律拦截会误伤。非接管端口不构成环路，因为那些端口不会再发起出站。
func IsSelfTakeover(addr string) bool {
	self, ok := GatewayIP()
	if !ok {
		return false
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false // 域名形式在此层不判定，由解析后的地址再检查
	}
	if ip.Unmap() != self {
		return false
	}
	port, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", portStr))
	if err != nil {
		return false
	}
	_, hit := takeoverPorts[int(port.Port())]
	return hit
}
