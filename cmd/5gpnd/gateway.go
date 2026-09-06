package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"

	"github.com/w0ven/5gpn-next/internal/egress"
	"github.com/w0ven/5gpn-next/internal/policy"
)

// gatewayRuntime 持有可热重载的策略引擎与出口注册表。
//
// 用原子指针整体替换，绝不复制含 sync.RWMutex 的结构体
// （那会造成数据竞争）；DoT 与 sniff 共用这一层运行态。
type gatewayRuntime struct {
	pol atomic.Pointer[policy.Engine]
	eg  atomic.Pointer[egress.Registry]
}

func (g *gatewayRuntime) SetRuntime(p *policy.Engine, e *egress.Registry) {
	g.pol.Store(p)
	g.eg.Store(e)
}

func (g *gatewayRuntime) Policy() *policy.Engine   { return g.pol.Load() }
func (g *gatewayRuntime) Egress() *egress.Registry { return g.eg.Load() }

// statsFunc 把闭包适配为 manage.StatsSource。
//
// 计数器实际由 sniff.Server 持有，而它在加密 DNS 入口分支里才创建；
// 用闭包延迟读取，避免为了取数把整段初始化顺序打乱。
type statsFunc func() map[string]int64

func (f statsFunc) Snapshot() map[string]int64 { return f() }

// dnsCounters 记录 DoT 判定分布，补充 sniff 侧的连接级计数。
type dnsCounters struct {
	Query  atomic.Int64
	Direct atomic.Int64
	Proxy  atomic.Int64
	Block  atomic.Int64
}

func (c *dnsCounters) record(action string) {
	c.Query.Add(1)
	switch action {
	case "direct":
		c.Direct.Add(1)
	case "proxy":
		c.Proxy.Add(1)
	case "block":
		c.Block.Add(1)
	}
}

// httpService 提供 HTTPS 端点：描述文件下载、内网面板与运行状态。
// 描述文件路径含随机串，不适合按固定前缀挂到 http.ServeMux。
type httpService struct {
	// ProfilePath / ProfileBytes 是蜂窝 DNS 描述文件下载端点
	ProfilePath  string
	ProfileBytes []byte

	// Panel 是内网 Web 面板处理器（可为 nil）
	Panel http.Handler

	// Stats 返回当前计数快照（可为 nil）
	Stats   func() map[string]int64
	Runtime *gatewayRuntime
	Version string

	// ClientCIDR 限定描述文件、状态端点与面板的来源。面板内部还有一层
	// 校验；这里覆盖随机下载路径和 /5gpn/stats，避免只靠 nftables。
	ClientCIDR netip.Prefix
}

func (h *httpService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !remoteAllowed(r.RemoteAddr, h.ClientCIDR) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 描述文件下载：iOS 下载时不带任何鉴权头，
	// 路径含随机串本身即能力凭证。
	if h.ProfilePath != "" && r.Method == http.MethodGet && r.URL.Path == h.ProfilePath {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="5gpn-next.mobileconfig"`)
		w.Write(h.ProfileBytes)
		return
	}

	if r.URL.Path == "/5gpn/stats" {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"version": h.Version}
		if h.Stats != nil {
			for k, v := range h.Stats() {
				out[k] = v
			}
		}
		if rt := h.Runtime; rt != nil {
			if p := rt.Policy(); p != nil {
				out["rules"] = p.Len()
			}
			if e := rt.Egress(); e != nil {
				out["egress"] = e.Names()
			}
		}
		json.NewEncoder(w).Encode(out)
		return
	}

	if h.Panel != nil {
		h.Panel.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func remoteAllowed(remote string, allowed netip.Prefix) bool {
	if !allowed.IsValid() {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || allowed.Contains(ip)
}
