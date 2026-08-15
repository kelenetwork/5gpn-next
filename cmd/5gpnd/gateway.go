package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
)

// gatewayRuntime 持有可热重载的策略引擎与出口注册表。
//
// 用原子指针整体替换，绝不复制含 sync.RWMutex 的结构体
// （那会造成数据竞争）。原先这份职责在 relay.Server 上，
// 删除 Relay 入口后独立出来，供 DoT 与 sniff 共用。
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
// 计数器实际由 sniff.Server 持有，而它在 Android 入口分支里才创建；
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

// httpService 提供 HTTPS 端点：描述文件下载、内网面板、运行状态。
//
// 删除 Relay 后这里不再需要处理 CONNECT，因此可以直接用标准
// http.ServeMux 之外的简单分发（描述文件路径含随机串，不适合 mux 前缀匹配）。
type httpService struct {
	// ProfilePath 是蜂窝 DNS 描述文件下载端点；ProfileBytes 现场生成，
	// 这样在 Bot 里开关定位修改后，重新下载即可拿到含/不含根证书的版本，
	// 无需重启服务。
	ProfilePath  string
	ProfileBytes func() ([]byte, error)

	// Panel 是内网 Web 面板处理器（可为 nil）
	Panel http.Handler

	// Stats 返回当前计数快照（可为 nil）
	Stats   func() map[string]int64
	Runtime *gatewayRuntime
	Version string
}

func (h *httpService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 描述文件下载：iOS 下载时不带任何鉴权头，
	// 路径含随机串本身即能力凭证。
	if h.ProfilePath != "" && h.ProfileBytes != nil &&
		r.Method == http.MethodGet && r.URL.Path == h.ProfilePath {
		b, err := h.ProfileBytes()
		if err != nil {
			http.Error(w, "profile unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="5gpn-next.mobileconfig"`)
		w.Write(b)
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
