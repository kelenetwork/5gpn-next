// Package policy 实现有序 first-match 的分流决策引擎。
//
// 三层分流模型（见 docs/ARCHITECTURE.md）：
//
//	第一层  手机侧 ExcludedDomains —— 国内头部域名根本不出手机（性能）
//	第二层  网关侧本包 —— 凡到达网关的连接都带明确目的地，用完整规则库判定（正确性）
//	第三层  自学习 —— 反复经过网关的国内域名回填第一层名单
//
// P0 实测结论驱动的两个硬约束：
//  1. 裸 IP 目标绕不过手机侧名单，GEOIP 判定是必需品而非可选项。
//  2. 出口无 IPv6 时，IPv6 字面量目标必须 fail-fast，否则 App 判定"无网络连接"。
package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/ruleset"
)

// Action 是决策结果。
type Action string

const (
	ActionDirect Action = "direct" // 网关本机直出
	ActionProxy  Action = "proxy"  // 交给指定出口
	ActionBlock  Action = "block"  // 拒绝
)

// Decision 是一次判定的完整结果，用于 trace 与审计。
type Decision struct {
	Action Action
	Egress string // ActionProxy 时的出口名
	Rule   string // 命中的规则描述，便于用户自助排障
	Index  int    // 命中规则在列表中的序号；-1 表示落到 final
}

// RuleKind 是规则类型。
type RuleKind string

const (
	KindDomain        RuleKind = "DOMAIN"
	KindDomainSuffix  RuleKind = "DOMAIN-SUFFIX"
	KindDomainKeyword RuleKind = "DOMAIN-KEYWORD"
	KindIPCIDR        RuleKind = "IP-CIDR"
	KindRuleSet       RuleKind = "RULE-SET"
	KindGeoIP         RuleKind = "GEOIP"
	KindFinal         RuleKind = "FINAL"
)

// Rule 是一条有序规则。
type Rule struct {
	Kind    RuleKind
	Value   string
	Action  Action
	Egress  string
	domains *ruleset.DomainSet // KindRuleSet(domain) 用
	cidrs   *ruleset.CIDRSet   // KindRuleSet(ipcidr) / KindGeoIP 用
	prefix  netip.Prefix       // KindIPCIDR 用
	hasPfx  bool
}

// Engine 持有规则列表与命名规则集。
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
	final Decision

	// 命名规则集：供 RULE-SET / GEOIP 引用
	domainSets map[string]*ruleset.DomainSet
	cidrSets   map[string]*ruleset.CIDRSet

	// egressHasV6 决定 IPv6 字面量目标是否 fail-fast
	egressHasV6 bool

	// DNS 缓存用于“域名解析后再匹配 IP-CIDR/GEOIP”。
	// Engine 在热重载时整体替换，缓存自然随规则生命周期清空。
	resolveMu    sync.RWMutex
	resolveCache map[string]resolveEntry
}

type resolveEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

// New 返回默认引擎：final 走 proxy（其余国际出海）。
func New() *Engine {
	return &Engine{
		final:        Decision{Action: ActionProxy, Rule: "FINAL", Index: -1},
		domainSets:   make(map[string]*ruleset.DomainSet),
		cidrSets:     make(map[string]*ruleset.CIDRSet),
		resolveCache: make(map[string]resolveEntry),
	}
}

// SetEgressHasV6 声明出口是否具备 IPv6 能力。
func (e *Engine) SetEgressHasV6(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.egressHasV6 = v
}

// EgressHasV6 返回出口 IPv6 能力。
func (e *Engine) EgressHasV6() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.egressHasV6
}

// RegisterDomainSet 注册域名规则集，供 RULE-SET 引用。
func (e *Engine) RegisterDomainSet(name string, ds *ruleset.DomainSet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.domainSets[name] = ds
}

// RegisterCIDRSet 注册 CIDR 规则集，供 RULE-SET / GEOIP 引用。
func (e *Engine) RegisterCIDRSet(name string, cs *ruleset.CIDRSet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cidrSets[name] = cs
}

// SetFinal 设置兜底动作。FINAL 只处理未命中任何规则的流量。
func (e *Engine) SetFinal(a Action, egress string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.final = Decision{Action: a, Egress: egress, Rule: "FINAL", Index: -1}
}

// Final 返回当前运行态的兜底决策。
func (e *Engine) Final() Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.final
}

// DomesticRulesReady 报告国内直连的两套强制规则是否都已有效载入。
// 仅“注册了名字”不够，空规则集同样视为未就绪。
func (e *Engine) DomesticRulesReady() bool {
	e.mu.RLock()
	ds := e.domainSets["cn-domain"]
	cs := e.cidrSets["geoip:cn"]
	e.mu.RUnlock()
	return ds != nil && ds.Len() > 0 && cs != nil && cs.Len() > 0
}

// AddRule 追加一条规则，顺序即优先级。
func (e *Engine) AddRule(r Rule) error {
	switch r.Kind {
	case KindIPCIDR:
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return fmt.Errorf("IP-CIDR %q 解析失败: %w", r.Value, err)
		}
		r.prefix = p.Masked()
		r.hasPfx = true

	case KindRuleSet:
		e.mu.RLock()
		ds, okD := e.domainSets[r.Value]
		cs, okC := e.cidrSets[r.Value]
		e.mu.RUnlock()
		if !okD && !okC {
			return fmt.Errorf("RULE-SET %q 未注册", r.Value)
		}
		r.domains, r.cidrs = ds, cs

	case KindGeoIP:
		e.mu.RLock()
		cs, ok := e.cidrSets["geoip:"+strings.ToLower(r.Value)]
		e.mu.RUnlock()
		if !ok {
			return fmt.Errorf("GEOIP %q 未注册", r.Value)
		}
		r.cidrs = cs

	case KindDomain, KindDomainSuffix, KindDomainKeyword:
		if r.Value == "" {
			return fmt.Errorf("%s 规则值为空", r.Kind)
		}

	case KindFinal:
		e.SetFinal(r.Action, r.Egress)
		return nil

	default:
		return fmt.Errorf("未知规则类型 %q", r.Kind)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	return nil
}

// Len 返回规则条数。
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Target 是一次待判定的连接目标。
type Target struct {
	Host string // 域名或 IP 字面量（不含端口）
	Port int
	addr netip.Addr
	isIP bool
}

// ParseTarget 从 "host:port" 解析目标；自动识别 IP 字面量。
func ParseTarget(hostport string) (Target, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// 容忍不带端口
		host = strings.Trim(hostport, "[]")
		portStr = "443"
	}
	t := Target{Host: strings.ToLower(strings.TrimSuffix(host, "."))}
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		t.Port = p
	} else {
		t.Port = 443
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		t.addr = a.Unmap()
		t.isIP = true
	}
	return t, nil
}

// IsIP 表示目标是裸 IP（无域名可匹配）。
func (t Target) IsIP() bool { return t.isIP }

// Addr 返回 IP 字面量地址。
func (t Target) Addr() netip.Addr { return t.addr }

// Match 执行有序 first-match 判定。域名不做 DNS 解析；需要让
// IP-CIDR/GEOIP 同时作用于域名时使用 MatchContext 或 MatchResolved。
func (e *Engine) Match(t Target) Decision {
	return e.matchResolved(t, nil)
}

// MatchContext 先解析域名，再按原始规则顺序同时匹配域名与目标 IP。
// 正向结果缓存 5 分钟；解析失败时退回纯域名规则，不阻断连接。
func (e *Engine) MatchContext(ctx context.Context, t Target) Decision {
	if t.isIP || t.Host == "" {
		return e.Match(t)
	}
	return e.MatchResolved(t, e.resolve(ctx, t.Host))
}

// MatchResolved 使用调用方已解析的地址参与 IP-CIDR/GEOIP 判定。
// Android DoT 使用其上游 DNS 的真实应答调用此方法，避免重复解析。
func (e *Engine) MatchResolved(t Target, addrs []netip.Addr) Decision {
	return e.matchResolved(t, normalizeAddrs(addrs))
}

func (e *Engine) matchResolved(t Target, addrs []netip.Addr) Decision {
	e.mu.RLock()
	rules := e.rules
	final := e.final
	e.mu.RUnlock()

	for i, r := range rules {
		if !r.matches(t, addrs) {
			continue
		}
		return Decision{
			Action: r.Action,
			Egress: r.Egress,
			Rule:   fmt.Sprintf("%s,%s", r.Kind, r.Value),
			Index:  i,
		}
	}
	return final
}

func (e *Engine) resolve(ctx context.Context, host string) []netip.Addr {
	now := time.Now()
	e.resolveMu.RLock()
	cached, ok := e.resolveCache[host]
	e.resolveMu.RUnlock()
	if ok && now.Before(cached.expire) {
		return append([]netip.Addr(nil), cached.addrs...)
	}

	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil
	}
	addrs = normalizeAddrs(addrs)
	if len(addrs) == 0 {
		return nil
	}
	e.resolveMu.Lock()
	e.resolveCache[host] = resolveEntry{
		addrs:  append([]netip.Addr(nil), addrs...),
		expire: now.Add(5 * time.Minute),
	}
	e.resolveMu.Unlock()
	return addrs
}

func normalizeAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	seen := make(map[netip.Addr]struct{}, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func (r Rule) matches(t Target, resolved []netip.Addr) bool {
	matchAddr := func(fn func(netip.Addr) bool) bool {
		if t.isIP && fn(t.addr) {
			return true
		}
		for _, a := range resolved {
			if fn(a) {
				return true
			}
		}
		return false
	}

	switch r.Kind {
	case KindDomain:
		return !t.isIP && t.Host == strings.ToLower(r.Value)

	case KindDomainSuffix:
		if t.isIP {
			return false
		}
		v := strings.ToLower(strings.TrimPrefix(r.Value, "."))
		return t.Host == v || strings.HasSuffix(t.Host, "."+v)

	case KindDomainKeyword:
		return !t.isIP && strings.Contains(t.Host, strings.ToLower(r.Value))

	case KindIPCIDR:
		return r.hasPfx && matchAddr(r.prefix.Contains)

	case KindGeoIP:
		return r.cidrs != nil && matchAddr(r.cidrs.Match)

	case KindRuleSet:
		if !t.isIP && r.domains != nil && r.domains.Match(t.Host) {
			return true
		}
		return r.cidrs != nil && matchAddr(r.cidrs.Match)
	}
	return false
}
