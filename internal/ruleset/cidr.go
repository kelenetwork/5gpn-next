package ruleset

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// CIDRSet 存储 IP 前缀集合，用于 GEOIP 判定。
//
// 实测发现：iOS Relay 会直接把裸 IP 交给网关（Twitter/Dropbox/XMPP 推送等），
// 这类连接没有域名可匹配，必须靠 CIDR 判定归属，否则国内 App 的直连部分会绕道。
type CIDRSet struct {
	mu sync.RWMutex
	v4 []netip.Prefix
	v6 []netip.Prefix
}

func NewCIDRSet() *CIDRSet {
	return &CIDRSet{}
}

func (c *CIDRSet) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.v4) + len(c.v6)
}

// AddRule 接受 "1.2.3.0/24" 或裸 IP。
func (c *CIDRSet) AddRule(raw string) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// 兼容 "IP-CIDR,1.2.3.0/24" 这类前缀
	if i := strings.LastIndex(line, ","); i >= 0 {
		cand := strings.TrimSpace(line[i+1:])
		if strings.Contains(cand, "/") || strings.Contains(cand, ".") || strings.Contains(cand, ":") {
			if _, err := netip.ParsePrefix(cand); err == nil {
				line = cand
			}
		}
	}
	if !strings.Contains(line, "/") {
		addr, err := netip.ParseAddr(line)
		if err != nil {
			return
		}
		bits := addr.BitLen()
		line = addr.String() + "/" + itoa(bits)
	}
	p, err := netip.ParsePrefix(line)
	if err != nil {
		return
	}
	p = p.Masked()

	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Addr().Is4() {
		c.v4 = append(c.v4, p)
	} else {
		c.v6 = append(c.v6, p)
	}
}

// Finalize 排序以便二分查找；载入完成后调用一次。
func (c *CIDRSet) Finalize() {
	c.mu.Lock()
	defer c.mu.Unlock()
	sortPrefixes(c.v4)
	sortPrefixes(c.v6)
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Addr().Less(ps[j].Addr())
	})
}

// Match 判断地址是否落在集合内。
func (c *CIDRSet) Match(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()

	c.mu.RLock()
	defer c.mu.RUnlock()

	list := c.v4
	if addr.Is6() {
		list = c.v6
	}
	if len(list) == 0 {
		return false
	}

	// 找到第一个起始地址 > addr 的位置，从其前一个开始向前回溯匹配
	i := sort.Search(len(list), func(i int) bool {
		return addr.Less(list[i].Addr())
	})
	for j := i - 1; j >= 0 && j >= i-64; j-- {
		if list[j].Contains(addr) {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
