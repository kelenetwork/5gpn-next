// Package ruleset 提供域名与 CIDR 规则集的加载和高速匹配。
package ruleset

import (
	"strings"
	"sync"
)

// DomainSet 以反向标签树存储域名规则，支持精确与后缀匹配。
//
// 规则形态（兼容 clash / mihomo 常见写法）：
//
//	example.com          后缀匹配（含自身及所有子域）
//	+.example.com        同上
//	.example.com         同上
//	full:example.com     仅精确匹配
//	domain:example.com   后缀匹配
//	keyword:foo          子串匹配
type DomainSet struct {
	mu       sync.RWMutex
	root     *node
	exact    map[string]struct{}
	keywords []string
	count    int
}

type node struct {
	children map[string]*node
	// terminal 表示到此为止即构成一条后缀规则
	terminal bool
}

func newNode() *node {
	return &node{children: make(map[string]*node, 4)}
}

// NewDomainSet 返回空集合。
func NewDomainSet() *DomainSet {
	return &DomainSet{
		root:  newNode(),
		exact: make(map[string]struct{}),
	}
}

// Len 返回已载入的规则条数。
func (d *DomainSet) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.count
}

// AddRule 解析并加入一条规则；空行与 # 注释被忽略。
func (d *DomainSet) AddRule(raw string) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return
	}
	// 去掉行尾注释
	if i := strings.IndexAny(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
		if line == "" {
			return
		}
	}

	switch {
	case strings.HasPrefix(line, "keyword:"):
		kw := strings.ToLower(strings.TrimSpace(line[len("keyword:"):]))
		if kw == "" {
			return
		}
		d.mu.Lock()
		d.keywords = append(d.keywords, kw)
		d.count++
		d.mu.Unlock()
		return

	case strings.HasPrefix(line, "full:"):
		host := normalizeHost(line[len("full:"):])
		if host == "" {
			return
		}
		d.mu.Lock()
		d.exact[host] = struct{}{}
		d.count++
		d.mu.Unlock()
		return

	case strings.HasPrefix(line, "domain:"):
		line = line[len("domain:"):]
	case strings.HasPrefix(line, "+."):
		line = line[2:]
	case strings.HasPrefix(line, "."):
		line = line[1:]
	}

	host := normalizeHost(line)
	if host == "" {
		return
	}
	d.addSuffix(host)
}

func (d *DomainSet) addSuffix(host string) {
	labels := strings.Split(host, ".")
	d.mu.Lock()
	defer d.mu.Unlock()
	cur := d.root
	// 反向插入：com -> example
	for i := len(labels) - 1; i >= 0; i-- {
		l := labels[i]
		if l == "" {
			continue
		}
		next, ok := cur.children[l]
		if !ok {
			next = newNode()
			cur.children[l] = next
		}
		cur = next
	}
	if !cur.terminal {
		cur.terminal = true
		d.count++
	}
}

// Match 判断 host 是否命中集合。
func (d *DomainSet) Match(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if _, ok := d.exact[h]; ok {
		return true
	}

	labels := strings.Split(h, ".")
	cur := d.root
	for i := len(labels) - 1; i >= 0; i-- {
		next, ok := cur.children[labels[i]]
		if !ok {
			break
		}
		cur = next
		if cur.terminal {
			return true
		}
	}

	for _, kw := range d.keywords {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

// normalizeHost 统一小写、去尾点、去端口、去 IPv6 方括号。
func normalizeHost(s string) string {
	h := strings.TrimSpace(strings.ToLower(s))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}
