// Package hint 维护「客户端 → 最近被改写到网关的域名」的短时关联。
//
// 用途：DNS 模式下，无 SNI 的私有协议（如 WhatsApp Noise over 443）
// 无法从首包嗅探出目的地。但客户端在建连前必然先经 DoT 查询过该域名，
// 且 A 记录被改写到网关 —— 这条 DNS 查询就是目的地的最佳线索。
// 嗅探失败时，用该客户端最近一次被改写的域名回退还原目标。
//
// 关联是启发式的：同一客户端在窗口内查询多个代理域名时可能取错。
// 因此只作为 SNI/Host 嗅探失败后的兜底，绝不覆盖显式嗅探结果。
package hint

import (
	"sync"
	"time"
)

const (
	// ttl 是线索有效期。App 在 DNS 应答后通常立即建连，
	// 30 秒足够覆盖重试；过长会放大错误关联。
	ttl = 30 * time.Second
	// maxClients 限制客户端数量，防止伪造源地址撑爆内存。
	maxClients = 4096
	// perClient 每客户端保留的最近域名数。
	perClient = 8
)

type entry struct {
	host string
	at   time.Time
}

// Store 是并发安全的短时关联表。
type Store struct {
	mu sync.Mutex
	m  map[string][]entry
}

// New 构造空表。
func New() *Store {
	return &Store{m: make(map[string][]entry)}
}

// Add 记录一次「client 查询了 host 且被改写到网关」。
func (s *Store) Add(client, host string) {
	if client == "" || host == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[client]; !ok && len(s.m) >= maxClients {
		// 先清过期客户端；仍满则任意淘汰，保证有界。
		for k, es := range s.m {
			if len(es) == 0 || now.Sub(es[len(es)-1].at) > ttl {
				delete(s.m, k)
			}
		}
		for k := range s.m {
			if len(s.m) < maxClients {
				break
			}
			delete(s.m, k)
		}
	}

	es := s.m[client]
	// 同域名刷新时间戳即可，避免重复占位
	for i := range es {
		if es[i].host == host {
			es[i].at = now
			s.m[client] = es
			return
		}
	}
	es = append(es, entry{host: host, at: now})
	if len(es) > perClient {
		es = es[len(es)-perClient:]
	}
	s.m[client] = es
}

// Lookup 返回 client 最近一次未过期的域名线索。
// 不消费线索：同一 App 可能对同一域名开多条连接。
func (s *Store) Lookup(client string) (string, bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	es := s.m[client]
	for i := len(es) - 1; i >= 0; i-- {
		if now.Sub(es[i].at) <= ttl {
			return es[i].host, true
		}
	}
	return "", false
}
