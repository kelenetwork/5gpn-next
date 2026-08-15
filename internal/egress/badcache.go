package egress

import (
	"sync"
	"time"
)

// badTTL 是坏目标的记忆时长。
//
// Meta/WhatsApp 这类服务有大量 edge IP，出口对其往往只是部分可达。
// 首字节看门狗能让单条坏连接 6 秒内收敛，但 App 轮询 5~6 个坏 edge
// 仍要几十秒才轮到可用的那个（用户实测：kfc/att 出口都要等几十秒）。
//
// 记住最近失败过的目标，后续连接直接快速失败，App 便能立刻跳过它们。
// 3 分钟足够覆盖一次登录/重连过程，又不会让临时抖动被长期误判。
const badTTL = 3 * time.Minute

// maxBadEntries 限制条目数，防止被大量随机目标撑爆内存。
const maxBadEntries = 2048

// badCache 记录"最近确认无响应"的目标。
//
// 只记录首字节超时（上游静默挂死）这一种确定性失败：
// 普通拨号错误由客户端自己快速感知，无需缓存。
type badCache struct {
	mu sync.Mutex
	m  map[string]time.Time // target -> 失效时刻
}

func newBadCache() *badCache {
	return &badCache{m: make(map[string]time.Time)}
}

// mark 记录一个坏目标。
func (c *badCache) mark(target string) {
	if target == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.m) >= maxBadEntries {
		for k, exp := range c.m {
			if now.After(exp) {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < maxBadEntries {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[target] = now.Add(badTTL)
}

// bad 报告目标是否处于坏名单中；过期条目顺手清理。
func (c *badCache) bad(target string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[target]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.m, target)
		return false
	}
	return true
}

// clear 移除一个目标（连接成功时调用，立即恢复可用）。
func (c *badCache) clear(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, target)
}
