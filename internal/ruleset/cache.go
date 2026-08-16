package ruleset

import (
	"fmt"
	"os"
	"sync"
)

// 规则集解析结果缓存。
//
// DomainSet / CIDRSet 载入后是只读的：匹配路径只走 RLock，从不修改内容。
// 但热重载会重新构建整个策略引擎，旧实现每次都从磁盘重新解析一遍
// （cn-domain 11 万条 + ad-block 10 万条，实测每套约 11.8MB 常驻堆）。
// 重建期间新旧引擎并存，四套规则集同时在内存里，峰值撞破 cgroup 上限
// 被 OOM kill —— 生产实测由此产生 OOM→重启→再 OOM 的死循环。
//
// 既然内容只读且按文件寻址，就可以在解析结果之间安全共享：只要文件的
// 修改时间与大小没变，就直接复用已解析对象，热重载不再产生任何新分配。
//
// 并发去重同样重要：启动与热重载可能并发触发同一文件的首次解析，若不
// 合并，多个 goroutine 会各解析一份数 MB 的规则集，恰好在内存峰值时刻
// 火上浇油。这里用每个 key 一个 entry + sync.Once 做单飞。
type cacheKey struct {
	path string
	size int64
	mod  int64
}

type domainEntry struct {
	once sync.Once
	ds   *DomainSet
	err  error
}

type cidrEntry struct {
	once sync.Once
	cs   *CIDRSet
	err  error
}

var (
	dsMu    sync.Mutex
	dsCache = map[cacheKey]*domainEntry{}

	csMu    sync.Mutex
	csCache = map[cacheKey]*cidrEntry{}
)

func keyOf(path string) (cacheKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return cacheKey{}, err
	}
	if st.Size() == 0 {
		return cacheKey{}, fmt.Errorf("规则集文件为空: %s", path)
	}
	return cacheKey{path: path, size: st.Size(), mod: st.ModTime().UnixNano()}, nil
}

// LoadDomainFileCached 返回该文件对应的域名规则集，命中缓存时零分配复用。
//
// 文件被替换（大小或 mtime 变化）时自动重新解析，并丢弃该路径的旧条目，
// 避免规则库长期更新后缓存无限增长。
func LoadDomainFileCached(path string) (*DomainSet, error) {
	k, err := keyOf(path)
	if err != nil {
		return nil, err
	}

	dsMu.Lock()
	e, ok := dsCache[k]
	if !ok {
		e = &domainEntry{}
		// 同路径的旧版本已失效，清掉再存，防止无界增长。
		for old := range dsCache {
			if old.path == k.path && old != k {
				delete(dsCache, old)
			}
		}
		dsCache[k] = e
	}
	dsMu.Unlock()

	// 解析在锁外进行，同一 key 的并发调用只解析一次。
	e.once.Do(func() { e.ds, e.err = LoadDomainFile(path) })
	if e.err != nil {
		// 解析失败不留污染条目，允许后续重试。
		dsMu.Lock()
		if cur, ok := dsCache[k]; ok && cur == e {
			delete(dsCache, k)
		}
		dsMu.Unlock()
		return nil, e.err
	}
	return e.ds, nil
}

// LoadCIDRFileCached 返回该文件对应的 CIDR 规则集，命中缓存时零分配复用。
func LoadCIDRFileCached(path string) (*CIDRSet, error) {
	k, err := keyOf(path)
	if err != nil {
		return nil, err
	}

	csMu.Lock()
	e, ok := csCache[k]
	if !ok {
		e = &cidrEntry{}
		for old := range csCache {
			if old.path == k.path && old != k {
				delete(csCache, old)
			}
		}
		csCache[k] = e
	}
	csMu.Unlock()

	e.once.Do(func() { e.cs, e.err = LoadCIDRFile(path) })
	if e.err != nil {
		csMu.Lock()
		if cur, ok := csCache[k]; ok && cur == e {
			delete(csCache, k)
		}
		csMu.Unlock()
		return nil, e.err
	}
	return e.cs, nil
}
