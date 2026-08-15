// Package stats 记录流量、连接与广告拦截统计，供 Bot 与面板展示。
//
// 设计取舍：正常访问只保留聚合数据（按天、按动作、Top 域名），不落
// 原始访问日志。广告拦截按用户要求额外保留最近 100 条命中，但只记录
// 已被 DNS 成功拦截的域名与时间，不记录客户端 IP、完整 URL 或正常访问。
package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Day 是单日聚合。
type Day struct {
	Date        string `json:"date"` // YYYY-MM-DD
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	Conns       int64  `json:"conns"`
	DirectConns int64  `json:"direct_conns"`
	ProxyConns  int64  `json:"proxy_conns"`
	Blocked     int64  `json:"blocked"`
	AdBlocked   int64  `json:"ad_blocked,omitempty"` // DNS 已成功返回 NXDOMAIN 的次数
	Failed      int64  `json:"failed"`
}

// Total 返回该日总流量。
func (d Day) Total() int64 { return d.Up + d.Down }

// BlockEvent 是一条最近广告拦截记录。At 为 Unix 秒，便于 Bot 与浏览器
// 按各自本地时区展示。
type BlockEvent struct {
	Host string `json:"host"`
	At   int64  `json:"at"`
}

type blockAggregate struct {
	Count  int64 `json:"count"`
	LastAt int64 `json:"last_at"`
}

type persisted struct {
	Days    map[string]*Day  `json:"days"`
	Domains map[string]int64 `json:"domains"` // 域名 -> 字节数（仅保留 Top N）
	Since   string           `json:"since"`

	AdBlockTotal   int64                      `json:"ad_block_total,omitempty"`
	AdBlockSince   string                     `json:"ad_block_since,omitempty"`
	BlockedDomains map[string]*blockAggregate `json:"blocked_domains,omitempty"`
	RecentBlocks   []BlockEvent               `json:"recent_blocks,omitempty"`
}

// Store 是统计存储。
type Store struct {
	mu   sync.Mutex
	path string
	data persisted

	dirty            bool
	maxDays          int
	maxDomain        int
	maxBlockedDomain int
	maxRecentBlocks  int
}

// New 构造 Store 并尝试载入已有数据。
func New(path string) *Store {
	s := &Store{
		path:             path,
		maxDays:          90,
		maxDomain:        400,
		maxBlockedDomain: 400,
		maxRecentBlocks:  100,
		data: persisted{
			Days:           make(map[string]*Day),
			Domains:        make(map[string]int64),
			Since:          time.Now().Format("2006-01-02"),
			BlockedDomains: make(map[string]*blockAggregate),
		},
	}
	s.load()
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return
	}
	if p.Days == nil {
		p.Days = make(map[string]*Day)
	}
	if p.Domains == nil {
		p.Domains = make(map[string]int64)
	}
	if p.BlockedDomains == nil {
		p.BlockedDomains = make(map[string]*blockAggregate)
	}
	if p.Since == "" {
		p.Since = time.Now().Format("2006-01-02")
	}
	s.data = p
}

// Flush 原子写盘。
func (s *Store) Flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	s.prune()
	b, err := json.Marshal(s.data)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// RunFlusher 周期落盘，直到 done 关闭。
func (s *Store) RunFlusher(done <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			_ = s.Flush()
			return
		case <-t.C:
			_ = s.Flush()
		}
	}
}

// prune 控制体积：只留最近 maxDays 天与 Top maxDomain 个域名。
// 调用方须持锁。
func (s *Store) prune() {
	if len(s.data.Days) > s.maxDays {
		keys := make([]string, 0, len(s.data.Days))
		for k := range s.data.Days {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:len(keys)-s.maxDays] {
			delete(s.data.Days, k)
		}
	}
	if len(s.data.Domains) > s.maxDomain {
		type kv struct {
			k string
			v int64
		}
		list := make([]kv, 0, len(s.data.Domains))
		for k, v := range s.data.Domains {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
		for _, e := range list[s.maxDomain:] {
			delete(s.data.Domains, e.k)
		}
	}
	if len(s.data.BlockedDomains) > s.maxBlockedDomain {
		type kv struct {
			k string
			v int64
		}
		list := make([]kv, 0, len(s.data.BlockedDomains))
		for k, v := range s.data.BlockedDomains {
			list = append(list, kv{k, v.Count})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].v == list[j].v {
				return list[i].k < list[j].k
			}
			return list[i].v > list[j].v
		})
		for _, e := range list[s.maxBlockedDomain:] {
			delete(s.data.BlockedDomains, e.k)
		}
	}
	if len(s.data.RecentBlocks) > s.maxRecentBlocks {
		s.data.RecentBlocks = append([]BlockEvent(nil),
			s.data.RecentBlocks[len(s.data.RecentBlocks)-s.maxRecentBlocks:]...)
	}
}

func (s *Store) today() *Day {
	key := time.Now().Format("2006-01-02")
	d, ok := s.data.Days[key]
	if !ok {
		d = &Day{Date: key}
		s.data.Days[key] = d
	}
	return d
}

// Conn 记录一次连接的结果与流量。
//
// host 为空或为 IP 时不计入域名榜，避免把裸 IP 塞满统计。
func (s *Store) Conn(host, action string, up, down int64, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.today()
	d.Conns++
	d.Up += up
	d.Down += down
	switch action {
	case "direct":
		d.DirectConns++
	case "proxy":
		d.ProxyConns++
	case "block":
		d.Blocked++
	}
	if failed {
		d.Failed++
	}
	if host != "" && (up+down) > 0 {
		s.data.Domains[host] += up + down
	}
	s.dirty = true
}

// AdBlockSuccess 记录一次已成功写回客户端的广告 NXDOMAIN 响应。
// 只有 DoT ResponseWriter.WriteMsg 返回 nil 后才能调用，因此这里的计数
// 是“成功拦截”，不是仅命中规则或尝试拦截。
func (s *Store) AdBlockSuccess(host string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return
	}
	now := time.Now()
	at := now.Unix()

	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.today()
	d.AdBlocked++
	s.data.AdBlockTotal++
	if s.data.AdBlockSince == "" {
		s.data.AdBlockSince = now.Format("2006-01-02")
	}
	agg := s.data.BlockedDomains[host]
	if agg == nil {
		agg = &blockAggregate{}
		s.data.BlockedDomains[host] = agg
	}
	agg.Count++
	agg.LastAt = at
	s.data.RecentBlocks = append(s.data.RecentBlocks, BlockEvent{Host: host, At: at})
	if len(s.data.RecentBlocks) > s.maxRecentBlocks {
		drop := len(s.data.RecentBlocks) - s.maxRecentBlocks
		copy(s.data.RecentBlocks, s.data.RecentBlocks[drop:])
		s.data.RecentBlocks = s.data.RecentBlocks[:s.maxRecentBlocks]
	}
	s.dirty = true
}

// Summary 是对外的统计快照。
type Summary struct {
	Since     string     `json:"since"`
	Today     Day        `json:"today"`
	Days7     Day        `json:"days7"`
	Days30    Day        `json:"days30"`
	AllTime   Day        `json:"all_time"`
	Recent    []Day      `json:"recent"`
	TopDomain []TopEntry `json:"top_domain"`
}

// TopEntry 是域名流量榜条目。
type TopEntry struct {
	Host  string `json:"host"`
	Bytes int64  `json:"bytes"`
}

// BlockedEntry 是按成功拦截次数聚合的域名。
type BlockedEntry struct {
	Host   string `json:"host"`
	Count  int64  `json:"count"`
	LastAt int64  `json:"last_at"`
}

// AdBlockSummary 是广告拦截的持久化快照。
type AdBlockSummary struct {
	Since  string         `json:"since"`
	Today  int64          `json:"today"`
	Days7  int64          `json:"days7"`
	Days30 int64          `json:"days30"`
	Total  int64          `json:"total"`
	Recent []BlockEvent   `json:"recent"`
	Top    []BlockedEntry `json:"top"`
}

// AdBlockSummary 返回成功拦截统计；最近记录按时间倒序。
func (s *Store) AdBlockSummary(recentN, topN int) AdBlockSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := AdBlockSummary{Since: s.data.AdBlockSince, Total: s.data.AdBlockTotal}
	todayKey := time.Now().Format("2006-01-02")
	if d := s.data.Days[todayKey]; d != nil {
		out.Today = d.AdBlocked
	}

	// 7/30 日按自然日窗口统计，而不是“最近 7/30 个有数据的日期”。
	// 后者在低频设备上会把几个月前的命中错误计入近期统计。
	now := time.Now()
	start7 := now.AddDate(0, 0, -6).Format("2006-01-02")
	start30 := now.AddDate(0, 0, -29).Format("2006-01-02")
	for key, d := range s.data.Days {
		if key >= start30 && key <= todayKey {
			out.Days30 += d.AdBlocked
		}
		if key >= start7 && key <= todayKey {
			out.Days7 += d.AdBlocked
		}
	}

	if recentN < 0 {
		recentN = 0
	}
	if recentN > len(s.data.RecentBlocks) {
		recentN = len(s.data.RecentBlocks)
	}
	out.Recent = make([]BlockEvent, 0, recentN)
	for i := len(s.data.RecentBlocks) - 1; i >= len(s.data.RecentBlocks)-recentN; i-- {
		out.Recent = append(out.Recent, s.data.RecentBlocks[i])
	}

	out.Top = make([]BlockedEntry, 0, len(s.data.BlockedDomains))
	for host, agg := range s.data.BlockedDomains {
		out.Top = append(out.Top, BlockedEntry{Host: host, Count: agg.Count, LastAt: agg.LastAt})
	}
	sort.Slice(out.Top, func(i, j int) bool {
		if out.Top[i].Count == out.Top[j].Count {
			return out.Top[i].Host < out.Top[j].Host
		}
		return out.Top[i].Count > out.Top[j].Count
	})
	if topN < 0 {
		topN = 0
	}
	if len(out.Top) > topN {
		out.Top = out.Top[:topN]
	}
	return out
}

// Summary 汇总统计。
func (s *Store) Summary(recentDays, topN int) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.data.Days))
	for k := range s.data.Days {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	out := Summary{Since: s.data.Since}
	todayKey := time.Now().Format("2006-01-02")
	if d, ok := s.data.Days[todayKey]; ok {
		out.Today = *d
	} else {
		out.Today = Day{Date: todayKey}
	}

	for i, k := range keys {
		d := s.data.Days[k]
		accumulate(&out.AllTime, d)
		if i < 7 {
			accumulate(&out.Days7, d)
		}
		if i < 30 {
			accumulate(&out.Days30, d)
		}
		if i < recentDays {
			out.Recent = append(out.Recent, *d)
		}
	}

	list := make([]TopEntry, 0, len(s.data.Domains))
	for h, b := range s.data.Domains {
		list = append(list, TopEntry{Host: h, Bytes: b})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Bytes > list[j].Bytes })
	if len(list) > topN {
		list = list[:topN]
	}
	out.TopDomain = list
	return out
}

func accumulate(dst *Day, src *Day) {
	dst.Up += src.Up
	dst.Down += src.Down
	dst.Conns += src.Conns
	dst.DirectConns += src.DirectConns
	dst.ProxyConns += src.ProxyConns
	dst.Blocked += src.Blocked
	dst.AdBlocked += src.AdBlocked
	dst.Failed += src.Failed
}

// HumanBytes 把字节数格式化为易读字符串。
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(n) + " B"
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	v := float64(n)
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return trimFloat(v) + " " + units[i]
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func trimFloat(v float64) string {
	s := formatFloat(v)
	return s
}

func formatFloat(v float64) string {
	// 保留一位小数，去掉多余的 .0
	n := int64(v*10 + 0.5)
	whole, frac := n/10, n%10
	if frac == 0 {
		return itoa(whole)
	}
	return itoa(whole) + "." + itoa(frac)
}
