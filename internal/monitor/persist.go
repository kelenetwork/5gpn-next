package monitor

import (
	"encoding/json"
	"os"
	"time"
)

// UnmarshalJSON 兼容 v0.13.20 及更早版本的毫秒快照。
//
// 老快照里字段名是 MS（毫秒）；直接改字段会让升级后的第一天历史
// 全部变成 0，看起来像监控炸了。缺 us 时按毫秒换算补上。
func (s *Sample) UnmarshalJSON(b []byte) error {
	var raw struct {
		At time.Time `json:"At"`
		US *int64    `json:"us"`
		MS *int64    `json:"MS"`
		OK bool      `json:"OK"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	s.At, s.OK = raw.At, raw.OK
	switch {
	case raw.US != nil:
		s.US = *raw.US
	case raw.MS != nil:
		s.US = *raw.MS * 1000
	}
	return nil
}

// persisted 是落盘快照格式。只存样本原始数据，聚合在读取时重算。
type persisted struct {
	SavedAt time.Time               `json:"saved_at"`
	Probes  map[string][]Sample     `json:"probes"`
	Fw      map[string][]Sample     `json:"fw"`
	DNS     []Sample                `json:"dns"`
	Traffic map[string]*egressBytes `json:"traffic,omitempty"`
}

// Save 原子写快照；PersistPath 为空时是 no-op。
func (m *Monitor) Save() error {
	if m.PersistPath == "" {
		return nil
	}
	m.mu.Lock()
	p := persisted{
		SavedAt: m.now(),
		Probes:  make(map[string][]Sample, len(m.probes)),
		Fw:      make(map[string][]Sample, len(m.fw)),
		DNS:     m.dns.all(),
		Traffic: make(map[string]*egressBytes, len(m.traffic)),
	}
	for n, r := range m.probes {
		p.Probes[n] = r.all()
	}
	for n, r := range m.fw {
		p.Fw[n] = r.all()
	}
	for n, t := range m.traffic {
		cp := *t
		p.Traffic[n] = &cp
	}
	m.mu.Unlock()

	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := m.PersistPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.PersistPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Load 从快照恢复；文件缺失/损坏静默忽略（监控数据可丢，不能拦启动）。
// 超过 25h 的样本直接丢弃，避免陈旧数据污染 24h 窗口。
func (m *Monitor) Load() {
	if m.PersistPath == "" {
		return
	}
	b, err := os.ReadFile(m.PersistPath)
	if err != nil {
		return
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return
	}
	cutoff := m.now().Add(-25 * time.Hour)
	m.mu.Lock()
	defer m.mu.Unlock()
	for n, ss := range p.Probes {
		r := newRing(probeCap)
		for _, s := range ss {
			if s.At.After(cutoff) {
				r.add(s)
			}
		}
		m.probes[n] = r
	}
	for n, ss := range p.Fw {
		r := newRing(fwCap)
		for _, s := range ss {
			if s.At.After(cutoff) {
				r.add(s)
			}
		}
		m.fw[n] = r
	}
	for _, s := range p.DNS {
		if s.At.After(cutoff) {
			m.dns.add(s)
		}
	}
	for n, t := range p.Traffic {
		if t != nil {
			cp := *t
			m.traffic[n] = &cp
		}
	}
}
