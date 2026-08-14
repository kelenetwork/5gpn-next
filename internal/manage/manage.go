// Package manage 提供 Telegram Bot 与内网 Web 面板共用的管理动作。
//
// 两个前端（Bot / Web）只负责交互，全部业务逻辑集中在此，
// 避免同一功能写两遍导致行为不一致。
package manage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/node"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/probe"
	"github.com/kelenetwork/5gpn-next/internal/stats"
	"github.com/kelenetwork/5gpn-next/internal/trace"
	"github.com/kelenetwork/5gpn-next/internal/update"
)

// StatsSource 提供运行时计数。
type StatsSource interface {
	Snapshot() map[string]int64
}

// Manager 是管理动作的唯一入口。
type Manager struct {
	mu sync.RWMutex

	ConfigPath string
	Cfg        *config.Config
	Policy     *policy.Engine
	Egress     *egress.Registry
	Stats      StatsSource

	// ProfileURL 是描述文件下载地址，供前端展示
	ProfileURL string

	// Reload 由主程序注入：配置变更后重建策略与出口
	Reload func() error

	// Traffic 是流量统计存储（可为空）
	Traffic *stats.Store

	// Updater 负责版本检查/升级/回退（可为空）
	Updater *update.Manager

	// ProfileBytes 返回当前 iOS 描述文件内容，供 Bot 以文件形式下发
	ProfileBytes func() ([]byte, error)

	// AndroidInfo 返回 Android 接入所需信息
	AndroidInfo func() AndroidGuide

	started time.Time
}

// AndroidGuide 是 Android 接入指引。
type AndroidGuide struct {
	Enabled   bool   `json:"enabled"`
	DoTHost   string `json:"dot_host"`
	GatewayIP string `json:"gateway_ip"`
	Note      string `json:"note"`
}

// New 构造 Manager。
func New(cfgPath string, cfg *config.Config, eng *policy.Engine, reg *egress.Registry) *Manager {
	return &Manager{
		ConfigPath: cfgPath,
		Cfg:        cfg,
		Policy:     eng,
		Egress:     reg,
		started:    time.Now(),
	}
}

// SetRuntime 原子替换策略与出口引用，供热重载使用。
func (m *Manager) SetRuntime(p *policy.Engine, e *egress.Registry) {
	m.mu.Lock()
	m.Policy, m.Egress = p, e
	m.mu.Unlock()
}

// ---------- 状态 ----------

// Status 是面板与 Bot 共用的状态快照。
type Status struct {
	Version   string           `json:"version"`
	Uptime    string           `json:"uptime"`
	Listen    string           `json:"listen"`
	Host      string           `json:"host"`
	Rules     int              `json:"rules"`
	Egress    []EgressStatus   `json:"egress"`
	Final     string           `json:"final"`
	Counters  map[string]int64 `json:"counters"`
	MemoryMB  float64          `json:"memory_mb"`
	CertUntil string           `json:"cert_until,omitempty"`
}

// EgressStatus 描述一个出口。
type EgressStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Addr    string `json:"addr,omitempty"`
	Current bool   `json:"current"`
}

// Status 返回当前状态。
func (m *Manager) Status(version string) Status {
	m.mu.RLock()
	cfg := m.Cfg
	eng := m.Policy
	m.mu.RUnlock()

	// final 可能是动作 "direct"（小写）而出口名叫 "DIRECT"，
	// 必须忽略大小写比较，否则 DIRECT 永远显示为非当前，
	// 界面上会多出一个无意义的「切到 DIRECT」。
	cur := strings.TrimPrefix(cfg.Final, "proxy:")
	var es []EgressStatus
	for _, e := range cfg.Egress {
		es = append(es, EgressStatus{
			Name: e.Name, Type: e.Type, Addr: e.Addr,
			Current: strings.EqualFold(e.Name, cur),
		})
	}

	st := Status{
		Version:  version,
		Uptime:   humanDuration(time.Since(m.started)),
		Listen:   cfg.Relay.Listen,
		Host:     cfg.Relay.Host,
		Rules:    eng.Len(),
		Egress:   es,
		Final:    cfg.Final,
		MemoryMB: memoryMB(),
	}
	if m.Stats != nil {
		st.Counters = m.Stats.Snapshot()
	}
	if t := certNotAfter(cfg.Relay.CertFile); t != "" {
		st.CertUntil = t
	}
	return st
}

// ---------- 出口管理 ----------

// AddEgress 由分享链接新增出口。
//
// 返回脱敏摘要，绝不回显密钥。
func (m *Manager) AddEgress(name, link string) (string, error) {
	n, err := node.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", err
	}
	if name == "" {
		name = sanitizeName(n.Name)
	}
	if name == "" || name == "DIRECT" {
		name = fmt.Sprintf("node%d", time.Now().Unix()%10000)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			return "", fmt.Errorf("出口名 %q 已存在", name)
		}
	}

	// 每个出口一个独立 mihomo 实例，端口顺延
	port := 7891 + len(m.Cfg.Egress)
	dir := "/etc/mihomo-5gpn/" + name
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	yaml, err := n.MihomoConfig(port)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dir+"/config.yaml", []byte(yaml), 0o600); err != nil {
		return "", err
	}
	if err := writeMihomoUnit(name, dir); err != nil {
		return "", err
	}
	if err := systemctl("enable", "--now", "mihomo-5gpn@"+name+".service"); err != nil {
		return "", fmt.Errorf("启动出口服务失败: %w", err)
	}

	m.Cfg.Egress = append(m.Cfg.Egress, config.EgressConfig{
		Name: name, Type: "socks5",
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
	})
	if err := m.saveAndReloadLocked(); err != nil {
		return "", err
	}
	return fmt.Sprintf("已添加出口 %s（%s）", name, n.Redacted()), nil
}

// RemoveEgress 删除出口。
func (m *Manager) RemoveEgress(name string) error {
	if name == "DIRECT" {
		return fmt.Errorf("DIRECT 是内置出口，不可删除")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, e := range m.Cfg.Egress {
		if e.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("出口 %q 不存在", name)
	}
	if strings.TrimPrefix(m.Cfg.Final, "proxy:") == name {
		return fmt.Errorf("出口 %q 正在使用中，请先切换到其它出口", name)
	}

	_ = systemctl("disable", "--now", "mihomo-5gpn@"+name+".service")
	_ = os.RemoveAll("/etc/mihomo-5gpn/" + name)

	m.Cfg.Egress = append(m.Cfg.Egress[:idx], m.Cfg.Egress[idx+1:]...)
	return m.saveAndReloadLocked()
}

// SwitchEgress 切换默认出口。
func (m *Manager) SwitchEgress(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	found := name == "DIRECT"
	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("出口 %q 不存在", name)
	}
	if name == "DIRECT" {
		m.Cfg.Final = "direct"
	} else {
		m.Cfg.Final = "proxy:" + name
	}
	return m.saveAndReloadLocked()
}

// ---------- 分流规则 ----------

// Rules 返回当前规则列表。
func (m *Manager) Rules() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.Cfg.Rules))
	copy(out, m.Cfg.Rules)
	return out
}

// AddRule 追加一条规则。插入到 FINAL 之前、其它规则之后。
func (m *Manager) AddRule(rule string) error {
	rule = strings.TrimSpace(rule)
	parts := strings.Split(rule, ",")
	if len(parts) < 3 {
		return fmt.Errorf("格式应为 类型,值,动作，例如 DOMAIN-SUFFIX,openai.com,proxy:node")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// 新规则插到最前，便于覆盖既有的大规则集
	m.Cfg.Rules = append([]string{rule}, m.Cfg.Rules...)
	return m.saveAndReloadLocked()
}

// RemoveRule 按序号删除规则。
func (m *Manager) RemoveRule(idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < 0 || idx >= len(m.Cfg.Rules) {
		return fmt.Errorf("序号超出范围")
	}
	m.Cfg.Rules = append(m.Cfg.Rules[:idx], m.Cfg.Rules[idx+1:]...)
	return m.saveAndReloadLocked()
}

// ---------- 诊断 ----------

// Probe 对目标执行全链路诊断。
func (m *Manager) Probe(ctx context.Context, target string) *trace.Trace {
	m.mu.RLock()
	p := &probe.Prober{Policy: m.Policy, Egress: m.Egress}
	m.mu.RUnlock()
	return p.Run(ctx, target)
}

// ---------- 流量 ----------

// Traffic 返回流量摘要；未启用统计时返回零值与 false。
func (m *Manager) TrafficSummary() (stats.Summary, bool) {
	if m.Traffic == nil {
		return stats.Summary{}, false
	}
	return m.Traffic.Summary(7, 10), true
}

// ---------- 更新 ----------

// CheckUpdate 查询是否有新版本。
func (m *Manager) CheckUpdate(ctx context.Context) (bool, *update.Release, error) {
	if m.Updater == nil {
		return false, nil, fmt.Errorf("更新功能未启用")
	}
	return m.Updater.HasUpdate(ctx)
}

// ApplyUpdate 安装指定版本。
func (m *Manager) ApplyUpdate(ctx context.Context, tag string) (string, error) {
	if m.Updater == nil {
		return "", fmt.Errorf("更新功能未启用")
	}
	return m.Updater.Apply(ctx, tag)
}

// RollbackVersions 列出可回退版本。
func (m *Manager) RollbackVersions() []string {
	if m.Updater == nil {
		return nil
	}
	return m.Updater.Versions()
}

// Rollback 回退到指定版本。
func (m *Manager) Rollback(ctx context.Context, tag string) (string, error) {
	if m.Updater == nil {
		return "", fmt.Errorf("更新功能未启用")
	}
	return m.Updater.Rollback(ctx, tag)
}

// ---------- 内部 ----------

// saveAndReloadLocked 保存配置并热重载。调用方须持有写锁。
//
// 失败时回滚到磁盘上的旧配置，避免内存态与磁盘态不一致。
func (m *Manager) saveAndReloadLocked() error {
	backup := m.ConfigPath + ".rollback"
	if b, err := os.ReadFile(m.ConfigPath); err == nil {
		_ = os.WriteFile(backup, b, 0o600)
	}
	if err := m.Cfg.Save(m.ConfigPath); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	if m.Reload == nil {
		return nil
	}
	if err := m.Reload(); err != nil {
		// 回滚
		if b, rerr := os.ReadFile(backup); rerr == nil {
			_ = os.WriteFile(m.ConfigPath, b, 0o600)
			if c, cerr := config.Load(m.ConfigPath); cerr == nil {
				m.Cfg = c
			}
			_ = m.Reload()
		}
		return fmt.Errorf("应用配置失败，已回滚: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}

func writeMihomoUnit(name, dir string) error {
	// 使用模板单元，避免每个出口写一个文件
	const tmplPath = "/etc/systemd/system/mihomo-5gpn@.service"
	if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
		unit := `[Unit]
Description=mihomo egress %i for 5gpn-next
After=network-online.target
Wants=network-online.target
StartLimitBurst=10
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo -d /var/lib/mihomo-5gpn/%i -f /etc/mihomo-5gpn/%i/config.yaml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/mihomo-5gpn
MemoryMax=192M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`
		if err := os.WriteFile(tmplPath, []byte(unit), 0o644); err != nil {
			return err
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
	}
	return os.MkdirAll("/var/lib/mihomo-5gpn/"+name, 0o750)
}

func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	out := strings.ToLower(b.String())
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时 %d 分", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d 天 %d 小时", int(d.Hours())/24, int(d.Hours())%24)
}

func memoryMB() float64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			var kb float64
			fmt.Sscanf(strings.TrimPrefix(line, "VmRSS:"), "%f", &kb)
			return kb / 1024
		}
	}
	return 0
}

func certNotAfter(path string) string {
	if path == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openssl", "x509", "-enddate", "-noout", "-in", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "notAfter="))
}

// SortedEgressNames 返回排序后的出口名，便于稳定展示。
func (m *Manager) SortedEgressNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.Cfg.Egress))
	for _, e := range m.Cfg.Egress {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}
