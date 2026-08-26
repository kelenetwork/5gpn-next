// Package manage 提供 Telegram Bot 与内网 Web 面板共用的管理动作。
//
// 两个前端（Bot / Web）只负责交互，全部业务逻辑集中在此，
// 避免同一功能写两遍导致行为不一致。
package manage

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/monitor"
	"github.com/kelenetwork/5gpn-next/internal/node"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/probe"
	"github.com/kelenetwork/5gpn-next/internal/ruleset"
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

	// Reload 由主程序注入：配置变更后重建策略与出口，
	// 返回新的运行态由 Manager 自行装配。
	// 注入的函数绝不能回调 Manager 的加锁方法（会死锁）。
	Reload func() (*policy.Engine, *egress.Registry, error)

	// Traffic 是流量统计存储（可为空）
	Traffic *stats.Store

	// Updater 负责版本检查/升级/回退（可为空）
	Updater *update.Manager

	// DNSProfileBytes 返回蜂窝 DNS 描述文件；未启用 DoT 时为 nil。
	DNSProfileBytes func() ([]byte, error)

	// AndroidInfo 返回 Android 接入所需信息
	AndroidInfo func() AndroidGuide

	// Health 是内置健康监控（可为空）
	Health *monitor.Monitor

	started time.Time
}

// ProfileDownloadURL 返回当前蜂窝 DNS 描述文件的 HTTPS 下载地址。
// 未启用 DoT、缺少 host 或随机路径时为空。
func (m *Manager) ProfileDownloadURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Cfg == nil {
		return ""
	}
	return m.Cfg.ProfileDownloadURL()
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
	Version       string           `json:"version"`
	Uptime        string           `json:"uptime"`
	Listen        string           `json:"listen"`
	Host          string           `json:"host"`
	Rules         int              `json:"rules"`
	Egress        []EgressStatus   `json:"egress"`
	Final         string           `json:"final"`
	Counters      map[string]int64 `json:"counters"`
	MemoryMB      float64          `json:"memory_mb"`
	CertUntil     string           `json:"cert_until,omitempty"`
	DomesticReady bool             `json:"domestic_ready"`
	// AdBlock 是广告拦截状态
	AdBlock AdBlockStatus `json:"ad_block"`
}

// AdBlockStatus 描述广告拦截当前状态。
type AdBlockStatus struct {
	Enabled bool `json:"enabled"`
	// Domains 是已载入的拦截域名条数；0 表示规则集尚未就绪
	Domains int `json:"domains"`
	// Allowlist 是白名单条数；AllowDomains 供内网面板管理具体条目。
	Allowlist    int      `json:"allowlist"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	// Hits 只统计已成功写回客户端的 NXDOMAIN，并保留最近命中记录。
	Hits stats.AdBlockSummary `json:"hits"`
}

// EgressStatus 描述一个出口。
type EgressStatus struct {
	Name string `json:"name"`
	// Type 为节点真实协议（ss/vless/...），direct 出口为 "direct"
	Type string `json:"type"`
	Addr string `json:"addr,omitempty"`
	// Display 为展示名（节点原始备注名，可含 emoji/中文）
	Display string `json:"display"`
	// Server 为节点服务器 host:port（仅代理出口）
	Server string `json:"server,omitempty"`
	// HasIPv6 表示该出口能否代拨 IPv6 目标（自动探测）
	HasIPv6 bool `json:"has_ipv6"`
	Current bool `json:"current"`
}

// Status 返回当前状态。
func (m *Manager) Status(version string) Status {
	m.mu.RLock()
	cfg := *m.Cfg
	cfg.Egress = append([]config.EgressConfig(nil), m.Cfg.Egress...)
	cfg.AdBlock.Allowlist = append([]string(nil), m.Cfg.AdBlock.Allowlist...)
	eng := m.Policy
	m.mu.RUnlock()

	// 以运行态 FINAL 为准：国内规则未就绪时引擎会安全回落 DIRECT，
	// 此时不能拿磁盘里的期望值冒充当前出口。
	final := eng.Final()
	effectiveFinal := "direct"
	if final.Action == policy.ActionProxy {
		effectiveFinal = "proxy:" + final.Egress
	}
	cur := strings.TrimPrefix(effectiveFinal, "proxy:")
	var es []EgressStatus
	for _, e := range cfg.Egress {
		proto := e.Proto
		if e.Name == "DIRECT" && e.Type == "direct" {
			proto = "本机公网"
		} else if proto == "" {
			proto = e.Type
		}
		es = append(es, EgressStatus{
			Name: e.Name, Type: proto, Addr: e.Addr,
			Display: displayOf(e),
			Server:  e.Server,
			HasIPv6: e.HasIPv6,
			Current: strings.EqualFold(e.Name, cur),
		})
	}

	st := Status{
		Version:       version,
		Uptime:        humanDuration(time.Since(m.started)),
		Listen:        cfg.Gateway.Listen,
		Host:          cfg.Gateway.Host,
		Rules:         eng.Len(),
		Egress:        es,
		Final:         effectiveFinal,
		MemoryMB:      memoryMB(),
		DomesticReady: eng.DomesticRulesReady(),
		AdBlock: AdBlockStatus{
			Enabled:      cfg.AdBlock.Enabled,
			Domains:      eng.DomainSetLen(config.AdBlockRuleSetName),
			Allowlist:    len(cfg.AdBlock.Allowlist),
			AllowDomains: append([]string(nil), cfg.AdBlock.Allowlist...),
		},
	}
	if m.Traffic != nil {
		st.AdBlock.Hits = m.Traffic.AdBlockSummary(12, 8)
	}
	if m.Stats != nil {
		st.Counters = m.Stats.Snapshot()
	}
	if t := certNotAfter(cfg.Gateway.CertFile); t != "" {
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

	// mihomo 缺失时运行期自动安装（安装脚本只在填了节点时才装）。
	if err := ensureMihomo(); err != nil {
		return "", fmt.Errorf("安装 mihomo 出口协议栈失败: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			return "", fmt.Errorf("出口名 %q 已存在", name)
		}
	}

	// 每个出口一个独立 mihomo 实例。端口取当前已用最大值 +1，
	// 不能用 len(egress)：删除后再添加会与存活实例撞端口。
	port := 7891
	for _, e := range m.Cfg.Egress {
		if p, ok := localPort(e.Addr); ok && p >= port {
			port = p + 1
		}
	}

	// 配置放 /var/lib：服务开启 ProtectSystem=full 后 /etc 只读，
	// 运行期写 /etc/mihomo-5gpn 会直接 EROFS。
	dir := egressDir + "/" + name
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	yaml, err := n.MihomoConfig(port)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dir+"/config.yaml", []byte(yaml), 0o600); err != nil {
		return "", err
	}
	if err := ensureMihomoUnit(); err != nil {
		return "", err
	}
	if err := systemctl("enable", "--now", "mihomo-5gpn@"+name+".service"); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("启动出口服务失败: %w", err)
	}

	// 端到端验证：经 mihomo 的 SOCKS5 真实建立一条出站连接。
	// 验证不通过就回滚，绝不把坏出口留在列表里 ——
	// 一旦切换到坏出口，手机侧全部国外流量当场失联。
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := verifyEgress(addr, 12*time.Second); err != nil {
		_ = systemctl("disable", "--now", "mihomo-5gpn@"+name+".service")
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("出口联通性验证失败，已回滚：%v\n\n"+
			"节点可能不可用或凭据错误，可在服务器执行\n"+
			"journalctl -u mihomo-5gpn@%s -n 30 查看细节", err, name)
	}

	// 探测节点能否代拨 IPv6：蜂窝多为 v6 环境，WhatsApp 等 App 优先连
	// IPv6 字面量；节点有 v6 能力时由节点代拨，无则快速失败促使回落 IPv4。
	hasV6 := egress.ProbeSocks5IPv6(addr, 4*time.Second)

	m.Cfg.Egress = append(m.Cfg.Egress, config.EgressConfig{
		Name: name, Type: "socks5",
		Addr:        addr,
		HasIPv6:     hasV6,
		DisplayName: strings.TrimSpace(n.Name),
		Proto:       n.Type,
		Server:      fmt.Sprintf("%s:%d", n.Server, n.Port),
	})
	if err := m.saveAndReloadLocked(); err != nil {
		return "", err
	}
	v6mark := "IPv6 ✗"
	if hasV6 {
		v6mark = "IPv6 ✓"
	}
	return fmt.Sprintf("已添加出口 %s（%s，%s），联通性验证通过", displayOf(m.Cfg.Egress[len(m.Cfg.Egress)-1]), n.Redacted(), v6mark), nil
}

// RefreshEgressIPv6 重新探测全部 SOCKS5 出口的 IPv6 代拨能力。
// 旧版本添加的出口 has_ipv6 恒为 false，启动后后台刷新一次即可自动修正。
func (m *Manager) RefreshEgressIPv6(timeout time.Duration) ([]string, error) {
	m.mu.RLock()
	type probeItem struct {
		name, addr string
		hasV6      bool
	}
	var items []probeItem
	for _, e := range m.Cfg.Egress {
		if e.Type == "socks5" && e.Addr != "" {
			items = append(items, probeItem{e.Name, e.Addr, e.HasIPv6})
		}
	}
	m.mu.RUnlock()

	result := make(map[string]bool, len(items))
	var changed []string
	for _, it := range items {
		got := egress.ProbeSocks5IPv6(it.addr, timeout)
		result[it.name] = got
		if got != it.hasV6 {
			changed = append(changed, fmt.Sprintf("%s→%v", it.name, got))
		}
	}
	if len(changed) == 0 {
		return nil, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.Cfg.Egress {
		if v, ok := result[m.Cfg.Egress[i].Name]; ok && m.Cfg.Egress[i].Type == "socks5" {
			m.Cfg.Egress[i].HasIPv6 = v
		}
	}
	if err := m.saveAndReloadLocked(); err != nil {
		return changed, err
	}
	return changed, nil
}

// displayOf 返回出口的展示名：优先节点原始备注名。
func displayOf(e config.EgressConfig) string {
	if e.DisplayName != "" {
		return e.DisplayName
	}
	if e.Name == "DIRECT" && e.Type == "direct" {
		return "KFC 本机出口"
	}
	return e.Name
}

// ensureMihomo 确保 mihomo 二进制存在；缺失时从官方发布下载安装。
// 写 /usr/local 在沙箱内只读，走 systemd-run 由 PID 1 在沙箱外完成。
func ensureMihomo() error {
	if _, err := os.Stat("/usr/local/bin/mihomo"); err == nil {
		return nil
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("不支持的架构 %s", arch)
	}
	ver := "v1.19.29"
	url := fmt.Sprintf(
		"https://github.com/MetaCubeX/mihomo/releases/download/%s/mihomo-linux-%s-%s.gz",
		ver, arch, ver)
	script := fmt.Sprintf(
		"curl -fsSL --max-time 180 %q | gunzip > /usr/local/bin/mihomo.new && "+
			"chmod 755 /usr/local/bin/mihomo.new && "+
			"/usr/local/bin/mihomo.new -v >/dev/null 2>&1 && "+
			"mv -f /usr/local/bin/mihomo.new /usr/local/bin/mihomo", url)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-run",
		"--quiet", "--wait", "--collect",
		"--property=Type=oneshot",
		"/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("下载安装失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// localPort 提取 127.0.0.1:N 形式地址的端口。
func localPort(addr string) (int, bool) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return p, true
}

// verifyEgress 端到端验证 SOCKS5 出口。
//
// 仅 SOCKS 握手成功不能证明链路可用：mihomo 会先应答本地 SOCKS，
// 再懒连接上游节点。必须真实发出 HTTP 请求并收到状态行，
// 才能证明 mihomo → 节点 → 目标 整条数据通路是通的。
// mihomo 启动需要时间，在 total 期限内重试。
func verifyEgress(addr string, total time.Duration) error {
	targets := []struct{ host, path string }{
		{"cp.cloudflare.com", "/generate_204"},
		{"www.gstatic.com", "/generate_204"},
	}
	d := egress.NewSocks5("verify", addr, false)
	deadline := time.Now().Add(total)
	var lastErr error
	for {
		for _, t := range targets {
			err := func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, err := d.DialContext(ctx, "tcp", t.host+":80")
				if err != nil {
					return err
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
					t.path, t.host)
				buf := make([]byte, 16)
				if _, err := io.ReadFull(c, buf); err != nil {
					return fmt.Errorf("读取响应失败（节点可能不通）: %w", err)
				}
				if !strings.HasPrefix(string(buf), "HTTP/") {
					return fmt.Errorf("响应异常: %q", string(buf))
				}
				return nil
			}()
			if err == nil {
				return nil
			}
			lastErr = err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(700 * time.Millisecond)
	}
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

	_ = systemctl("disable", "--now", "mihomo-5gpn@"+name+".service")
	_ = os.RemoveAll(egressDir + "/" + name)
	// 旧版本的配置位置（沙箱内只读，删不掉也无妨）
	_ = os.RemoveAll("/etc/mihomo-5gpn/" + name)

	m.Cfg.Egress = append(m.Cfg.Egress[:idx], m.Cfg.Egress[idx+1:]...)

	// 删除的是当前出口：自动回落 DIRECT，绝不留下悬空引用
	if strings.TrimPrefix(m.Cfg.Final, "proxy:") == name {
		m.Cfg.Final = "direct"
	}
	// 清理引用该出口的自定义规则
	var kept []string
	for _, r := range m.Cfg.Rules {
		if strings.HasSuffix(strings.TrimSpace(r), ",proxy:"+name) {
			continue
		}
		kept = append(kept, r)
	}
	m.Cfg.Rules = kept

	return m.saveAndReloadLocked()
}

// TestEgress 端到端测试一个出口，返回耗时。
func (m *Manager) TestEgress(name string) (time.Duration, error) {
	m.mu.RLock()
	addr := ""
	found := false
	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			found = true
			addr = e.Addr
			break
		}
	}
	m.mu.RUnlock()
	if !found && name != "DIRECT" {
		return 0, fmt.Errorf("出口 %q 不存在", name)
	}

	start := time.Now()
	if addr == "" {
		// DIRECT：本机直接连测试目标
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", "cp.cloudflare.com:80")
		if err != nil {
			return 0, err
		}
		c.Close()
		return time.Since(start), nil
	}
	if err := verifyEgress(addr, 8*time.Second); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// SwitchEgress 切换默认出口。
func (m *Manager) SwitchEgress(name string) error {
	m.mu.RLock()
	found := name == "DIRECT"
	addr := ""
	for _, e := range m.Cfg.Egress {
		if e.Name == name {
			found = true
			if e.Type == "socks5" {
				addr = e.Addr
			}
			break
		}
	}
	m.mu.RUnlock()

	if !found {
		return fmt.Errorf("出口 %q 不存在", name)
	}

	// 代理出口只承担“国外兜底”。切换前必须确认国内域名/IP 两套
	// 直连规则均已加载；缺失时主动刷新，仍失败就拒绝切换。
	// 这样规则源故障也不会让“国外出口”退化成国内外全局代理。
	if name != "DIRECT" {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		err := m.ensureDomesticRules(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("国内直连规则未就绪，已拒绝切换，当前出口不变：%w", err)
		}
	}

	// 切换前先验证：切到坏出口 = 手机侧全部国外流量当场失联，
	// 必须在这里挡住，而不是让用户切完才发现没网。
	if addr != "" {
		if err := verifyEgress(addr, 8*time.Second); err != nil {
			return fmt.Errorf("出口 %q 验证失败，未切换：%v\n\n"+
				"请先用「连通诊断」排查该出口", name, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if name == "DIRECT" {
		m.Cfg.Final = "direct"
	} else {
		m.Cfg.Final = "proxy:" + name
	}
	return m.saveAndReloadLocked()
}

// ensureDomesticRules 确保 cn-domain 与 geoip:cn 已加载。
// 无缓存时现场下载一次，再热重载策略；任何失败都 fail-closed。
func (m *Manager) ensureDomesticRules(ctx context.Context) error {
	m.mu.RLock()
	if m.Policy != nil && m.Policy.DomesticRulesReady() {
		m.mu.RUnlock()
		return nil
	}
	sets := append([]config.RuleSetConfig(nil), m.Cfg.RuleSets...)
	m.mu.RUnlock()

	required := map[string]bool{"cn-domain": false, "geoip:cn": false}
	fetcher := ruleset.NewFetcher("/var/lib/5gpn-next/rulesets")
	for _, rs := range sets {
		if _, ok := required[rs.Name]; !ok {
			continue
		}
		required[rs.Name] = true
		if rs.Path != "" {
			if st, err := os.Stat(rs.Path); err != nil || st.Size() == 0 {
				return fmt.Errorf("规则集 %s 文件不可用", rs.Name)
			}
			continue
		}
		if _, err := fetcher.Fetch(ctx, rs.Name, rs.URL); err != nil {
			return fmt.Errorf("刷新规则集 %s 失败: %w", rs.Name, err)
		}
	}
	for name, present := range required {
		if !present {
			return fmt.Errorf("配置缺少必需规则集 %s", name)
		}
	}
	if err := m.ReloadRuntime(); err != nil {
		return fmt.Errorf("重载国内直连规则失败: %w", err)
	}
	m.mu.RLock()
	ready := m.Policy != nil && m.Policy.DomesticRulesReady()
	m.mu.RUnlock()
	if !ready {
		return fmt.Errorf("cn-domain / geoip:cn 内容为空或解析失败")
	}
	return nil
}

// ---------- 广告拦截 ----------

// SetAdBlock 开关广告拦截。
//
// 开启时先确保规则集已下载（首次约 2MB / 10 万条），
// 避免“显示已开启但实际一条没拦”的假成功。若配置已经是 enabled
// 但运行态 0 条规则，也会重新下载并热重载，而不是错误地返回“已开启”。
func (m *Manager) SetAdBlock(ctx context.Context, on bool) (string, error) {
	m.mu.Lock()
	changed := m.Cfg.AdBlock.Enabled != on
	if changed {
		m.Cfg.AdBlock.Enabled = on
		if err := m.saveAndReloadLocked(); err != nil {
			m.mu.Unlock()
			return "", err
		}
	}
	m.mu.Unlock()

	if !on {
		if changed {
			return "广告拦截已关闭", nil
		}
		return "广告拦截已是关闭状态", nil
	}
	if m.adBlockReady() {
		prefix := "广告拦截已开启"
		if !changed {
			prefix = "广告拦截已是开启状态"
		}
		return fmt.Sprintf("%s，已载入 %d 条拦截域名", prefix, m.adBlockDomains()), nil
	}

	// 首次下载失败或缓存损坏时，重复点击“开启”必须能在这里真正重试。
	rs, ok := m.adBlockRuleSet()
	if !ok {
		return "", fmt.Errorf("广告规则集配置缺失（已开启，但暂未生效）")
	}
	if rs.Path != "" {
		if st, err := os.Stat(rs.Path); err != nil || st.Size() == 0 {
			return "", fmt.Errorf("本地广告规则集 %s 不可用（已开启，但暂未生效）", rs.Path)
		}
	} else {
		f := ruleset.NewFetcher("/var/lib/5gpn-next/rulesets")
		if _, err := f.Fetch(ctx, rs.Name, rs.URL); err != nil {
			return "", fmt.Errorf("规则集下载失败（已开启，但暂未生效）: %w", err)
		}
	}
	if err := m.ReloadRuntime(); err != nil {
		return "", fmt.Errorf("规则集已就绪，重载失败: %w", err)
	}
	if n := m.adBlockDomains(); n > 0 {
		return fmt.Sprintf("广告拦截已开启，已载入 %d 条拦截域名", n), nil
	}
	return "", fmt.Errorf("广告规则集重载后仍为 0 条（已开启，但暂未生效）")
}

func (m *Manager) adBlockRuleSet() (config.RuleSetConfig, bool) {
	m.mu.RLock()
	sets := m.Cfg.EffectiveRuleSets()
	m.mu.RUnlock()
	for _, rs := range sets {
		if rs.Name == config.AdBlockRuleSetName {
			return rs, true
		}
	}
	return config.RuleSetConfig{}, false
}

func (m *Manager) adBlockDomains() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Policy == nil {
		return 0
	}
	return m.Policy.DomainSetLen(config.AdBlockRuleSetName)
}

func (m *Manager) adBlockReady() bool { return m.adBlockDomains() > 0 }

// EffectiveRuleSets 返回当前运行配置需要刷新的规则集副本。
// 默认广告规则只存在于 Config.EffectiveRuleSets()，后台刷新不能只看
// 磁盘里的 rulesets 数组。
func (m *Manager) EffectiveRuleSets() []config.RuleSetConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Cfg.EffectiveRuleSets()
}

// AllowAd 把域名加入广告白名单（误杀时救急）。
func (m *Manager) AllowAd(domain string) error {
	d := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	if d == "" || strings.ContainsAny(d, ",/ ") {
		return fmt.Errorf("域名 %q 格式不合法", domain)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Cfg.AdBlock.Allowlist {
		if strings.EqualFold(x, d) {
			return fmt.Errorf("%q 已在白名单中", d)
		}
	}
	m.Cfg.AdBlock.Allowlist = append(m.Cfg.AdBlock.Allowlist, d)
	return m.saveAndReloadLocked()
}

// AdAllowlist 返回白名单副本。
func (m *Manager) AdAllowlist() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.Cfg.AdBlock.Allowlist...)
}

// RemoveAdAllow 按序号移除白名单条目。
func (m *Manager) RemoveAdAllow(idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < 0 || idx >= len(m.Cfg.AdBlock.Allowlist) {
		return fmt.Errorf("序号 %d 超出范围", idx+1)
	}
	m.Cfg.AdBlock.Allowlist = append(m.Cfg.AdBlock.Allowlist[:idx], m.Cfg.AdBlock.Allowlist[idx+1:]...)
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
	return p.Run(ctx, NormalizeTarget(target))
}

// NormalizeTarget 把用户输入清洗成 host[:port]。
//
// 用户经常直接粘完整 URL（https://ipinfo.io/ip）；
// 逐层剥掉 scheme、userinfo、路径、查询串，只留主机与端口。
func NormalizeTarget(s string) string {
	s = strings.TrimSpace(s)
	// scheme://
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// 路径 / 查询 / 锚点（IPv6 字面量含 ]，先处理右括号后的部分）
	cutFrom := 0
	if strings.HasPrefix(s, "[") {
		if j := strings.Index(s, "]"); j >= 0 {
			cutFrom = j
		}
	}
	if i := strings.IndexAny(s[cutFrom:], "/?#"); i >= 0 {
		s = s[:cutFrom+i]
	}
	// user:pass@host
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return s
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

// CachedUpdate 返回最近一次成功检查缓存的最新版本；从未检查过时 ok=false。
func (m *Manager) CachedUpdate() (*update.Release, time.Time, bool) {
	if m.Updater == nil {
		return nil, time.Time{}, false
	}
	return m.Updater.Cached()
}

// UpdateBanner 返回主菜单升级横幅所需的新版本 tag；无新版、已忽略或
// 尚未检查过时返回空串。
func (m *Manager) UpdateBanner() string {
	rel, _, ok := m.CachedUpdate()
	if !ok || rel == nil {
		return ""
	}
	if !update.Newer(rel.Tag, m.currentVersion()) {
		return ""
	}
	if m.IsIgnoredVersion(rel.Tag) {
		return ""
	}
	return rel.Tag
}

func (m *Manager) currentVersion() string {
	if m.Updater == nil {
		return ""
	}
	return m.Updater.Current
}

// IsIgnoredVersion 报告某 tag 是否已被用户忽略。
func (m *Manager) IsIgnoredVersion(tag string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.Cfg.Update.IgnoredVersions {
		if t == tag {
			return true
		}
	}
	return false
}

// IgnoredVersions 返回忽略列表副本。
func (m *Manager) IgnoredVersions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.Cfg.Update.IgnoredVersions...)
}

// IgnoreVersion 把某 tag 加入忽略列表并持久化。
func (m *Manager) IgnoreVersion(tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Errorf("版本号为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.Cfg.Update.IgnoredVersions {
		if t == tag {
			return nil
		}
	}
	m.Cfg.Update.IgnoredVersions = append(m.Cfg.Update.IgnoredVersions, tag)
	return m.Cfg.Save(m.ConfigPath)
}

// UnignoreVersion 移出忽略列表并持久化。
func (m *Manager) UnignoreVersion(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.Cfg.Update.IgnoredVersions[:0]
	for _, t := range m.Cfg.Update.IgnoredVersions {
		if t != tag {
			out = append(out, t)
		}
	}
	m.Cfg.Update.IgnoredVersions = out
	return m.Cfg.Save(m.ConfigPath)
}

// UpdateSettings 返回自动检查/自动安装设置。
func (m *Manager) UpdateSettings() (checkEnabled, autoApply bool, intervalHours int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	iv := m.Cfg.Update.IntervalHours
	if iv <= 0 {
		iv = config.DefaultUpdateIntervalHours
	}
	return m.Cfg.Update.CheckEnabled, m.Cfg.Update.AutoApply, iv
}

// SetUpdateAutoApply 开关自动安装并持久化。
func (m *Manager) SetUpdateAutoApply(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Cfg.Update.AutoApply = on
	return m.Cfg.Save(m.ConfigPath)
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

// ReloadRuntime 仅重建运行态（策略引擎/出口），不改配置文件。
// 供规则集后台刷新等场景使用。
func (m *Manager) ReloadRuntime() error {
	if m.Reload == nil {
		return nil
	}
	p, e, err := m.Reload()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.Policy, m.Egress = p, e
	m.mu.Unlock()
	return nil
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
	p, e, err := m.Reload()
	if err != nil {
		// 回滚
		if b, rerr := os.ReadFile(backup); rerr == nil {
			_ = os.WriteFile(m.ConfigPath, b, 0o600)
			if c, cerr := config.Load(m.ConfigPath); cerr == nil {
				m.Cfg = c
			}
			if rp, re, rerr2 := m.Reload(); rerr2 == nil {
				m.Policy, m.Egress = rp, re
			}
		}
		return fmt.Errorf("应用配置失败，已回滚: %w", err)
	}
	// 调用方已持有写锁，直接赋值
	m.Policy, m.Egress = p, e
	_ = os.Remove(backup)
	return nil
}

// egressDir 存放各出口的 mihomo 配置与运行数据。
// 必须位于 /var/lib：主服务 ProtectSystem=full 下 /etc 只读。
const egressDir = "/var/lib/mihomo-5gpn"

const mihomoUnitPath = "/etc/systemd/system/mihomo-5gpn@.service"

const mihomoUnitContent = `[Unit]
Description=mihomo egress %i for 5gpn-next
After=network-online.target
Wants=network-online.target
StartLimitBurst=10
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo -d /var/lib/mihomo-5gpn/%i -f /var/lib/mihomo-5gpn/%i/config.yaml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
UMask=0077
ReadWritePaths=/var/lib/mihomo-5gpn
MemoryMax=192M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`

// ensureMihomoUnit 确保模板单元存在且为当前版本内容。
// 旧版本模板引用 /etc/mihomo-5gpn/%i，需要覆盖迁移。
func ensureMihomoUnit() error {
	if b, err := os.ReadFile(mihomoUnitPath); err == nil && string(b) == mihomoUnitContent {
		return nil
	}
	if err := writeFileMaybeSandboxed(mihomoUnitPath, []byte(mihomoUnitContent), 0o644); err != nil {
		return fmt.Errorf("写入 mihomo 模板单元失败: %w", err)
	}
	return systemctl("daemon-reload")
}

// writeFileMaybeSandboxed 写文件；直接写失败（典型为沙箱内 /etc 只读）时，
// 通过 systemd-run 请求 PID 1 在沙箱外代写。内容经 base64 传递，避免引号问题。
func writeFileMaybeSandboxed(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err == nil {
		return nil
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	script := fmt.Sprintf("echo %s | base64 -d > %q && chmod %o %q", b64, path, mode, path)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-run",
		"--quiet", "--wait", "--collect",
		"--property=Type=oneshot",
		"/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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

// ---------- 健康监控 ----------

// HealthReport 是 Bot 与面板共用的健康快照。
func (m *Manager) HealthReport() (monitor.Health, bool) {
	if m.Health == nil {
		return monitor.Health{}, false
	}
	return m.Health.Snapshot(), true
}

// HealthAnomalies 返回某出口最近异常探测点。
func (m *Manager) HealthAnomalies(name string, limit int) []monitor.Sample {
	if m.Health == nil {
		return nil
	}
	return m.Health.Anomalies(name, limit)
}

// SysHealth 是进程/系统层健康读数。
type SysHealth struct {
	MemoryMB   float64
	Goroutines int
	Uptime     string
	CertDays   int // -1 表示未知
}

// SysHealthNow 返回当前系统读数。
func (m *Manager) SysHealthNow() SysHealth {
	m.mu.RLock()
	cert := ""
	if m.Cfg != nil {
		cert = m.Cfg.Gateway.CertFile
	}
	started := m.started
	m.mu.RUnlock()
	h := SysHealth{
		MemoryMB:   memoryMB(),
		Goroutines: runtime.NumGoroutine(),
		Uptime:     humanDuration(time.Since(started)),
		CertDays:   certDaysLeft(cert),
	}
	return h
}

// certDaysLeft 返回证书剩余天数；解析失败返回 -1。
func certDaysLeft(path string) int {
	if path == "" {
		return -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openssl", "x509", "-enddate", "-noout", "-in", path).Output()
	if err != nil {
		return -1
	}
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "notAfter="))
	t, err := time.Parse("Jan 2 15:04:05 2006 MST", raw)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
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
