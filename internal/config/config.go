// Package config 定义 5gpn-NEXT 的声明式配置。
//
// 设计原则：期望态存配置，reconcile 负责收敛，
// 替代四家项目"bash 事务 + 快照回滚"的做法。
package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Config 是完整配置。
type Config struct {
	// Relay 入口
	Relay RelayConfig `json:"relay"`

	// 出口列表
	Egress []EgressConfig `json:"egress"`

	// 分流规则（有序）
	Rules []string `json:"rules"`

	// FINAL 兜底动作：direct / proxy:<name> / block
	Final string `json:"final"`

	// 规则集订阅
	RuleSets []RuleSetConfig `json:"rulesets"`

	// 手机侧直连域名（写进描述文件 ExcludedDomains）
	ExcludedDomains []string `json:"excluded_domains"`

	// AdBlock 是广告/追踪拦截配置。
	AdBlock AdBlockConfig `json:"ad_block"`

	// PreferIPv4 让所有出口对 IPv6 字面量目标立即快速失败（0ms），
	// 促使客户端 Happy Eyeballs 直接改用 IPv4。
	//
	// 生产实测结论：经 mihomo 代拨的 IPv6 对 Meta 这类多 edge 服务往往
	// 只是「部分可达」，坏 edge 每个都要等一个看门狗周期；而完全没有
	// IPv6 的出口反而更快（用户实测 KFC 明显快于 usatt）。因此默认开启。
	//
	// 置 false 可恢复 IPv6 代拨（出口具备完整 v6 能力时更优）。
	PreferIPv4 *bool `json:"prefer_ipv4,omitempty"`

	// Telegram Bot（可选）
	Bot BotConfig `json:"bot"`

	// 内网 Web 面板
	Panel PanelConfig `json:"panel"`

	// 客户端来源网段（用于面板访问控制与 DNS 改写判定）
	ClientCIDR string `json:"client_cidr"`

	// Android 接入路径（DoT + SNI 嗅探）
	Android AndroidConfig `json:"android"`

	// 自动更新检查
	Update UpdateConfig `json:"update"`

	// 日志
	LogPath string `json:"log_path"`
}

// AndroidConfig 是 Android 接入配置。
//
// Android 只提供「私密 DNS」一个入口，拿不到应用层目的地，
// 因此必须靠 DNS 改写 + SNI/Host 嗅探还原目标。
type AndroidConfig struct {
	// Enabled 为 false 时完全不监听 DoT 与嗅探端口
	Enabled bool `json:"enabled"`
	// DoTListen 通常为 ":853"
	DoTListen string `json:"dot_listen"`
	// GatewayIP 是改写后返回给客户端的地址，必须是客户端可路由到的网关地址
	GatewayIP string `json:"gateway_ip"`
	// HTTPListen / TLSListen 是嗅探接管端口
	HTTPListen string `json:"http_listen"`
	TLSListen  string `json:"tls_listen"`
	// Upstream 是 DNS 上游
	Upstream []string `json:"upstream"`
}

// UpdateConfig 是更新检查配置。
type UpdateConfig struct {
	// CheckEnabled 开启后周期检查新版本并通过 Bot 推送
	CheckEnabled bool `json:"check_enabled"`
	// IntervalHours 检查间隔，0 表示使用默认 12 小时
	IntervalHours int `json:"interval_hours"`
	// AutoApply 为 true 时自动安装（默认关闭，仅推送通知）
	AutoApply bool `json:"auto_apply"`
}

// BotConfig 是 Telegram 管理机器人配置。
type BotConfig struct {
	// Token 为空时不启用 Bot
	Token string `json:"token"`
	// Admins 是允许操作的 Telegram 数字 ID；为空时 Bot 不响应任何人
	Admins []int64 `json:"admins"`
}

// PanelConfig 是内网 Web 面板配置。
type PanelConfig struct {
	// Enabled 为 false 时完全不挂载面板路由
	Enabled bool `json:"enabled"`
	// Token 是登录令牌
	Token string `json:"token"`
}

// RelayConfig 是 Relay 入口配置。
type RelayConfig struct {
	Listen   string `json:"listen"` // 例如 ":20443"
	Host     string `json:"host"`   // 证书主机名，例如 kfc.ke1e.de
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Token    string `json:"token"`
	// ProfilePath 是描述文件下载路径（含随机串）
	ProfilePath string `json:"profile_path"`
}

// EgressConfig 是一个出口。
type EgressConfig struct {
	Name string `json:"name"`
	// Type: direct | socks5（socks5 指对接本机 mihomo 实例的内部桥）
	Type    string `json:"type"`
	Addr    string `json:"addr,omitempty"`
	HasIPv6 bool   `json:"has_ipv6,omitempty"`

	// DisplayName 是节点原始备注名（可含 emoji/中文），仅用于展示。
	DisplayName string `json:"display_name,omitempty"`
	// Proto 是节点真实协议（ss/vless/trojan/...），仅用于展示。
	Proto string `json:"proto,omitempty"`
	// Server 是节点服务器 host:port，仅用于展示。
	Server string `json:"server,omitempty"`
}

// AdBlockConfig 控制广告拦截。
//
// 拦截在网关侧完成，全设备生效且无需安装任何 App：
//   - Relay 模式：CONNECT 直接返回 403，App 秒失败不转圈
//   - DNS 模式：返回 NXDOMAIN，更彻底
type AdBlockConfig struct {
	// Enabled 为 false 时完全不加载规则集，不占内存与带宽。
	Enabled bool `json:"enabled"`

	// URL 为空时使用 DefaultAdBlockURL。
	URL string `json:"url,omitempty"`

	// Allowlist 是白名单域名后缀（误杀时救急）。
	//
	// 注意：用户自定义规则本身就排在广告拦截之前，写一条
	// DOMAIN-SUFFIX,xxx,direct 同样能放行；此字段只是更直观的入口。
	Allowlist []string `json:"allowlist,omitempty"`
}

// DefaultAdBlockURL 是默认规则源（anti-AD，中文环境命中率最高）。
const DefaultAdBlockURL = "https://anti-ad.net/domains.txt"

// AdBlockRuleSetName 是广告规则集的内部名。
const AdBlockRuleSetName = "ad-block"

// AdBlockURLOrDefault 返回实际使用的规则源。
func (c *Config) AdBlockURLOrDefault() string {
	if c.AdBlock.URL != "" {
		return c.AdBlock.URL
	}
	return DefaultAdBlockURL
}

// BuiltinAdBlock 返回广告拦截规则（含白名单）。
//
// 顺序：白名单 direct 必须在 RULE-SET block 之前，否则永远不会命中。
func (c *Config) BuiltinAdBlock() []string {
	if !c.AdBlock.Enabled {
		return nil
	}
	out := make([]string, 0, len(c.AdBlock.Allowlist)+1)
	for _, d := range c.AdBlock.Allowlist {
		d = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "."))
		if d == "" || strings.ContainsAny(d, ",/ ") {
			continue
		}
		out = append(out, "DOMAIN-SUFFIX,"+d+",direct")
	}
	return append(out, "RULE-SET,"+AdBlockRuleSetName+",block")
}

// EffectiveRuleSets 返回实际需要加载的规则集（含广告规则）。
//
// 广告规则集不写进配置文件的 rulesets 数组：它由 ad_block.enabled
// 控制，关闭时应彻底不下载不占内存。
func (c *Config) EffectiveRuleSets() []RuleSetConfig {
	out := append([]RuleSetConfig(nil), c.RuleSets...)
	if !c.AdBlock.Enabled {
		return out
	}
	for _, rs := range out {
		if rs.Name == AdBlockRuleSetName {
			return out // 用户已显式配置，以其为准
		}
	}
	return append(out, RuleSetConfig{
		Name:          AdBlockRuleSetName,
		Kind:          "domain",
		URL:           c.AdBlockURLOrDefault(),
		IntervalHours: 24,
	})
}

// RuleSetConfig 是一个规则集来源。
type RuleSetConfig struct {
	Name string `json:"name"`
	// Kind: domain | ipcidr
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
	Path string `json:"path,omitempty"`
	// IntervalHours 为 0 时不自动更新
	IntervalHours int `json:"interval_hours,omitempty"`
}

// Default 返回可直接运行的默认配置。
func Default() *Config {
	return &Config{
		Relay: RelayConfig{
			Listen: ":20443",
		},
		Egress: []EgressConfig{
			{Name: "DIRECT", Type: "direct"},
		},
		// Rules 只存用户自定义规则；基础规则已内置（见 BuiltinPre/BuiltinPost），
		// 不进配置文件，用户无法误删。
		Rules:      nil,
		Final:      "direct",
		PreferIPv4: boolPtr(true),
		ClientCIDR: "172.22.0.0/16",
		Panel:      PanelConfig{Enabled: true},
		Android: AndroidConfig{
			// 默认启用：Android 与 iOS 一并支持，用户无需额外选择
			Enabled:    true,
			DoTListen:  ":853",
			HTTPListen: ":80",
			TLSListen:  ":443",
			Upstream:   []string{"223.5.5.5:53", "119.29.29.29:53"},
		},
		Update:  UpdateConfig{CheckEnabled: true, IntervalHours: 12},
		LogPath: "/var/log/5gpn-next/trace.jsonl",
		RuleSets: []RuleSetConfig{
			{Name: "cn-domain", Kind: "domain", IntervalHours: 24,
				URL: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
			{Name: "geoip:cn", Kind: "ipcidr", IntervalHours: 24,
				URL: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"},
		},
	}
}

// BuiltinPre 是永远最先匹配的内置规则：私有地址绝不出网关。
// 放在用户规则之前，任何自定义规则都无法把内网流量导出去。
func BuiltinPre() []string {
	return []string{
		"IP-CIDR,10.0.0.0/8,direct",
		"IP-CIDR,172.16.0.0/12,direct",
		"IP-CIDR,192.168.0.0/16,direct",
		"IP-CIDR,127.0.0.0/8,direct",
		"IP-CIDR,169.254.0.0/16,direct",
	}
}

// BuiltinPost 是用户规则之后的内置兜底：国内域名与国内 IP 直连。
// 放在用户规则之后，用户仍可用自定义规则覆盖个别域名。
func BuiltinPost() []string {
	return []string{
		"RULE-SET,cn-domain,direct",
		"GEOIP,cn,direct",
	}
}

// stripBuiltin 从用户规则中剔除与内置规则重复的条目。
// 兼容旧版本：以前这些规则写在配置文件里，升级后自动迁移。
func stripBuiltin(rules []string) []string {
	builtin := map[string]bool{}
	for _, r := range BuiltinPre() {
		builtin[normalizeRule(r)] = true
	}
	for _, r := range BuiltinPost() {
		builtin[normalizeRule(r)] = true
	}
	var out []string
	for _, r := range rules {
		if !builtin[normalizeRule(r)] {
			out = append(out, r)
		}
	}
	return out
}

func normalizeRule(r string) string {
	parts := strings.Split(r, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.ToUpper(strings.Join(parts, ","))
}

func boolPtr(v bool) *bool { return &v }

// IPv4Preferred 报告是否强制 IPv4 优先（未配置时默认 true）。
func (c *Config) IPv4Preferred() bool {
	if c.PreferIPv4 == nil {
		return true
	}
	return *c.PreferIPv4
}

// Load 从文件读取配置。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	c.Rules = stripBuiltin(c.Rules)
	// 迁移：旧版本无节点安装时 final 写成悬空的 "proxy"（无目标出口名），
	// 语义上等于本机直出，归一为 "direct"，让 DIRECT 正确显示为当前出口。
	if c.Final == "proxy" || c.Final == "" {
		c.Final = "direct"
	}
	return c, c.Validate()
}

// Save 原子写入配置。
//
// 服务沙箱（ProtectSystem=full）内 /etc 只读，直接写会 EROFS；
// 此时降级为 systemd-run 请求 PID 1 在沙箱外完成同样的原子写。
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileSandboxSafe(path, append(b, '\n'), 0o600)
}

// WriteFileSandboxSafe 原子写文件；沙箱内目标路径只读时，
// 经 systemd-run 由 PID 1 在沙箱外代写（与自升级同一通道）。
// 内容以 base64 传递，避免任何引号/转义问题。
func WriteFileSandboxSafe(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err == nil {
		if rerr := os.Rename(tmp, path); rerr == nil {
			return nil
		}
		_ = os.Remove(tmp)
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	script := fmt.Sprintf(
		"echo %s | base64 -d > %q && chmod %o %q && mv -f %q %q",
		b64, tmp, mode, tmp, tmp, path)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-run",
		"--quiet", "--wait", "--collect",
		"--property=Type=oneshot",
		"/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("写入 %s 失败（沙箱外代写也失败）: %v: %s",
			path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Validate 做基本校验。
func (c *Config) Validate() error {
	if c.Relay.Listen == "" {
		return fmt.Errorf("relay.listen 不能为空")
	}
	if c.Relay.CertFile == "" || c.Relay.KeyFile == "" {
		return fmt.Errorf("relay.cert_file / relay.key_file 不能为空")
	}
	seen := map[string]bool{}
	for _, e := range c.Egress {
		if e.Name == "" {
			return fmt.Errorf("出口名不能为空")
		}
		if seen[e.Name] {
			return fmt.Errorf("出口名重复: %s", e.Name)
		}
		seen[e.Name] = true
		switch e.Type {
		case "direct":
		case "socks5":
			if e.Addr == "" {
				return fmt.Errorf("出口 %s 缺少 addr", e.Name)
			}
		default:
			return fmt.Errorf("出口 %s 类型未知: %s", e.Name, e.Type)
		}
	}
	if c.Final == "" {
		return fmt.Errorf("final 不能为空")
	}
	if c.Bot.Token != "" && len(c.Bot.Admins) == 0 {
		return fmt.Errorf("已配置 bot.token 但 bot.admins 为空，Bot 将不响应任何人")
	}

	if c.Android.Enabled {
		if c.Android.GatewayIP == "" {
			return fmt.Errorf("已启用 Android 支持但 android.gateway_ip 为空")
		}
		if net.ParseIP(c.Android.GatewayIP) == nil {
			return fmt.Errorf("android.gateway_ip %q 不是合法 IP", c.Android.GatewayIP)
		}
	}
	if strings.HasPrefix(c.Final, "proxy:") {
		name := strings.TrimPrefix(c.Final, "proxy:")
		if !seen[name] {
			return fmt.Errorf("final 指向不存在的出口: %s", name)
		}
	}
	return nil
}
