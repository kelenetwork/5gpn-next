// Package config 定义 5gpn-NEXT 的声明式配置。
//
// 设计原则：期望态存配置，reconcile 负责收敛，
// 替代四家项目"bash 事务 + 快照回滚"的做法。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	// Telegram Bot（可选）
	Bot BotConfig `json:"bot"`

	// 内网 Web 面板
	Panel PanelConfig `json:"panel"`

	// 客户端来源网段（用于面板访问控制与提示）
	ClientCIDR string `json:"client_cidr"`

	// 日志
	LogPath string `json:"log_path"`
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
	// Type: direct | socks5
	Type    string `json:"type"`
	Addr    string `json:"addr,omitempty"`
	HasIPv6 bool   `json:"has_ipv6,omitempty"`
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
		Rules: []string{
			// 私有地址永不出网关
			"IP-CIDR,10.0.0.0/8,direct",
			"IP-CIDR,172.16.0.0/12,direct",
			"IP-CIDR,192.168.0.0/16,direct",
			"IP-CIDR,127.0.0.0/8,direct",
			// 国内域名与国内 IP 直连
			"RULE-SET,cn-domain,direct",
			"GEOIP,cn,direct",
		},
		Final:      "proxy",
		ClientCIDR: "172.22.0.0/16",
		Panel:      PanelConfig{Enabled: true},
		LogPath:    "/var/log/5gpn-next/trace.jsonl",
		RuleSets: []RuleSetConfig{
			{Name: "cn-domain", Kind: "domain", IntervalHours: 24,
				URL: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
			{Name: "geoip:cn", Kind: "ipcidr", IntervalHours: 24,
				URL: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"},
		},
	}
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
	return c, c.Validate()
}

// Save 原子写入配置。
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	if c.Panel.Enabled && c.Panel.Token == "" {
		return fmt.Errorf("面板已启用但 panel.token 为空")
	}
	if strings.HasPrefix(c.Final, "proxy:") {
		name := strings.TrimPrefix(c.Final, "proxy:")
		if !seen[name] {
			return fmt.Errorf("final 指向不存在的出口: %s", name)
		}
	}
	return nil
}
