package node

import (
	"fmt"
	"strings"
)

// MihomoConfig 渲染 mihomo 配置。
//
// mihomo 在此仅作为出口协议栈：只监听本机 SOCKS5，不接管任何流量，
// 分流决策全部由 5gpnd 完成。因此配置刻意保持最小。
func (n *Node) MihomoConfig(socksPort int) (string, error) {
	if n.Server == "" || n.Port == 0 {
		return "", fmt.Errorf("节点缺少服务器地址或端口")
	}

	proxy, err := n.mihomoProxy()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# 由 5gpn-next 生成，请勿手动编辑。\n")
	b.WriteString("# mihomo 在此仅作为出口协议栈，分流由 5gpnd 决策。\n")
	fmt.Fprintf(&b, "mixed-port: 0\nsocks-port: %d\n", socksPort)
	b.WriteString("allow-lan: false\n")
	b.WriteString("bind-address: 127.0.0.1\n")
	// 必须为 rule：global 模式会走 GLOBAL 选择器并绕过下方 rules
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: warning\n")
	b.WriteString("ipv6: false\n")
	b.WriteString("external-controller: 127.0.0.1:9095\n")
	b.WriteString("profile:\n  store-selected: false\n  store-fake-ip: false\n")
	b.WriteString("\nproxies:\n")
	b.WriteString(proxy)
	b.WriteString("\nproxy-groups:\n")
	b.WriteString("  - name: \"PROXY\"\n    type: select\n    proxies:\n      - \"node\"\n")
	b.WriteString("\nrules:\n  - MATCH,PROXY\n")
	return b.String(), nil
}

// mihomoProxy 渲染单个 proxies 条目。出口名固定为 ASCII 的 node，
// 避免节点名含 emoji 或空格时在 YAML 与配置引用中出问题。
func (n *Node) mihomoProxy() (string, error) {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("  - name: \"node\"\n")
	w("    type: %s\n", n.Type)
	w("    server: %s\n", n.Server)
	w("    port: %d\n", n.Port)

	switch n.Type {
	case "ss":
		w("    cipher: %s\n", n.Cipher)
		w("    password: %s\n", yamlStr(n.Password))

	case "vless":
		w("    uuid: %s\n", n.UUID)
		w("    tls: %t\n", n.TLS)
		if n.Flow != "" {
			w("    flow: %s\n", n.Flow)
		}
		if n.Security == "reality" {
			if n.PublicKey == "" {
				return "", fmt.Errorf("reality 节点缺少 pbk 公钥参数")
			}
			w("    reality-opts:\n      public-key: %s\n", n.PublicKey)
			if n.ShortID != "" {
				w("      short-id: %s\n", yamlStr(n.ShortID))
			}
		}
		n.writeTLSCommon(w)
		n.writeNetwork(w)

	case "vmess":
		w("    uuid: %s\n", n.UUID)
		w("    alterId: %d\n", n.AlterID)
		w("    cipher: %s\n", orDef(n.Security, "auto"))
		w("    tls: %t\n", n.TLS)
		n.writeTLSCommon(w)
		n.writeNetwork(w)

	case "trojan":
		w("    password: %s\n", yamlStr(n.Password))
		n.writeTLSCommon(w)
		n.writeNetwork(w)

	case "hysteria2":
		w("    password: %s\n", yamlStr(n.Password))
		n.writeTLSCommon(w)

	case "tuic":
		w("    uuid: %s\n", n.UUID)
		w("    password: %s\n", yamlStr(n.Password))
		n.writeTLSCommon(w)

	case "socks5", "http":
		if n.Username != "" {
			w("    username: %s\n", yamlStr(n.Username))
			w("    password: %s\n", yamlStr(n.Password))
		}
		if n.Type == "http" && n.TLS {
			w("    tls: true\n")
		}

	default:
		return "", fmt.Errorf("未支持渲染的类型 %q", n.Type)
	}

	if n.UDP {
		w("    udp: true\n")
	}
	return b.String(), nil
}

func (n *Node) writeTLSCommon(w func(string, ...any)) {
	if n.SNI != "" {
		w("    servername: %s\n", n.SNI)
	}
	if n.SkipCertVerify {
		w("    skip-cert-verify: true\n")
	}
	if n.ClientFP != "" {
		w("    client-fingerprint: %s\n", n.ClientFP)
	}
	if len(n.ALPN) > 0 {
		w("    alpn:\n")
		for _, a := range n.ALPN {
			w("      - %s\n", strings.TrimSpace(a))
		}
	}
}

func (n *Node) writeNetwork(w func(string, ...any)) {
	switch n.Network {
	case "ws":
		w("    network: ws\n    ws-opts:\n")
		w("      path: %s\n", yamlStr(orDef(n.WSPath, "/")))
		if n.WSHost != "" {
			w("      headers:\n        Host: %s\n", n.WSHost)
		}
	case "grpc":
		w("    network: grpc\n")
		if n.WSPath != "" {
			w("    grpc-opts:\n      grpc-service-name: %s\n", yamlStr(n.WSPath))
		}
	case "", "tcp":
		// 默认，无需显式声明
	default:
		w("    network: %s\n", n.Network)
	}
}

// yamlStr 安全地引用字符串，避免密码中的特殊字符破坏 YAML。
func yamlStr(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Redacted 返回可安全打印的摘要，绝不含密钥。
func (n *Node) Redacted() string {
	secret := n.Password
	if secret == "" {
		secret = n.UUID
	}
	return fmt.Sprintf("类型=%s 服务器=%s:%d 凭据=<已隐藏 len=%d>",
		n.Type, n.Server, n.Port, len(secret))
}
