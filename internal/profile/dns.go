package profile

import (
	"bytes"
	"fmt"
)

// PayloadTypeDNS 是加密 DNS 载荷类型（iOS 14+）。
const PayloadTypeDNS = "com.apple.dnsSettings.managed"

// DNSOptions 生成蜂窝加密 DNS 描述文件。
//
// 描述文件只改 DNS，不建立 VPN 或中继连接。
//   - 蜂窝：DoT 指向网关，国外域名 A 记录被改写到网关（由 dot 包完成），
//     国内域名返回真实 IP，手机本地直连。
//   - Wi-Fi：OnDemandRules 命中 Disconnect，完全使用 Wi-Fi 自身 DNS，
//     不经过网关。
//
// Apple 官方 payload 注记：手动安装（非 MDM 下发）时对蜂窝网络同样生效，
// 这正是本模式的前提。
type DNSOptions struct {
	// Host 是 DoT 服务器主机名，必须与网关 TLS 证书匹配。
	Host string
	// ServerAddresses 是 DoT 服务器 IP（通常为 dns.gateway_ip）。
	// 可为空：为空时系统按 Host 解析。
	ServerAddresses []string

	Organization string
	DisplayName  string
	Description  string

	// 稳定标识：同一网关的后续版本必须复用，避免 iOS 视为新配置。
	ProfileIdentifier string
	DNSIdentifier     string
	ProfileUUID       string
	DNSPayloadUUID    string
}

// DefaultDNS 返回填好稳定标识的默认参数。
func DefaultDNS(host string) DNSOptions {
	return DNSOptions{
		Host:         host,
		Organization: "5gpn-NEXT",
		DisplayName:  "5gpn-NEXT 蜂窝DNS",
		Description: "5gpn-NEXT 蜂窝 DNS 分流：仅蜂窝数据下启用加密 DNS，" +
			"Wi-Fi 下自动停用、完全不受影响。不建立 VPN 或中继连接。",
		ProfileIdentifier: "de.ke1e.5gpn.next.dnsmode",
		DNSIdentifier:     "de.ke1e.5gpn.next.dnsmode.dot",
	}
}

// Build 渲染 plist。
func (o DNSOptions) Build() ([]byte, error) {
	if o.Host == "" {
		return nil, fmt.Errorf("host 不能为空")
	}
	if o.ProfileUUID == "" {
		o.ProfileUUID = deriveUUID("dns-profile:" + o.Host)
	}
	if o.DNSPayloadUUID == "" {
		o.DNSPayloadUUID = deriveUUID("dns-payload:" + o.Host)
	}

	settings := dict{}
	settings.set("DNSProtocol", str("TLS"))
	settings.set("ServerName", str(o.Host))
	if len(o.ServerAddresses) > 0 {
		settings.set("ServerAddresses", strArray(o.ServerAddresses))
	}

	// 规则有序 first-match：蜂窝启用，其余（Wi-Fi/以太网/未知）一律停用。
	cellular := dict{}
	cellular.set("InterfaceTypeMatch", str("Cellular"))
	cellular.set("Action", str("Connect"))
	fallback := dict{}
	fallback.set("Action", str("Disconnect"))

	dns := dict{}
	dns.set("PayloadType", str(PayloadTypeDNS))
	dns.set("PayloadVersion", integer(1))
	dns.set("PayloadIdentifier", str(o.DNSIdentifier))
	dns.set("PayloadUUID", str(o.DNSPayloadUUID))
	dns.set("PayloadDisplayName", str(o.DisplayName))
	dns.set("PayloadDescription", str(o.Description))
	dns.set("PayloadOrganization", str(o.Organization))
	dns.set("DNSSettings", settings)
	dns.set("OnDemandRules", array{cellular, fallback})
	dns.set("ProhibitDisablement", boolean(false))

	root := dict{}
	root.set("PayloadType", str("Configuration"))
	root.set("PayloadVersion", integer(1))
	root.set("PayloadIdentifier", str(o.ProfileIdentifier))
	root.set("PayloadUUID", str(o.ProfileUUID))
	root.set("PayloadDisplayName", str(o.DisplayName))
	root.set("PayloadDescription", str(o.Description))
	root.set("PayloadOrganization", str(o.Organization))
	root.set("PayloadRemovalDisallowed", boolean(false))
	root.set("PayloadContent", array{dns})

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	root.render(&buf, 0)
	buf.WriteString("</plist>\n")
	return buf.Bytes(), nil
}
