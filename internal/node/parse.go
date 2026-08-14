// Package node 解析分享链接并生成 mihomo 出口配置。
//
// 设计取舍：只做"链接 → mihomo proxies 条目"的转换，协议实现完全交给
// mihomo 官方二进制。这样新协议由 mihomo 升级带来，本项目无需跟进，
// 也就不必 fork mihomo。
package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Node 是一个出口节点。
type Node struct {
	Name   string
	Type   string // ss / vless / vmess / trojan / hysteria2 / tuic / socks5 / http
	Server string
	Port   int

	// 各协议字段（按需填充）
	Cipher         string
	Password       string
	UUID           string
	AlterID        int
	Security       string
	Network        string
	TLS            bool
	SNI            string
	SkipCertVerify bool
	ALPN           []string
	Flow           string
	ClientFP       string
	PublicKey      string
	ShortID        string
	WSPath         string
	WSHost         string
	Username       string
	UDP            bool
}

// Parse 解析单条分享链接。
func Parse(raw string) (*Node, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("链接为空")
	}
	i := strings.Index(s, "://")
	if i < 0 {
		return nil, fmt.Errorf("不是有效的分享链接（缺少协议前缀）")
	}
	scheme := strings.ToLower(s[:i])

	switch scheme {
	case "ss":
		return parseSS(s)
	case "vless":
		return parseVLESS(s)
	case "trojan":
		return parseTrojan(s)
	case "hysteria2", "hy2":
		return parseHysteria2(s)
	case "vmess":
		return parseVMess(s)
	case "socks5", "socks":
		return parseSocksHTTP(s, "socks5")
	case "http", "https":
		return parseSocksHTTP(s, "http")
	case "tuic":
		return parseTUIC(s)
	}
	return nil, fmt.Errorf("暫不支持的协议 %q（mihomo 支持但本解析器未覆盖，可手写 /etc/mihomo-5gpn/config.yaml）", scheme)
}

// ---------- 各协议 ----------

// parseSS 支持 SIP002（base64 userinfo）与整体 base64 两种形态。
func parseSS(raw string) (*Node, error) {
	body := raw[len("ss://"):]

	name := ""
	if j := strings.Index(body, "#"); j >= 0 {
		name, _ = url.QueryUnescape(body[j+1:])
		body = body[:j]
	}
	query := ""
	if j := strings.Index(body, "?"); j >= 0 {
		query = body[j+1:]
		body = body[:j]
	}

	// 整体 base64（旧格式）：解码后形如 method:pass@host:port
	if !strings.Contains(body, "@") {
		dec, err := b64(body)
		if err != nil {
			return nil, fmt.Errorf("ss 链接解码失败: %w", err)
		}
		body = dec
	}

	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss 链接缺少 @ 分隔")
	}
	userinfo, hostport := body[:at], body[at+1:]

	// userinfo 可能是 base64，也可能是明文 method:password
	method, password := "", ""
	if dec, err := b64(userinfo); err == nil && strings.Contains(dec, ":") {
		method, password = splitFirst(dec, ":")
	} else if strings.Contains(userinfo, ":") {
		m, p := splitFirst(userinfo, ":")
		method = m
		password, _ = url.QueryUnescape(p)
	} else {
		return nil, fmt.Errorf("ss userinfo 格式无法识别")
	}
	if method == "" || password == "" {
		return nil, fmt.Errorf("ss 加密方式或密码为空")
	}

	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	n := &Node{
		Name: name, Type: "ss", Server: host, Port: port,
		Cipher: method, Password: password, UDP: true,
	}
	// plugin 等参数暂不支持，明确报错优于静默丢弃
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		return nil, fmt.Errorf("ss plugin=%q 暂不支持，请手写 mihomo 配置", q.Get("plugin"))
	}
	return n, nil
}

func parseVLESS(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vless 链接解析失败: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()

	n := &Node{
		Name:   frag(u),
		Type:   "vless",
		Server: u.Hostname(),
		Port:   port,
		UUID:   u.User.Username(),
		UDP:    true,

		Network:        orDef(q.Get("type"), "tcp"),
		Flow:           q.Get("flow"),
		SNI:            firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host")),
		ClientFP:       q.Get("fp"),
		PublicKey:      q.Get("pbk"),
		ShortID:        q.Get("sid"),
		WSPath:         q.Get("path"),
		WSHost:         q.Get("host"),
		SkipCertVerify: q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
	}
	sec := strings.ToLower(q.Get("security"))
	n.Security = sec
	n.TLS = sec == "tls" || sec == "reality" || sec == "xtls"
	if a := q.Get("alpn"); a != "" {
		n.ALPN = strings.Split(a, ",")
	}
	if n.UUID == "" {
		return nil, fmt.Errorf("vless 链接缺少 UUID")
	}
	if port == 0 {
		return nil, fmt.Errorf("vless 链接缺少端口")
	}
	return n, nil
}

func parseTrojan(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trojan 链接解析失败: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()
	pw, _ := url.QueryUnescape(u.User.Username())
	n := &Node{
		Name: frag(u), Type: "trojan", Server: u.Hostname(), Port: port,
		Password: pw, TLS: true, UDP: true,
		SNI:            firstNonEmpty(q.Get("sni"), q.Get("peer")),
		SkipCertVerify: q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
		Network:        orDef(q.Get("type"), "tcp"),
		WSPath:         q.Get("path"),
		WSHost:         q.Get("host"),
	}
	if a := q.Get("alpn"); a != "" {
		n.ALPN = strings.Split(a, ",")
	}
	if n.Password == "" || port == 0 {
		return nil, fmt.Errorf("trojan 链接缺少密码或端口")
	}
	return n, nil
}

func parseHysteria2(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 链接解析失败: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	q := u.Query()
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok && p != "" {
		pw = pw + ":" + p
	}
	pw, _ = url.QueryUnescape(pw)
	n := &Node{
		Name: frag(u), Type: "hysteria2", Server: u.Hostname(), Port: port,
		Password: pw, TLS: true, UDP: true,
		SNI:            q.Get("sni"),
		SkipCertVerify: q.Get("insecure") == "1",
	}
	if n.Password == "" {
		return nil, fmt.Errorf("hysteria2 链接缺少密码")
	}
	return n, nil
}

// parseVMess 支持常见的 base64(JSON) 形态。
func parseVMess(raw string) (*Node, error) {
	dec, err := b64(raw[len("vmess://"):])
	if err != nil {
		return nil, fmt.Errorf("vmess 链接解码失败（仅支持 base64 JSON 形态）: %w", err)
	}
	var v struct {
		PS   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"`
		ID   string      `json:"id"`
		Aid  interface{} `json:"aid"`
		Scy  string      `json:"scy"`
		Net  string      `json:"net"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
		Host string      `json:"host"`
		Path string      `json:"path"`
	}
	if err := json.Unmarshal([]byte(dec), &v); err != nil {
		return nil, fmt.Errorf("vmess JSON 解析失败: %w", err)
	}
	n := &Node{
		Name: v.PS, Type: "vmess", Server: v.Add,
		Port: toInt(v.Port), UUID: v.ID, AlterID: toInt(v.Aid),
		Security: orDef(v.Scy, "auto"), Network: orDef(v.Net, "tcp"),
		TLS: v.TLS == "tls", SNI: firstNonEmpty(v.SNI, v.Host),
		WSPath: v.Path, WSHost: v.Host, UDP: true,
	}
	if n.UUID == "" || n.Server == "" || n.Port == 0 {
		return nil, fmt.Errorf("vmess 链接字段不完整")
	}
	return n, nil
}

func parseSocksHTTP(raw, typ string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s 链接解析失败: %w", typ, err)
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		return nil, fmt.Errorf("%s 链接缺少端口", typ)
	}
	pw, _ := u.User.Password()
	return &Node{
		Name: frag(u), Type: typ, Server: u.Hostname(), Port: port,
		Username: u.User.Username(), Password: pw,
		TLS: strings.HasPrefix(strings.ToLower(raw), "https://"),
		UDP: typ == "socks5",
	}, nil
}

func parseTUIC(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("tuic 链接解析失败: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	pw, _ := u.User.Password()
	q := u.Query()
	n := &Node{
		Name: frag(u), Type: "tuic", Server: u.Hostname(), Port: port,
		UUID: u.User.Username(), Password: pw, TLS: true, UDP: true,
		SNI:            q.Get("sni"),
		SkipCertVerify: q.Get("insecure") == "1" || q.Get("allow_insecure") == "1",
	}
	if a := q.Get("alpn"); a != "" {
		n.ALPN = strings.Split(a, ",")
	}
	if n.UUID == "" || port == 0 {
		return nil, fmt.Errorf("tuic 链接字段不完整")
	}
	return n, nil
}

// ---------- 小工具 ----------

func b64(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if p := len(s) % 4; p != 0 {
		s += strings.Repeat("=", 4-p)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func splitFirst(s, sep string) (string, string) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}

func splitHostPort(hp string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, fmt.Errorf("地址 %q 格式错误: %w", hp, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("端口 %q 无效", portStr)
	}
	return host, port, nil
}

func frag(u *url.URL) string {
	s, err := url.QueryUnescape(u.Fragment)
	if err != nil {
		return u.Fragment
	}
	return s
}

func orDef(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
