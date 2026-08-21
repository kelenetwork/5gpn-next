// Package fw 维护 5gpn-next 自有的 nftables 规则。
//
// 只操作本项目独占的 inet fgpn 表，绝不触碰其它表或链，
// 因此不会影响 Docker、fail2ban 或用户既有防火墙配置。
package fw

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tableName = "inet fgpn"
	chainName = "input"
	// quicComment 标记由本程序添加的 QUIC 放行规则。
	quicComment = "5gpn-quic-takeover"
	cmdTimeout  = 5 * time.Second
)

// EnsureIngressRestrictions 为已监听端口补齐“客户端放行 + 公网丢弃”。
//
// install.sh 会为新装机器写完整规则，但内置自更新只替换二进制，不会重跑
// 安装器；生产旧机因此可能长期只有 allow、没有兜底 drop。这里在每次新版
// 启动时幂等补齐，使安全修复真正覆盖存量部署。应用层仍保留第二道校验。
func EnsureIngressRestrictions(ctx context.Context, clientCIDR string, tcpPorts, udpPorts []int) (changed bool, err error) {
	pfx, err := netip.ParsePrefix(clientCIDR)
	if err != nil {
		return false, fmt.Errorf("客户端网段无效: %w", err)
	}
	family := "ip"
	if pfx.Addr().Is6() {
		family = "ip6"
	}
	cidr := pfx.Masked().String()
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}
	hasComment := func(comments ...string) bool {
		for _, r := range rules {
			for _, comment := range comments {
				if strings.Contains(r.text, `comment "`+comment+`"`) {
					return true
				}
			}
		}
		return false
	}

	// 通用 installer 规则存在时不再制造重复项；旧版 legacy allow 也视为
	// 覆盖默认 DNS 端口。缺失时用端口级 comment，避免中途失败后只补一半。
	for _, port := range cleanPorts(tcpPorts) {
		allowComment := "5gpn-runtime-allow-tcp-" + strconv.Itoa(port)
		denyComment := "5gpn-runtime-deny-tcp-" + strconv.Itoa(port)
		allowCovered := hasComment(allowComment)
		denyCovered := hasComment(denyComment)
		if port == firstPort(tcpPorts) {
			allowCovered = allowCovered || hasComment("5gpn-next")
			denyCovered = denyCovered || hasComment("5gpn-deny-public-panel")
		}
		if !allowCovered && hasComment("5gpn-dns", "5gpn-android") {
			allowCovered = true
		}
		if !denyCovered && hasComment("5gpn-deny-public-tcp") {
			denyCovered = true
		}
		if !allowCovered {
			if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
				family, "saddr", cidr, "tcp", "dport", strconv.Itoa(port), "accept",
				"comment", `"`+allowComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
		if !denyCovered {
			if err := run(ctx, "add", "rule", "inet", "fgpn", chainName,
				"tcp", "dport", strconv.Itoa(port), "drop",
				"comment", `"`+denyComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	for _, port := range cleanPorts(udpPorts) {
		allowComment := "5gpn-runtime-allow-udp-" + strconv.Itoa(port)
		denyComment := "5gpn-runtime-deny-udp-" + strconv.Itoa(port)
		allowCovered := hasComment(allowComment, quicComment, "5gpn-android")
		denyCovered := hasComment(denyComment, "5gpn-deny-public-udp")
		if !allowCovered {
			if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
				family, "saddr", cidr, "udp", "dport", strconv.Itoa(port), "accept",
				"comment", `"`+allowComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
		if !denyCovered {
			if err := run(ctx, "add", "rule", "inet", "fgpn", chainName,
				"udp", "dport", strconv.Itoa(port), "drop",
				"comment", `"`+denyComment+`"`); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	return changed, nil
}

func cleanPorts(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func firstPort(in []int) int {
	for _, p := range in {
		if p >= 1 && p <= 65535 {
			return p
		}
	}
	return 0
}

// EnsureQUICAccept 让客户端的 QUIC（UDP 443）能够到达网关监听。
//
// 旧版本在防火墙层 reject UDP 443，指望客户端回落 TCP；Google Play
// 下载器不回落，只会无限重试。接管 QUIC 后必须放行，否则新监听收不到
// 任何数据报。
//
// 行为是幂等的：已放行则不做任何修改。仅当确实改动过才返回 changed=true。
func EnsureQUICAccept(ctx context.Context, clientCIDR string) (changed bool, err error) {
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}

	var rejectHandles []string
	hasAccept := false
	for _, r := range rules {
		// 只操作本项目带明确 comment 的“客户端 QUIC 行为”规则。
		// 公网来源的兜底 drop 也包含 udp/443，绝不能被这里误删。
		switch {
		case strings.Contains(r.text, `comment "`+quicComment+`"`):
			if strings.Contains(r.text, "accept") {
				hasAccept = true
			}
		case strings.Contains(r.text, `comment "5gpn-dns-quic"`):
			if r.handle != "" {
				rejectHandles = append(rejectHandles, r.handle)
			}
		}
	}

	// 先加放行、再删拒绝：任何时刻都不出现「既不放行也不拒绝」的空窗。
	if !hasAccept {
		if err := addAccept(ctx, clientCIDR); err != nil {
			return false, err
		}
		changed = true
	}
	for _, h := range rejectHandles {
		if err := deleteRule(ctx, h); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// RestoreQUICReject 恢复「拒绝 UDP 443」的旧行为。
//
// 关闭 QUIC 接管时调用：监听已经不存在，若继续放行，客户端发出的
// QUIC 会石沉大海（无 ICMP 回应），比明确拒绝更糟。
func RestoreQUICReject(ctx context.Context, clientCIDR string) (changed bool, err error) {
	rules, err := listChain(ctx)
	if err != nil {
		return false, err
	}
	var acceptHandles []string
	hasReject := false
	for _, r := range rules {
		switch {
		case strings.Contains(r.text, `comment "5gpn-dns-quic"`):
			hasReject = true
		case strings.Contains(r.text, `comment "`+quicComment+`"`):
			if r.handle != "" {
				acceptHandles = append(acceptHandles, r.handle)
			}
		}
	}
	if !hasReject {
		// insert 保证客户端规则位于公网兜底 drop 之前。
		if err := run(ctx, "insert", "rule", "inet", "fgpn", chainName,
			"ip", "saddr", clientCIDR, "udp", "dport", "443",
			"reject", "with", "icmp", "port-unreachable",
			"comment", `"5gpn-dns-quic"`); err != nil {
			return false, err
		}
		changed = true
	}
	for _, h := range acceptHandles {
		if err := deleteRule(ctx, h); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

type rule struct {
	text   string
	handle string
}

func listChain(ctx context.Context) ([]rule, error) {
	c, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(c, "nft", "-a", "list", "chain", "inet", "fgpn", chainName).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("读取 %s %s 失败: %w (%s)", tableName, chainName, err, strings.TrimSpace(string(out)))
	}
	var rules []rule
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "table ") ||
			strings.HasPrefix(line, "chain ") || strings.HasPrefix(line, "type ") ||
			line == "}" {
			continue
		}
		r := rule{text: line}
		if i := strings.LastIndex(line, "# handle "); i >= 0 {
			r.handle = strings.TrimSpace(line[i+len("# handle "):])
			r.text = strings.TrimSpace(line[:i])
		}
		rules = append(rules, r)
	}
	return rules, sc.Err()
}

func addAccept(ctx context.Context, clientCIDR string) error {
	// insert 保证客户端放行位于公网兜底 drop 之前。
	return run(ctx, "insert", "rule", "inet", "fgpn", chainName,
		"ip", "saddr", clientCIDR, "udp", "dport", "443", "accept",
		"comment", `"`+quicComment+`"`)
}

func deleteRule(ctx context.Context, handle string) error {
	return run(ctx, "delete", "rule", "inet", "fgpn", chainName, "handle", handle)
}

func run(ctx context.Context, args ...string) error {
	c, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(c, "nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s 失败: %w (%s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
