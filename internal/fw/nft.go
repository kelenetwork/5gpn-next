// Package fw 维护 5gpn-next 自有的 nftables 规则。
//
// 只操作本项目独占的 inet fgpn 表，绝不触碰其它表或链，
// 因此不会影响 Docker、fail2ban 或用户既有防火墙配置。
package fw

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
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
		if !strings.Contains(r.text, "udp dport 443") {
			continue
		}
		switch {
		case strings.Contains(r.text, "reject"), strings.Contains(r.text, "drop"):
			if r.handle != "" {
				rejectHandles = append(rejectHandles, r.handle)
			}
		case strings.Contains(r.text, "accept"):
			hasAccept = true
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
		if !strings.Contains(r.text, "udp dport 443") {
			continue
		}
		if strings.Contains(r.text, "reject") {
			hasReject = true
		} else if strings.Contains(r.text, "accept") && r.handle != "" {
			acceptHandles = append(acceptHandles, r.handle)
		}
	}
	if !hasReject {
		if err := run(ctx, "add", "rule", "inet", "fgpn", chainName,
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
	return run(ctx, "add", "rule", "inet", "fgpn", chainName,
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
