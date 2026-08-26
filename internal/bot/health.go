package bot

import (
	"context"
	"fmt"
	"html"
	"strings"

	"github.com/kelenetwork/5gpn-next/internal/monitor"
)

// showHealth 展示健康监控总览：出口探测、真实转发、DoT、会话水位与系统面。
func (b *Bot) showHealth(ctx context.Context, v view) {
	h, ok := b.Manager.HealthReport()
	if !ok {
		b.render(ctx, v, "🩺 <b>健康监控</b>\n\n监控未启用。", backTo("menu"))
		return
	}
	sys := b.Manager.SysHealthNow()

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>健康监控</b>\n", em("🔮"))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")

	// ---- 出口 ----
	if len(h.Egress) == 0 {
		sb.WriteString("<i>探测数据积累中，约 1 分钟后可见 ⏳</i>\n\n")
	} else {
		sb.WriteString("<b>出口链路</b>\n")
		for _, e := range h.Egress {
			sb.WriteString(egressHealthLine(e))
		}
		sb.WriteString("<i>探测＝到出口节点的 TCP 建连；转发＝真实用户流量拨号</i>\n\n")
	}

	// ---- DoT ----
	sb.WriteString("<b>DNS（DoT 上游）</b>\n<blockquote>")
	if h.DNS1h.Count > 0 {
		fmt.Fprintf(&sb, "%s 1h　均 <b>%dms</b> · p95 <b>%dms</b> · 失败 <b>%d</b>/%d",
			rateIcon(h.DNS1h.FailRate()), h.DNS1h.AvgMS, h.DNS1h.P95MS, h.DNS1h.Fail, h.DNS1h.Count)
	} else {
		sb.WriteString("1h 内无上游查询（缓存命中或无流量）")
	}
	if h.DNS24h.Count > 0 {
		fmt.Fprintf(&sb, "\n🕐 24h　均 <b>%dms</b> · p95 <b>%dms</b> · 失败 <b>%d</b>/%d",
			h.DNS24h.AvgMS, h.DNS24h.P95MS, h.DNS24h.Fail, h.DNS24h.Count)
	}
	sb.WriteString("</blockquote>\n")

	// ---- 会话水位 ----
	sb.WriteString("<b>会话水位</b>\n<blockquote>")
	fmt.Fprintf(&sb, "%s TCP 转发　<b>%d</b> / %d", levelIcon(h.TCPActive, h.TCPMax), h.TCPActive, h.TCPMax)
	if h.QUICMax > 0 {
		fmt.Fprintf(&sb, "\n%s QUIC 会话　<b>%d</b> / %d", levelIcon(h.QUICActive, h.QUICMax), h.QUICActive, h.QUICMax)
	}
	sb.WriteString("</blockquote>\n")

	// ---- 系统 ----
	sb.WriteString("<b>网关进程</b>\n<blockquote>")
	fmt.Fprintf(&sb, "%s 内存　<b>%.1f MB</b>\n", em("💻"), sys.MemoryMB)
	fmt.Fprintf(&sb, "🧵 goroutine　<b>%d</b>\n", sys.Goroutines)
	fmt.Fprintf(&sb, "%s 运行　<b>%s</b>", em("🔋"), sys.Uptime)
	if sys.CertDays >= 0 {
		icon := "🔐"
		if sys.CertDays <= 14 {
			icon = "⚠️"
		}
		fmt.Fprintf(&sb, "\n%s 证书剩余　<b>%d 天</b>", icon, sys.CertDays)
	}
	sb.WriteString("</blockquote>\n")
	sb.WriteString("\n<i>点击出口名可查看最近异常明细 ↓</i>")

	var rows [][]btn
	var cur []btn
	for _, e := range h.Egress {
		cur = append(cur, btn{"🔍 " + truncateText(e.Name, 10), "health_detail:" + e.Name})
		if len(cur) == 2 {
			rows = append(rows, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		rows = append(rows, cur)
	}
	rows = append(rows, []btn{{"🔄 刷新", "health"}}, []btn{{"« 返回主菜单", "menu"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// egressHealthLine 渲染单个出口的两行摘要。
func egressHealthLine(e monitor.EgressHealth) string {
	var sb strings.Builder
	icon := rateIcon(e.Probe1h.FailRate())
	if e.Probe1h.Count == 0 && e.Fw1h.Count > 0 {
		icon = rateIcon(e.Fw1h.FailRate())
	}
	fmt.Fprintf(&sb, "%s <b>%s</b>\n<blockquote>", icon, html.EscapeString(e.Name))
	wrote := false
	if e.Probe1h.Count > 0 {
		fmt.Fprintf(&sb, "探测 1h　均 <b>%dms</b> · p95 <b>%dms</b> · 失败 <b>%d</b>/%d",
			e.Probe1h.AvgMS, e.Probe1h.P95MS, e.Probe1h.Fail, e.Probe1h.Count)
		wrote = true
	}
	if e.Probe24h.Count > 0 && e.Probe24h.Count != e.Probe1h.Count {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "探测 24h　均 <b>%dms</b> · p95 <b>%dms</b> · 失败 <b>%d</b>/%d",
			e.Probe24h.AvgMS, e.Probe24h.P95MS, e.Probe24h.Fail, e.Probe24h.Count)
		wrote = true
	}
	if e.Fw1h.Count > 0 {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "转发 1h　<b>%d</b> 次 · 失败 <b>%d</b>（%.0f%%）",
			e.Fw1h.Count, e.Fw1h.Fail, e.Fw1h.FailRate()*100)
		wrote = true
	}
	if e.UpBytes > 0 || e.DownBytes > 0 {
		if wrote {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "流量　↑ <b>%s</b> · ↓ <b>%s</b>",
			humanBytes(e.UpBytes), humanBytes(e.DownBytes))
		wrote = true
	}
	if !wrote {
		sb.WriteString("暂无数据")
	}
	if !e.Probe1h.LastFailAt.IsZero() {
		fmt.Fprintf(&sb, "\n上次失败　%s", e.Probe1h.LastFailAt.Local().Format("15:04:05"))
	}
	sb.WriteString("</blockquote>\n")
	return sb.String()
}

// showHealthDetail 展示单出口最近异常探测点。
func (b *Bot) showHealthDetail(ctx context.Context, v view, name string) {
	samples := b.Manager.HealthAnomalies(name, 20)

	var sb strings.Builder
	fmt.Fprintf(&sb, "🔍 <b>出口异常明细</b> · <code>%s</code>\n", html.EscapeString(name))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	if len(samples) == 0 {
		sb.WriteString("✅ 24h 内没有异常探测点，这条出口很稳。\n")
	} else {
		sb.WriteString("<i>失败或显著慢于均值的探测点（新的在前）：</i>\n<blockquote>")
		for i, s := range samples {
			if i > 0 {
				sb.WriteString("\n")
			}
			if s.OK {
				fmt.Fprintf(&sb, "🐢 %s　<b>%dms</b>（慢）", s.At.Local().Format("01-02 15:04"), s.MS)
			} else {
				fmt.Fprintf(&sb, "❌ %s　<b>失败</b>", s.At.Local().Format("01-02 15:04"))
			}
		}
		sb.WriteString("</blockquote>\n")
		sb.WriteString("\n<i>感觉「卡了一下」时，对一下这里的时间点即可定位。</i>")
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🔄 刷新", "health_detail:" + name}},
		[]btn{{"« 返回健康监控", "health"}},
	))
}

// humanBytes 把字节数格式化为人类可读。
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// rateIcon 按失败率返回红黄绿。
func rateIcon(r float64) string {
	switch {
	case r >= 0.2:
		return "🔴"
	case r > 0:
		return "🟡"
	default:
		return "🟢"
	}
}

// levelIcon 按水位占比返回红黄绿。
func levelIcon(cur, max int) string {
	if max <= 0 {
		return "🟢"
	}
	switch r := float64(cur) / float64(max); {
	case r >= 0.9:
		return "🔴"
	case r >= 0.6:
		return "🟡"
	default:
		return "🟢"
	}
}
