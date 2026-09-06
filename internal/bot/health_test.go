package bot

import (
	"strings"
	"testing"
	"time"

	"github.com/w0ven/5gpn-next/internal/monitor"
)

// telegramTags 是 Telegram HTML parse_mode 支持的标签集合。
var telegramTags = map[string]bool{
	"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true,
	"s": true, "strike": true, "del": true, "span": true, "tg-spoiler": true,
	"a": true, "code": true, "pre": true, "blockquote": true,
}

// assertTelegramHTML 校验文本能被 Telegram 的 HTML parse_mode 接受。
//
// 存在理由：Bot 一律用 parse_mode=HTML 发送。文本里出现裸 `<`（比如
// "<0.1ms"）时 Telegram 直接返回 400，整条消息发不出去，用户看到的
// 现象是「点了按钮没反应 / 页面进不去」——完全没有错误提示。
func assertTelegramHTML(t *testing.T, s string) {
	t.Helper()
	var stack []string
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			t.Fatalf("裸 `<` 未闭合（Telegram 会返回 400）: %q", snippet(s, i))
		}
		inner := s[i+1 : i+end]
		closing := strings.HasPrefix(inner, "/")
		name := strings.TrimPrefix(inner, "/")
		if j := strings.IndexAny(name, " \t"); j >= 0 {
			name = name[:j]
		}
		if name == "" || !telegramTags[strings.ToLower(name)] {
			t.Fatalf("非法标签 %q（Telegram 会返回 400，整条消息发不出去）: %q",
				inner, snippet(s, i))
		}
		if closing {
			if len(stack) == 0 || stack[len(stack)-1] != strings.ToLower(name) {
				t.Fatalf("标签闭合不匹配 </%s>: %q", name, snippet(s, i))
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, strings.ToLower(name))
		}
		i += end
	}
	if len(stack) > 0 {
		t.Fatalf("标签未闭合: %v", stack)
	}
}

func snippet(s string, i int) string {
	lo := i - 30
	if lo < 0 {
		lo = 0
	}
	hi := i + 30
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
}

// 亚毫秒耗时曾被格式化成 "<0.1ms"，直接让健康监控整页发不出去。
func TestEgressHealthLineIsValidTelegramHTML(t *testing.T) {
	cases := []struct {
		name string
		e    monitor.EgressHealth
	}{
		{"亚毫秒桥探测", monitor.EgressHealth{
			Name: "hinet", Kind: monitor.ProbeKindBridge,
			Probe1h:  monitor.Window{Count: 60, AvgUS: 40, P95US: 85},
			Probe24h: monitor.Window{Count: 1440, AvgUS: 43, P95US: 91},
			Fw1h:     monitor.Window{Count: 10, AvgUS: 60, P95US: 90},
		}},
		{"真实链路", monitor.EgressHealth{
			Name: "softbank", Kind: monitor.ProbeKindEndToEnd,
			Probe1h:   monitor.Window{Count: 60, AvgUS: 135_000, P95US: 210_000},
			UpBytes:   1 << 20,
			DownBytes: 5 << 20,
		}},
		{"含失败与尖括号名", monitor.EgressHealth{
			Name: "a<b>&c", Kind: monitor.ProbeKindNode,
			Probe1h: monitor.Window{
				Count: 60, Fail: 3, AvgUS: 36_000, P95US: 99_000,
				LastFailAt: time.Now(),
			},
		}},
		{"无数据", monitor.EgressHealth{Name: "DIRECT"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertTelegramHTML(t, egressHealthLine(c.e))
		})
	}
}

// FormatUS 的输出会被直接拼进 HTML 消息，绝不能含裸尖括号。
func TestFormatUSHasNoHTMLSpecialChars(t *testing.T) {
	for _, us := range []int64{0, 1, 40, 99, 100, 432, 1500, 9999, 36_000, 4_000_000} {
		got := monitor.FormatUS(us)
		if strings.ContainsAny(got, "<>&") {
			t.Fatalf("FormatUS(%d)=%q 含 HTML 特殊字符，会让整条消息发送失败", us, got)
		}
	}
}
