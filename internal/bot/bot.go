// Package bot 实现 Telegram 管理机器人（纯标准库，长轮询）。
//
// 只接受配置中列出的管理员 ID；其它来源一律忽略，不回任何内容，
// 避免把网关暴露给陌生人。
package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/manage"
	"github.com/kelenetwork/5gpn-next/internal/stats"
)

// Bot 是 Telegram 管理机器人。
type Bot struct {
	Token   string
	Admins  []int64
	Manager *manage.Manager
	Version string

	client *http.Client
	offset int64

	// 等待用户输入的会话状态：chatID -> 待执行动作
	mu      sync.Mutex
	pending map[int64]string
}

// New 构造 Bot。
func New(token string, admins []int64, m *manage.Manager, version string) *Bot {
	return &Bot{
		Token:   token,
		Admins:  admins,
		Manager: m,
		Version: version,
		client:  &http.Client{Timeout: 70 * time.Second},
		pending: make(map[int64]string),
	}
}

// Run 启动长轮询，直到 ctx 取消。
func (b *Bot) Run(ctx context.Context) {
	log.Printf("Telegram Bot 已启动，管理员 %v", b.Admins)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		updates, err := b.getUpdates(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Bot 轮询失败: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for _, u := range updates {
			b.handle(ctx, u)
		}
	}
}

// ---------- Telegram API ----------

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64 `json:"message_id"`
		From      struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

func (b *Bot) api(ctx context.Context, method string, params url.Values) ([]byte, error) {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/%s", b.Token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var r struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, fmt.Errorf("telegram: %s", r.Description)
	}
	return r.Result, nil
}

func (b *Bot) getUpdates(ctx context.Context) ([]update, error) {
	p := url.Values{}
	p.Set("timeout", "50")
	p.Set("offset", strconv.FormatInt(b.offset, 10))
	p.Set("allowed_updates", `["message","callback_query"]`)
	raw, err := b.api(ctx, "getUpdates", p)
	if err != nil {
		return nil, err
	}
	var ups []update
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, err
	}
	for _, u := range ups {
		if u.UpdateID >= b.offset {
			b.offset = u.UpdateID + 1
		}
	}
	return ups, nil
}

// send 发送 HTML 消息。
//
// 一律走 HTML 而非 MarkdownV2：节点名、域名里常含 - _ . 等字符，
// MarkdownV2 需要逐字符转义，漏一个就整条发送失败。
func (b *Bot) send(ctx context.Context, chatID int64, text string, keyboard string) {
	p := url.Values{}
	p.Set("chat_id", strconv.FormatInt(chatID, 10))
	p.Set("text", text)
	p.Set("parse_mode", "HTML")
	p.Set("disable_web_page_preview", "true")
	if keyboard != "" {
		p.Set("reply_markup", keyboard)
	}
	if _, err := b.api(ctx, "sendMessage", p); err != nil {
		log.Printf("Bot 发送失败: %v", err)
	}
}

func (b *Bot) answerCallback(ctx context.Context, id, text string) {
	p := url.Values{}
	p.Set("callback_query_id", id)
	if text != "" {
		p.Set("text", text)
	}
	_, _ = b.api(ctx, "answerCallbackQuery", p)
}

// Notify 主动推送告警给所有管理员。
func (b *Bot) Notify(ctx context.Context, text string) {
	for _, id := range b.Admins {
		b.send(ctx, id, text, "")
	}
}

// ---------- 交互 ----------

func (b *Bot) isAdmin(id int64) bool {
	for _, a := range b.Admins {
		if a == id {
			return true
		}
	}
	return false
}

func (b *Bot) handle(ctx context.Context, u update) {
	switch {
	case u.CallbackQuery != nil:
		q := u.CallbackQuery
		if !b.isAdmin(q.From.ID) || q.Message == nil {
			return
		}
		b.answerCallback(ctx, q.ID, "")
		b.dispatch(ctx, q.Message.Chat.ID, q.Data)

	case u.Message != nil:
		m := u.Message
		if !b.isAdmin(m.From.ID) {
			return // 静默忽略陌生人
		}
		text := strings.TrimSpace(m.Text)
		if text == "" {
			return
		}

		// 处于等待输入状态时，优先当作输入处理
		b.mu.Lock()
		action, waiting := b.pending[m.Chat.ID]
		if waiting {
			delete(b.pending, m.Chat.ID)
		}
		b.mu.Unlock()

		if waiting && !strings.HasPrefix(text, "/") {
			b.handleInput(ctx, m.Chat.ID, action, text)
			return
		}
		b.dispatch(ctx, m.Chat.ID, strings.TrimPrefix(text, "/"))
	}
}

func (b *Bot) dispatch(ctx context.Context, chatID int64, cmd string) {
	switch {
	case cmd == "start" || cmd == "menu":
		b.showMenu(ctx, chatID)
	case cmd == "status":
		b.showStatus(ctx, chatID)
	case cmd == "egress":
		b.showEgress(ctx, chatID)
	case cmd == "rules":
		b.showRules(ctx, chatID)
	case cmd == "client":
		b.showClient(ctx, chatID)
	case cmd == "traffic":
		b.showTraffic(ctx, chatID)
	case cmd == "update":
		b.showUpdate(ctx, chatID)
	case cmd == "ios_profile":
		b.sendProfile(ctx, chatID)
	case cmd == "android_guide":
		b.showAndroid(ctx, chatID)
	case cmd == "update_check":
		b.doUpdateCheck(ctx, chatID)
	case strings.HasPrefix(cmd, "update_apply:"):
		b.doUpdateApply(ctx, chatID, strings.TrimPrefix(cmd, "update_apply:"))
	case cmd == "update_rollback":
		b.showRollback(ctx, chatID)
	case strings.HasPrefix(cmd, "rollback:"):
		b.doRollback(ctx, chatID, strings.TrimPrefix(cmd, "rollback:"))
	case cmd == "cancel":
		b.mu.Lock()
		delete(b.pending, chatID)
		b.mu.Unlock()
		b.send(ctx, chatID, "已取消。", "")

	case cmd == "ask_egress_add":
		b.ask(ctx, chatID, "egress_add",
			"请粘贴节点分享链接：\n\n<i>支持 ss:// vless:// vmess:// trojan:// hysteria2:// tuic:// socks5:// http://</i>\n\n发送 /cancel 取消。")
	case cmd == "ask_rule_add":
		b.ask(ctx, chatID, "rule_add",
			"请输入分流规则，格式为 <code>类型,值,动作</code>\n\n例如：\n<code>DOMAIN-SUFFIX,openai.com,proxy:node</code>\n<code>DOMAIN-SUFFIX,example.cn,direct</code>\n<code>DOMAIN-KEYWORD,ads,block</code>\n\n发送 /cancel 取消。")
	case cmd == "ask_probe":
		b.ask(ctx, chatID, "probe",
			"请输入要诊断的域名，例如 <code>youtube.com</code>\n\n发送 /cancel 取消。")

	case strings.HasPrefix(cmd, "switch:"):
		name := strings.TrimPrefix(cmd, "switch:")
		if err := b.Manager.SwitchEgress(name); err != nil {
			b.send(ctx, chatID, "切换失败："+html.EscapeString(err.Error()), "")
			return
		}
		b.send(ctx, chatID, "已切换到出口 <b>"+html.EscapeString(name)+"</b>", "")
		b.showEgress(ctx, chatID)

	case strings.HasPrefix(cmd, "del_egress:"):
		name := strings.TrimPrefix(cmd, "del_egress:")
		if err := b.Manager.RemoveEgress(name); err != nil {
			b.send(ctx, chatID, "删除失败："+html.EscapeString(err.Error()), "")
			return
		}
		b.send(ctx, chatID, "已删除出口 <b>"+html.EscapeString(name)+"</b>", "")
		b.showEgress(ctx, chatID)

	case strings.HasPrefix(cmd, "del_rule:"):
		idx, err := strconv.Atoi(strings.TrimPrefix(cmd, "del_rule:"))
		if err == nil {
			if err := b.Manager.RemoveRule(idx); err != nil {
				b.send(ctx, chatID, "删除失败："+html.EscapeString(err.Error()), "")
				return
			}
		}
		b.showRules(ctx, chatID)

	default:
		b.showMenu(ctx, chatID)
	}
}

func (b *Bot) ask(ctx context.Context, chatID int64, action, prompt string) {
	b.mu.Lock()
	b.pending[chatID] = action
	b.mu.Unlock()
	b.send(ctx, chatID, prompt, "")
}

func (b *Bot) handleInput(ctx context.Context, chatID int64, action, text string) {
	switch action {
	case "egress_add":
		msg, err := b.Manager.AddEgress("", text)
		if err != nil {
			b.send(ctx, chatID, "添加失败："+html.EscapeString(err.Error()), "")
			return
		}
		b.send(ctx, chatID, "✅ "+html.EscapeString(msg), "")
		b.showEgress(ctx, chatID)

	case "rule_add":
		if err := b.Manager.AddRule(text); err != nil {
			b.send(ctx, chatID, "添加失败："+html.EscapeString(err.Error()), "")
			return
		}
		b.send(ctx, chatID, "✅ 规则已添加", "")
		b.showRules(ctx, chatID)

	case "probe":
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		tr := b.Manager.Probe(cctx, strings.TrimSpace(text))
		b.send(ctx, chatID,
			"<b>诊断 "+html.EscapeString(text)+"</b>\n<pre>"+html.EscapeString(tr.Human())+"</pre>", "")
	}
}

// ---------- 视图 ----------

func (b *Bot) showMenu(ctx context.Context, chatID int64) {
	kb := inlineKeyboard(
		[]btn{{"📊 状态", "status"}, {"📈 流量", "traffic"}},
		[]btn{{"📤 出口", "egress"}, {"📑 分流", "rules"}},
		[]btn{{"🔍 诊断", "ask_probe"}, {"📱 客户端", "client"}},
		[]btn{{"🔄 更新", "update"}},
	)
	b.send(ctx, chatID,
		"<b>5gpn-NEXT 管理面板</b>\n\n选择要执行的操作：", kb)
}

func (b *Bot) showStatus(ctx context.Context, chatID int64) {
	st := b.Manager.Status(b.Version)
	var sb strings.Builder
	sb.WriteString("<b>📊 运行状态</b>\n\n")
	fmt.Fprintf(&sb, "版本：<code>%s</code>\n", html.EscapeString(st.Version))
	fmt.Fprintf(&sb, "运行：%s\n", st.Uptime)
	fmt.Fprintf(&sb, "监听：<code>%s</code>\n", html.EscapeString(st.Listen))
	fmt.Fprintf(&sb, "内存：%.1f MB\n", st.MemoryMB)
	fmt.Fprintf(&sb, "规则：%d 条\n", st.Rules)
	if st.CertUntil != "" {
		fmt.Fprintf(&sb, "证书：%s\n", html.EscapeString(st.CertUntil))
	}
	if len(st.Counters) > 0 {
		sb.WriteString("\n<b>计数</b>\n")
		for _, k := range []string{"connect", "blocked", "dial_fail", "auth_fail", "v6_fastfail"} {
			if v, ok := st.Counters[k]; ok {
				fmt.Fprintf(&sb, "%s：%d\n", counterName(k), v)
			}
		}
	}
	b.send(ctx, chatID, sb.String(), inlineKeyboard([]btn{{"⬅️ 返回", "menu"}}))
}

func (b *Bot) showEgress(ctx context.Context, chatID int64) {
	st := b.Manager.Status(b.Version)
	var sb strings.Builder
	sb.WriteString("<b>📤 出口管理</b>\n\n")

	var rows [][]btn
	for _, e := range st.Egress {
		mark := "　"
		if e.Current {
			mark = "✅"
		}
		fmt.Fprintf(&sb, "%s <b>%s</b>  <i>%s</i>\n", mark, html.EscapeString(e.Name), e.Type)

		row := []btn{{"切到 " + e.Name, "switch:" + e.Name}}
		if e.Name != "DIRECT" && !e.Current {
			row = append(row, btn{"🗑 删除", "del_egress:" + e.Name})
		}
		rows = append(rows, row)
	}
	sb.WriteString("\n<i>✅ 表示当前默认出口</i>")

	rows = append(rows, []btn{{"➕ 添加出口", "ask_egress_add"}})
	rows = append(rows, []btn{{"⬅️ 返回", "menu"}})
	b.send(ctx, chatID, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showRules(ctx context.Context, chatID int64) {
	rules := b.Manager.Rules()
	var sb strings.Builder
	sb.WriteString("<b>📑 分流规则</b>\n\n")
	if len(rules) == 0 {
		sb.WriteString("<i>暂无规则</i>\n")
	}
	var rows [][]btn
	for i, r := range rules {
		if i >= 20 {
			fmt.Fprintf(&sb, "\n<i>… 另有 %d 条未显示</i>\n", len(rules)-20)
			break
		}
		fmt.Fprintf(&sb, "%d. <code>%s</code>\n", i+1, html.EscapeString(r))
		if i < 8 {
			rows = append(rows, []btn{{fmt.Sprintf("🗑 删除第 %d 条", i+1), fmt.Sprintf("del_rule:%d", i)}})
		}
	}
	sb.WriteString("\n<i>规则按顺序匹配，命中即停止</i>")
	rows = append(rows, []btn{{"➕ 添加规则", "ask_rule_add"}})
	rows = append(rows, []btn{{"⬅️ 返回", "menu"}})
	b.send(ctx, chatID, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showClient(ctx context.Context, chatID int64) {
	var sb strings.Builder
	sb.WriteString("<b>📱 客户端接入</b>\n\n")
	sb.WriteString("选择你的设备类型：\n\n")
	sb.WriteString("<b>iPhone / iPad</b>（iOS 17 及以上）\n")
	sb.WriteString("直接下发描述文件，点开即可安装。\n\n")
	sb.WriteString("<b>Android</b>\n")
	sb.WriteString("只需在系统「私人 DNS」中填一个域名，无需安装应用。")

	b.send(ctx, chatID, sb.String(), inlineKeyboard(
		[]btn{{"🍎 获取 iOS 描述文件", "ios_profile"}},
		[]btn{{"🤖 Android 接入方法", "android_guide"}},
		[]btn{{"⬅️ 返回", "menu"}},
	))
}

// ---------- 流量 ----------

func (b *Bot) showTraffic(ctx context.Context, chatID int64) {
	sum, ok := b.Manager.TrafficSummary()
	if !ok {
		b.send(ctx, chatID, "流量统计未启用。", inlineKeyboard([]btn{{"⬅️ 返回", "menu"}}))
		return
	}

	var sb strings.Builder
	sb.WriteString("<b>📈 流量使用</b>\n\n")

	line := func(name string, d stats.Day) {
		fmt.Fprintf(&sb, "<b>%s</b>  %s\n", name, stats.HumanBytes(d.Total()))
		fmt.Fprintf(&sb, "  ↑ %s   ↓ %s\n",
			stats.HumanBytes(d.Up), stats.HumanBytes(d.Down))
		fmt.Fprintf(&sb, "  连接 %d（直连 %d / 代理 %d）\n\n",
			d.Conns, d.DirectConns, d.ProxyConns)
	}
	line("今日", sum.Today)
	line("近 7 天", sum.Days7)
	line("近 30 天", sum.Days30)

	if len(sum.TopDomain) > 0 {
		sb.WriteString("<b>流量最高的站点</b>\n")
		for i, t := range sum.TopDomain {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code>  %s\n",
				i+1, html.EscapeString(t.Host), stats.HumanBytes(t.Bytes))
		}
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "<i>统计自 %s 起，仅保留聚合数据，不记录访问明细</i>",
		html.EscapeString(sum.Since))

	b.send(ctx, chatID, sb.String(), inlineKeyboard(
		[]btn{{"🔄 刷新", "traffic"}},
		[]btn{{"⬅️ 返回", "menu"}},
	))
}

// ---------- 更新 ----------

func (b *Bot) showUpdate(ctx context.Context, chatID int64) {
	var sb strings.Builder
	sb.WriteString("<b>🔄 版本管理</b>\n\n")
	fmt.Fprintf(&sb, "当前版本：<code>%s</code>\n\n", html.EscapeString(b.Version))
	sb.WriteString("检查更新会向 GitHub 查询最新发布版本。\n")
	sb.WriteString("升级会校验 SHA256 后替换二进制并重启；\n")
	sb.WriteString("若新版本启动失败，会自动回退到当前版本。")

	rows := [][]btn{{{"🔍 检查更新", "update_check"}}}
	if len(b.Manager.RollbackVersions()) > 0 {
		rows = append(rows, []btn{{"⏮ 回退版本", "update_rollback"}})
	}
	rows = append(rows, []btn{{"⬅️ 返回", "menu"}})
	b.send(ctx, chatID, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) doUpdateCheck(ctx context.Context, chatID int64) {
	b.send(ctx, chatID, "正在查询最新版本…", "")
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	has, rel, err := b.Manager.CheckUpdate(cctx)
	if err != nil {
		b.send(ctx, chatID, "查询失败："+html.EscapeString(err.Error()),
			inlineKeyboard([]btn{{"⬅️ 返回", "update"}}))
		return
	}
	if !has {
		b.send(ctx, chatID,
			fmt.Sprintf("已是最新版本 <code>%s</code>", html.EscapeString(b.Version)),
			inlineKeyboard([]btn{{"⬅️ 返回", "update"}}))
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>发现新版本 %s</b>\n\n", html.EscapeString(rel.Tag))
	fmt.Fprintf(&sb, "当前：<code>%s</code>\n", html.EscapeString(b.Version))
	if !rel.Published.IsZero() {
		fmt.Fprintf(&sb, "发布：%s\n", rel.Published.Format("2006-01-02 15:04"))
	}
	if notes := truncateText(rel.Notes, 1200); notes != "" {
		fmt.Fprintf(&sb, "\n<b>更新内容</b>\n<pre>%s</pre>", html.EscapeString(notes))
	}
	b.send(ctx, chatID, sb.String(), inlineKeyboard(
		[]btn{{"⬆️ 立即升级 " + rel.Tag, "update_apply:" + rel.Tag}},
		[]btn{{"⬅️ 返回", "update"}},
	))
}

func (b *Bot) doUpdateApply(ctx context.Context, chatID int64, tag string) {
	b.send(ctx, chatID,
		fmt.Sprintf("正在升级到 <code>%s</code>…\n升级期间服务会短暂重启。",
			html.EscapeString(tag)), "")

	// 升级会重启本进程，用独立 context 避免被取消
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	msg, err := b.Manager.ApplyUpdate(cctx, tag)
	if err != nil {
		b.send(ctx, chatID, "升级失败："+html.EscapeString(err.Error()),
			inlineKeyboard([]btn{{"⬅️ 返回", "update"}}))
		return
	}
	b.send(ctx, chatID, "✅ "+html.EscapeString(msg), "")
}

func (b *Bot) showRollback(ctx context.Context, chatID int64) {
	vs := b.Manager.RollbackVersions()
	if len(vs) == 0 {
		b.send(ctx, chatID, "没有可回退的版本备份。",
			inlineKeyboard([]btn{{"⬅️ 返回", "update"}}))
		return
	}
	var rows [][]btn
	for i, v := range vs {
		if i >= 6 {
			break
		}
		rows = append(rows, []btn{{"⏮ 回退到 " + v, "rollback:" + v}})
	}
	rows = append(rows, []btn{{"⬅️ 返回", "update"}})
	b.send(ctx, chatID,
		"<b>⏮ 回退版本</b>\n\n选择要回退到的版本。回退后会自动重启并验证服务状态。",
		inlineKeyboard(rows...))
}

func (b *Bot) doRollback(ctx context.Context, chatID int64, tag string) {
	b.send(ctx, chatID, "正在回退到 <code>"+html.EscapeString(tag)+"</code>…", "")
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	msg, err := b.Manager.Rollback(cctx, tag)
	if err != nil {
		b.send(ctx, chatID, "回退失败："+html.EscapeString(err.Error()),
			inlineKeyboard([]btn{{"⬅️ 返回", "update"}}))
		return
	}
	b.send(ctx, chatID, "✅ "+html.EscapeString(msg), "")
}

// ---------- 客户端文件下发 ----------

// sendProfile 直接把描述文件作为文档发给管理员。
//
// 相比让用户去 Safari 打开一个长链接，直接发文件更省事：
// iOS 上点开 Telegram 里的 .mobileconfig 即可跳转安装。
func (b *Bot) sendProfile(ctx context.Context, chatID int64) {
	if b.Manager.ProfileBytes == nil {
		b.send(ctx, chatID, "描述文件生成器未就绪。", "")
		return
	}
	data, err := b.Manager.ProfileBytes()
	if err != nil {
		b.send(ctx, chatID, "生成失败："+html.EscapeString(err.Error()), "")
		return
	}
	caption := "<b>iOS 描述文件</b>\n\n" +
		"1. 点击上方文件，选择「下载」\n" +
		"2. 打开 设置 → 通用 → VPN 与设备管理\n" +
		"3. 安装「5gpn-NEXT」描述文件\n\n" +
		"⚠️ 安装前请先删除同名的旧描述文件。"
	if err := b.sendDocument(ctx, chatID, "5gpn-next.mobileconfig", data, caption); err != nil {
		b.send(ctx, chatID, "发送失败："+html.EscapeString(err.Error()), "")
	}
}

func (b *Bot) showAndroid(ctx context.Context, chatID int64) {
	var sb strings.Builder
	sb.WriteString("<b>Android 接入</b>\n\n")

	var g manage.AndroidGuide
	if b.Manager.AndroidInfo != nil {
		g = b.Manager.AndroidInfo()
	}
	if !g.Enabled {
		sb.WriteString("当前未启用 Android 支持。\n\n")
		sb.WriteString("启用方法：编辑服务器上的 <code>/etc/5gpn-next/config.json</code>，\n")
		sb.WriteString("把 <code>android.enabled</code> 改为 <code>true</code> 并填写 <code>android.gateway_ip</code>，\n")
		sb.WriteString("然后执行 <code>systemctl restart 5gpn-next</code>。")
		b.send(ctx, chatID, sb.String(), inlineKeyboard([]btn{{"⬅️ 返回", "client"}}))
		return
	}

	sb.WriteString("在手机上操作：\n\n")
	sb.WriteString("设置 → 网络和互联网 → <b>私人 DNS</b>\n")
	sb.WriteString("选择「指定的私人 DNS 服务提供商主机名」，填入：\n\n")
	fmt.Fprintf(&sb, "<code>%s</code>\n\n", html.EscapeString(g.DoTHost))
	sb.WriteString("保存后即可生效，无需安装任何应用。\n\n")
	if g.Note != "" {
		fmt.Fprintf(&sb, "<i>%s</i>", html.EscapeString(g.Note))
	}
	b.send(ctx, chatID, sb.String(), inlineKeyboard([]btn{{"⬅️ 返回", "client"}}))
}

// sendDocument 以 multipart 上传文件。
func (b *Bot) sendDocument(ctx context.Context, chatID int64, filename string, data []byte, caption string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	_ = mw.WriteField("caption", caption)
	_ = mw.WriteField("parse_mode", "HTML")
	fw, err := mw.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", b.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &r)
	if !r.OK {
		return fmt.Errorf("telegram: %s", r.Description)
	}
	return nil
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n…（内容过长已截断）"
}

// ---------- 键盘 ----------

type btn struct {
	Text string
	Data string
}

func inlineKeyboard(rows ...[]btn) string {
	type ib struct {
		Text string `json:"text"`
		Data string `json:"callback_data"`
	}
	out := make([][]ib, 0, len(rows))
	for _, r := range rows {
		row := make([]ib, 0, len(r))
		for _, b := range r {
			row = append(row, ib{Text: b.Text, Data: b.Data})
		}
		out = append(out, row)
	}
	kb, _ := json.Marshal(map[string]any{"inline_keyboard": out})
	return string(kb)
}

func counterName(k string) string {
	switch k {
	case "connect":
		return "连接总数"
	case "blocked":
		return "已拦截"
	case "dial_fail":
		return "拨号失败"
	case "auth_fail":
		return "鉴权失败"
	case "v6_fastfail":
		return "IPv6 快速回落"
	}
	return k
}
