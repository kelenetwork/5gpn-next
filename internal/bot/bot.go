// Package bot 实现 Telegram 管理机器人（纯标准库，长轮询）。
//
// 交互原则：
//   - 点击按钮就地更新原消息，不堆叠新消息；只有发送文件、执行结果这类
//     确实需要留痕的动作才新发一条。
//   - 只接受配置中列出的管理员 ID；其它来源静默忽略，不回任何内容。
//   - 一律使用 HTML parse_mode。域名与节点名常含 - _ . 等字符，
//     MarkdownV2 需逐字符转义，漏一个即整条发送失败。
package bot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/manage"
	"github.com/kelenetwork/5gpn-next/internal/qrcode"
	"github.com/kelenetwork/5gpn-next/internal/stats"
)

// Bot 是 Telegram 管理机器人。
type Bot struct {
	Token   string
	Admins  []int64
	Manager *manage.Manager
	Version string

	// PanelURL 是内网面板地址，供菜单展示
	PanelURL string

	client *http.Client
	offset int64

	mu sync.Mutex
	// pending 记录等待用户输入的动作：chatID -> action
	pending map[int64]string
	// promptMsg 记录发出提示的消息 ID，便于输入后就地更新
	promptMsg map[int64]int64
	// greeted 标记已经打过招呼的管理员，避免重复补发欢迎语
	greeted map[int64]bool
	// pendingGreet 为 true 时表示启动通知没送达，等用户首次交互再补
	pendingGreet bool
}

// offsetFile 持久化长轮询 offset。
//
// 升级/回退会重启本进程；若 offset 只存内存，Telegram 会把
// 尚未确认的「立即升级」回调重投给新进程，形成升级→重启→再升级
// 的死循环。落盘后重启不再重放已处理的更新。
const offsetFile = "/var/lib/5gpn-next/bot-offset"

// New 构造 Bot。
func New(token string, admins []int64, m *manage.Manager, version string) *Bot {
	b := &Bot{
		Token:     token,
		Admins:    admins,
		Manager:   m,
		Version:   version,
		client:    &http.Client{Timeout: 70 * time.Second},
		pending:   make(map[int64]string),
		promptMsg: make(map[int64]int64),
		greeted:   make(map[int64]bool),
	}
	if raw, err := os.ReadFile(offsetFile); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && n > 0 {
			b.offset = n
		}
	}
	return b
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
	advanced := false
	for _, u := range ups {
		if u.UpdateID >= b.offset {
			b.offset = u.UpdateID + 1
			advanced = true
		}
	}
	// 在处理任何更新之前先落盘：即便处理过程中进程被重启
	//（典型：自升级），这批更新也不会被 Telegram 重投。
	if advanced {
		_ = os.MkdirAll("/var/lib/5gpn-next", 0o750)
		_ = os.WriteFile(offsetFile, []byte(strconv.FormatInt(b.offset, 10)+"\n"), 0o640)
	}
	return ups, nil
}

// view 描述一屏内容。
type view struct {
	chatID int64
	// msgID 非 0 时就地编辑该消息，否则新发一条
	msgID int64
}

// render 渲染一屏：能编辑就编辑，避免消息越堆越多。
func (b *Bot) render(ctx context.Context, v view, text, keyboard string) int64 {
	if v.msgID != 0 {
		p := url.Values{}
		p.Set("chat_id", strconv.FormatInt(v.chatID, 10))
		p.Set("message_id", strconv.FormatInt(v.msgID, 10))
		p.Set("text", text)
		p.Set("parse_mode", "HTML")
		p.Set("disable_web_page_preview", "true")
		if keyboard != "" {
			p.Set("reply_markup", keyboard)
		}
		if _, err := b.api(ctx, "editMessageText", p); err == nil {
			return v.msgID
		}
		// 编辑失败（内容未变、消息过旧等）时退回新发，不让用户卡住
	}
	return b.send(ctx, v.chatID, text, keyboard)
}

// send 新发一条消息，返回消息 ID。
func (b *Bot) send(ctx context.Context, chatID int64, text, keyboard string) int64 {
	p := url.Values{}
	p.Set("chat_id", strconv.FormatInt(chatID, 10))
	p.Set("text", text)
	p.Set("parse_mode", "HTML")
	p.Set("disable_web_page_preview", "true")
	if keyboard != "" {
		p.Set("reply_markup", keyboard)
	}
	raw, err := b.api(ctx, "sendMessage", p)
	if err != nil {
		log.Printf("Bot 发送失败: %v", err)
		return 0
	}
	var r struct {
		MessageID int64 `json:"message_id"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.MessageID
}

// toast 在按钮上方弹出轻提示，不产生新消息。
func (b *Bot) toast(ctx context.Context, id, text string, alert bool) {
	p := url.Values{}
	p.Set("callback_query_id", id)
	if text != "" {
		p.Set("text", text)
	}
	if alert {
		p.Set("show_alert", "true")
	}
	_, _ = b.api(ctx, "answerCallbackQuery", p)
}

// Notify 主动推送给所有管理员。
//
// 若全部投递失败（常见于 Bot 刚创建、用户尚未 /start），
// 标记待补发，等用户首次交互时再送出。
func (b *Bot) Notify(ctx context.Context, text string) {
	delivered := false
	for _, id := range b.Admins {
		if b.send(ctx, id, text, "") != 0 {
			delivered = true
		}
	}
	if !delivered {
		b.mu.Lock()
		b.pendingGreet = true
		b.mu.Unlock()
		log.Printf("Bot 启动通知未送达（管理员可能尚未与 Bot 对话），将在首次交互时补发")
	}
}

// ---------- 交互 ----------

func (b *Bot) isAdmin(id int64) bool {
	for _, a := range b.Admins {
		if subtle.ConstantTimeCompare(
			[]byte(strconv.FormatInt(a, 10)),
			[]byte(strconv.FormatInt(id, 10))) == 1 {
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
		b.toast(ctx, q.ID, "", false)
		b.dispatch(ctx, view{chatID: q.Message.Chat.ID, msgID: q.Message.MessageID}, q.Data)

	case u.Message != nil:
		m := u.Message
		if !b.isAdmin(m.From.ID) {
			return // 静默忽略陌生人
		}
		text := strings.TrimSpace(m.Text)
		if text == "" {
			return
		}

		b.maybeGreet(ctx, m.Chat.ID)

		// 等待输入状态优先
		b.mu.Lock()
		action, waiting := b.pending[m.Chat.ID]
		promptID := b.promptMsg[m.Chat.ID]
		if waiting {
			delete(b.pending, m.Chat.ID)
			delete(b.promptMsg, m.Chat.ID)
		}
		b.mu.Unlock()

		if waiting && !strings.HasPrefix(text, "/") {
			b.handleInput(ctx, view{chatID: m.Chat.ID, msgID: promptID}, action, text)
			return
		}
		// 用户主动发命令：新开一屏
		b.dispatch(ctx, view{chatID: m.Chat.ID}, strings.TrimPrefix(text, "/"))
	}
}

// maybeGreet 在首次交互时补发启动通知。
//
// Bot 刚创建时用户往往还没 /start，此时服务端无法主动发消息
// （Telegram 限制：Bot 不能向未开启会话的用户发起对话）。
func (b *Bot) maybeGreet(ctx context.Context, chatID int64) {
	b.mu.Lock()
	need := b.pendingGreet && !b.greeted[chatID]
	if need {
		b.greeted[chatID] = true
	}
	b.mu.Unlock()
	if !need {
		return
	}
	b.send(ctx, chatID, fmt.Sprintf(
		"✅ <b>5gpn-NEXT 已就绪</b>\n\n"+
			"版本  <code>%s</code>\n"+
			"服务已在运行，随时可以开始配置。",
		html.EscapeString(b.Version)), "")
}

func (b *Bot) dispatch(ctx context.Context, v view, cmd string) {
	switch {
	case cmd == "start", cmd == "menu":
		b.showMenu(ctx, v)
	case cmd == "status":
		b.showStatus(ctx, v)
	case cmd == "traffic":
		b.showTraffic(ctx, v)
	case cmd == "egress":
		b.showEgress(ctx, v)
	case cmd == "health":
		b.showHealth(ctx, v)
	case strings.HasPrefix(cmd, "health_detail:"):
		b.showHealthDetail(ctx, v, strings.TrimPrefix(cmd, "health_detail:"))
	case cmd == "rules":
		b.showRules(ctx, v)
	case cmd == "adblock":
		b.showAdBlock(ctx, v)
	case cmd == "adblock_on":
		b.doAdBlockToggle(ctx, v, true)
	case cmd == "adblock_off":
		b.doAdBlockToggle(ctx, v, false)
	case cmd == "ask_ad_allow":
		b.ask(ctx, v, "ad_allow",
			"➕ <b>添加广告白名单</b>\n\n"+
				"某个 App 被误杀（白屏、加载不出来）时，把它的域名加进来。\n\n"+
				"直接发域名即可，例如：<code>example.com</code>\n"+
				"会连同子域名一起放行。")
	case cmd == "ad_allow_list":
		b.showAdAllowlist(ctx, v)
	case strings.HasPrefix(cmd, "ad_allow_del:"):
		if idx, err := strconv.Atoi(strings.TrimPrefix(cmd, "ad_allow_del:")); err == nil {
			if err := b.Manager.RemoveAdAllow(idx); err != nil {
				b.render(ctx, v, errBox("移除失败", err), backTo("ad_allow_list"))
				return
			}
		}
		b.showAdAllowlist(ctx, v)
	case cmd == "client":
		b.showClient(ctx, v)
	case cmd == "panel":
		b.showPanel(ctx, v)
	case cmd == "update":
		b.showUpdate(ctx, v)
	case cmd == "cancel":
		b.mu.Lock()
		delete(b.pending, v.chatID)
		delete(b.promptMsg, v.chatID)
		b.mu.Unlock()
		b.showMenu(ctx, v)

	case cmd == "ask_egress_add":
		b.ask(ctx, v, "egress_add",
			"➕ <b>添加出口</b>\n\n"+
				"请粘贴节点分享链接。\n\n"+
				"支持：<code>ss</code> <code>vless</code> <code>vmess</code> "+
				"<code>trojan</code> <code>hysteria2</code> <code>tuic</code> "+
				"<code>socks5</code> <code>http</code>")
	case cmd == "ask_rule_add":
		b.askRuleAdd(ctx, v)
	case cmd == "ask_probe":
		b.ask(ctx, v, "probe",
			"🩺 <b>连通性诊断</b>\n\n"+
				"请输入要检测的域名，例如 <code>youtube.com</code>\n\n"+
				"将逐层检查入口、策略、出口、连接与应用层。")

	case cmd == "ios_dns_profile":
		b.sendDNSProfile(ctx, v)
	case cmd == "android_guide":
		b.showAndroid(ctx, v)
	case cmd == "update_check":
		b.doUpdateCheck(ctx, v)
	case strings.HasPrefix(cmd, "update_ignore:"):
		if err := b.Manager.IgnoreVersion(strings.TrimPrefix(cmd, "update_ignore:")); err != nil {
			b.render(ctx, v, errBox("忽略失败", err), backTo("update"))
			return
		}
		b.showUpdate(ctx, v)
	case strings.HasPrefix(cmd, "update_unignore:"):
		if err := b.Manager.UnignoreVersion(strings.TrimPrefix(cmd, "update_unignore:")); err != nil {
			b.render(ctx, v, errBox("操作失败", err), backTo("update"))
			return
		}
		b.showUpdate(ctx, v)
	case cmd == "update_clear_ignored":
		for _, t := range b.Manager.IgnoredVersions() {
			_ = b.Manager.UnignoreVersion(t)
		}
		b.showUpdate(ctx, v)
	case cmd == "update_toggle_auto":
		_, cur, _ := b.Manager.UpdateSettings()
		if err := b.Manager.SetUpdateAutoApply(!cur); err != nil {
			b.render(ctx, v, errBox("设置失败", err), backTo("update"))
			return
		}
		b.showUpdate(ctx, v)
	case strings.HasPrefix(cmd, "update_apply:"):
		b.doUpdateApply(ctx, v, strings.TrimPrefix(cmd, "update_apply:"))
	case cmd == "update_backups":
		b.showUpdateBackups(ctx, v)
	case cmd == "update_history":
		b.showUpdateHistory(ctx, v)
	case cmd == "ask_update_interval":
		b.ask(ctx, v, "update_interval",
			"⏱ <b>调整检查间隔</b>\n\n"+
				"请输入小时数（1-168），例如 <code>1</code> 或 <code>6</code>。\n\n"+
				"<i>改动保存后，下次重启起完全生效。</i>")
	case cmd == "monitor_settings":
		b.showMonitorSettings(ctx, v)
	case cmd == "monitor_toggle_alerts":
		_, _, disabled := b.Manager.MonitorSettings()
		newVal := !disabled
		if err := b.Manager.SetMonitorAlerts(0, 0, &newVal); err != nil {
			b.render(ctx, v, errBox("设置失败", err), backTo("monitor_settings"))
			return
		}
		b.showMonitorSettings(ctx, v)
	case cmd == "ask_monitor_after":
		b.ask(ctx, v, "monitor_after",
			"🚨 <b>连续失败阈值</b>\n\n"+
				"出口连续多少次探测失败才告警？请输入次数（1-60）。\n\n"+
				"<i>每次探测间隔 60 秒；3 表示约 3 分钟无响应才提醒。</i>")
	case cmd == "ask_monitor_cooldown":
		b.ask(ctx, v, "monitor_cooldown",
			"🔕 <b>告警冷却</b>\n\n"+
				"同一出口两次告警之间至少间隔多少分钟？请输入分钟数（1-1440）。")
	case cmd == "update_rollback":
		b.showRollback(ctx, v)
	case strings.HasPrefix(cmd, "rollback:"):
		b.doRollback(ctx, v, strings.TrimPrefix(cmd, "rollback:"))

	case strings.HasPrefix(cmd, "test_egress:"):
		b.doTestEgress(ctx, v, strings.TrimPrefix(cmd, "test_egress:"))

	case strings.HasPrefix(cmd, "switch:"):
		name := strings.TrimPrefix(cmd, "switch:")
		if err := b.Manager.SwitchEgress(name); err != nil {
			b.render(ctx, v, errBox("切换失败", err), backTo("egress"))
			return
		}
		b.showEgress(ctx, v)

	case strings.HasPrefix(cmd, "del_egress:"):
		name := strings.TrimPrefix(cmd, "del_egress:")
		if err := b.Manager.RemoveEgress(name); err != nil {
			b.render(ctx, v, errBox("删除失败", err), backTo("egress"))
			return
		}
		b.showEgress(ctx, v)

	case cmd == "rule_del_menu":
		b.showRuleDelMenu(ctx, v)
	case strings.HasPrefix(cmd, "rule_del_ask:"):
		if idx, err := strconv.Atoi(strings.TrimPrefix(cmd, "rule_del_ask:")); err == nil {
			b.askRuleDelete(ctx, v, idx)
			return
		}
		b.showRules(ctx, v)
	case strings.HasPrefix(cmd, "rule_del_do:"):
		b.doRuleDelete(ctx, v, strings.TrimPrefix(cmd, "rule_del_do:"))

	default:
		b.showMenu(ctx, v)
	}
}

func (b *Bot) ask(ctx context.Context, v view, action, prompt string) {
	id := b.render(ctx, v, prompt+"\n\n<i>直接发送内容即可，或点下方取消。</i>",
		inlineKeyboard([]btn{{"取消", "cancel"}}))
	b.mu.Lock()
	b.pending[v.chatID] = action
	b.promptMsg[v.chatID] = id
	b.mu.Unlock()
}

func (b *Bot) handleInput(ctx context.Context, v view, action, text string) {
	switch action {
	case "egress_add":
		msg, err := b.Manager.AddEgress("", text)
		if err != nil {
			b.render(ctx, v, errBox("添加失败", err), backTo("egress"))
			return
		}
		b.render(ctx, v, "✅ <b>已添加出口</b>\n\n"+html.EscapeString(msg),
			inlineKeyboard([]btn{{"🌐 查看出口", "egress"}}, []btn{{"« 返回主菜单", "menu"}}))

	case "rule_add":
		if err := b.Manager.AddRule(text); err != nil {
			b.render(ctx, v, errBox("添加失败", err), backTo("rules"))
			return
		}
		b.showRules(ctx, v)

	case "ad_allow":
		if err := b.Manager.AllowAd(text); err != nil {
			b.render(ctx, v, errBox("添加失败", err), backTo("adblock"))
			return
		}
		b.showAdBlock(ctx, v)

	case "update_interval":
		hours, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			b.render(ctx, v, errBox("输入无效", fmt.Errorf("请输入 1-168 的整数")), backTo("update"))
			return
		}
		if err := b.Manager.SetUpdateInterval(hours); err != nil {
			b.render(ctx, v, errBox("设置失败", err), backTo("update"))
			return
		}
		b.showUpdate(ctx, v)

	case "monitor_after":
		n, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			b.render(ctx, v, errBox("输入无效", fmt.Errorf("请输入 1-60 的整数")), backTo("monitor_settings"))
			return
		}
		if err := b.Manager.SetMonitorAlerts(n, 0, nil); err != nil {
			b.render(ctx, v, errBox("设置失败", err), backTo("monitor_settings"))
			return
		}
		b.showMonitorSettings(ctx, v)

	case "monitor_cooldown":
		n, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			b.render(ctx, v, errBox("输入无效", fmt.Errorf("请输入 1-1440 的整数")), backTo("monitor_settings"))
			return
		}
		if err := b.Manager.SetMonitorAlerts(0, n, nil); err != nil {
			b.render(ctx, v, errBox("设置失败", err), backTo("monitor_settings"))
			return
		}
		b.showMonitorSettings(ctx, v)

	case "probe":
		target := strings.TrimSpace(text)
		b.render(ctx, v, "🩺 正在诊断 <code>"+html.EscapeString(target)+"</code> …", "")
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		tr := b.Manager.Probe(cctx, target)

		verdict := "✅ 连通正常"
		if !tr.OK() {
			verdict = "❌ 存在故障"
		}
		body := fmt.Sprintf("🩺 <b>诊断结果</b> · %s\n<code>%s</code>\n\n<pre>%s</pre>",
			verdict, html.EscapeString(target), html.EscapeString(tr.Human()))
		b.render(ctx, v, body, inlineKeyboard(
			[]btn{{"🔁 再测一次", "ask_probe"}},
			[]btn{{"« 返回主菜单", "menu"}},
		))
	}
}

// ---------- 视图 ----------

func (b *Bot) showMenu(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)

	cur := "本机直出"
	for _, e := range st.Egress {
		if e.Current {
			cur = e.Name
			break
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>5gpn-NEXT</b> · <i>网关管理控制台</i>\n", em("🤖"))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(&sb, "%s 运行 <b>%s</b> · 版本 <code>%s</code>\n", em("🔋"), st.Uptime, st.Version)
	fmt.Fprintf(&sb, "%s 当前出口 <b>%s</b>\n", em("🌏"), html.EscapeString(cur))
	fmt.Fprintf(&sb, "%s 分流规则 <b>%d</b> 条\n", em("🧭"), st.Rules)

	// 升级横幅：缓存里有未忽略的新版本时，在主菜单直接提示。
	newTag := b.Manager.UpdateBanner()
	if newTag != "" {
		fmt.Fprintf(&sb, "\n%s <b>新版本 %s 可用</b> · 点下方按钮一键升级\n", em("🚀"), html.EscapeString(newTag))
	}
	sb.WriteString("\n<i>请选择要执行的操作 ↓</i>")

	rows := [][]btn{}
	if newTag != "" {
		rows = append(rows, []btn{{"🚀 升级到 " + newTag, "update_apply:" + newTag}})
	}
	rows = append(rows,
		[]btn{{"📊 运行状态", "status"}, {"📈 网关转发流量", "traffic"}},
		[]btn{{"🌐 出口管理", "egress"}, {"🧭 分流规则", "rules"}},
		[]btn{{"🛡 广告拦截", "adblock"}, {"🩺 连通诊断", "ask_probe"}},
		[]btn{{"💓 健康监控", "health"}},
		[]btn{{"📱 客户端接入", "client"}, {"🖥 内网面板", "panel"}},
		[]btn{{"🚀 版本更新", "update"}},
	)
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showStatus(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)

	var sb strings.Builder
	sb.WriteString("📊 <b>运行状态</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(&sb, "🏷 版本　<code>%s</code>\n", st.Version)
	fmt.Fprintf(&sb, "⏱ 运行　<b>%s</b>\n", st.Uptime)
	fmt.Fprintf(&sb, "📡 监听　<code>%s</code>\n", html.EscapeString(st.Listen))
	fmt.Fprintf(&sb, "💾 内存　<b>%.1f MB</b>\n", st.MemoryMB)
	fmt.Fprintf(&sb, "📋 规则　<b>%d</b> 条\n", st.Rules)
	if st.DomesticReady {
		sb.WriteString("🇨🇳 国内　<b>直连规则已就绪</b>\n")
	} else {
		sb.WriteString("⚠️ 国内　<b>规则未就绪，国外出口已安全回落 KFC 本机出口</b>\n")
	}
	if st.CertUntil != "" {
		fmt.Fprintf(&sb, "🔐 证书　%s\n", html.EscapeString(st.CertUntil))
	}

	if len(st.Counters) > 0 {
		sb.WriteString("\n<b>连接计数</b>\n<blockquote>")
		first := true
		for _, k := range []string{"connect", "blocked", "dial_fail", "auth_fail", "v6_fastfail"} {
			if val, ok := st.Counters[k]; ok {
				if !first {
					sb.WriteString("\n")
				}
				first = false
				fmt.Fprintf(&sb, "%s　<b>%d</b>", counterName(k), val)
			}
		}
		sb.WriteString("</blockquote>")
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🔄 刷新", "status"}},
		[]btn{{"« 返回主菜单", "menu"}},
	))
}

func (b *Bot) showTraffic(ctx context.Context, v view) {
	sum, ok := b.Manager.TrafficSummary()
	if !ok {
		b.render(ctx, v, "📈 <b>网关转发流量</b>\n\n统计功能未启用。", backTo("menu"))
		return
	}

	var sb strings.Builder
	sb.WriteString("📈 <b>网关转发流量</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("<i>这里只统计经过 5gpn-NEXT 服务器的数据，不是手机总流量。</i>\n\n")
	row := func(icon, name string, d stats.Day) {
		fmt.Fprintf(&sb, "%s <b>%s</b>　<b>%s</b>\n", icon, name, stats.HumanBytes(d.Total()))
		fmt.Fprintf(&sb, "<blockquote>↑ %s　↓ %s\n%d 连接 · 网关直出 %d / 代理出口 %d",
			stats.HumanBytes(d.Up), stats.HumanBytes(d.Down),
			d.Conns, d.DirectConns, d.ProxyConns)
		if d.Blocked > 0 {
			fmt.Fprintf(&sb, " / 拦截 %d", d.Blocked)
		}
		// v0.13.9 及更早版本把 QUIC/失败写成未识别 action；历史聚合
		// 无法可靠反推直连或代理，只透明展示差额，不伪造分类。
		unclassified := d.Conns - d.DirectConns - d.ProxyConns - d.Blocked
		if unclassified > 0 {
			fmt.Fprintf(&sb, " / 旧版未分类 %d", unclassified)
		}
		if d.Failed > 0 {
			fmt.Fprintf(&sb, "\n其中失败 %d", d.Failed)
		}
		sb.WriteString("</blockquote>\n")
	}
	row("📅", "今日", sum.Today)
	row("🗓", "近 7 天", sum.Days7)
	row("📆", "近 30 天", sum.Days30)

	if len(sum.TopDomain) > 0 {
		sb.WriteString("\n🔝 <b>网关累计流量最高的站点</b>\n<blockquote expandable>")
		for i, t := range sum.TopDomain {
			if i >= 8 {
				break
			}
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code> · %s", i+1,
				html.EscapeString(truncateText(t.Host, 30)), stats.HumanBytes(t.Bytes))
		}
		sb.WriteString("</blockquote>")
	}
	fmt.Fprintf(&sb, "\n<i>按北京时间自然日统计；国内网站等手机本地直连流量不在其中。统计自 %s 起，流量统计本身仅保留聚合数据。</i>",
		html.EscapeString(sum.Since))

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🔄 刷新", "traffic"}},
		[]btn{{"« 返回主菜单", "menu"}},
	))
}

func (b *Bot) showEgress(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)

	var sb strings.Builder
	sb.WriteString("🌐 <b>国外默认出口</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString("<i>只决定国外未命中流量：KFC 本机出口表示使用 KFC 公网 IP；国内常用域名由描述文件在手机侧直连，其余域名解析 IP 后由 GEOIP 兜底。自定义规则始终优先。</i>\n\n")
	if !st.DomesticReady {
		sb.WriteString("⚠️ <b>国内直连规则尚未就绪</b>\n<blockquote>为防止退化成国内外全局代理，当前运行态已安全回落 KFC 本机出口；切换代理出口时会先刷新规则。</blockquote>\n")
	}

	var rows [][]btn
	for _, e := range st.Egress {
		mark := "○"
		if e.Current {
			mark = "●"
		}
		disp := e.Display
		if disp == "" {
			disp = e.Name
		}
		fmt.Fprintf(&sb, "%s <b>%s</b>  <i>%s</i>\n", mark, html.EscapeString(disp), e.Type)
		if e.Server != "" {
			fmt.Fprintf(&sb, "   <code>%s</code>\n", html.EscapeString(e.Server))
		}

		short := truncateText(disp, 12)
		row := []btn{{"🧪 测 " + short, "test_egress:" + e.Name}}
		if !e.Current {
			row = append([]btn{{"国外走 " + short, "switch:" + e.Name}}, row...)
		}
		if e.Name != "DIRECT" {
			row = append(row, btn{"🗑", "del_egress:" + e.Name})
		}
		rows = append(rows, row)
	}
	sb.WriteString("\n<i>● 仅表示国外兜底出口。删除当前出口会自动回落 KFC 本机出口。</i>")

	rows = append(rows, []btn{{"➕ 添加出口", "ask_egress_add"}})
	rows = append(rows, []btn{{"« 返回主菜单", "menu"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// doTestEgress 端到端测试出口连通性。
func (b *Bot) doTestEgress(ctx context.Context, v view, name string) {
	b.render(ctx, v, "🧪 正在测试出口 <code>"+html.EscapeString(name)+"</code> …\n\n<i>经该出口真实访问外网并校验响应。</i>", "")
	d, err := b.Manager.TestEgress(name)
	if err != nil {
		b.render(ctx, v, fmt.Sprintf(
			"❌ <b>出口不通</b> · <code>%s</code>\n\n<code>%s</code>",
			html.EscapeString(name), html.EscapeString(err.Error())),
			inlineKeyboard(
				[]btn{{"🔁 再测一次", "test_egress:" + name}},
				[]btn{{"« 返回出口", "egress"}},
			))
		return
	}
	b.render(ctx, v, fmt.Sprintf(
		"✅ <b>出口连通</b> · <code>%s</code>\n\n端到端耗时 <b>%dms</b>",
		html.EscapeString(name), d.Milliseconds()),
		inlineKeyboard(
			[]btn{{"🔁 再测一次", "test_egress:" + name}},
			[]btn{{"« 返回出口", "egress"}},
		))
}

// showAdBlock 展示广告拦截状态与开关。
func (b *Bot) showAdBlock(ctx context.Context, v view) {
	st := b.Manager.Status(b.Version)
	ad := st.AdBlock

	var sb strings.Builder
	sb.WriteString("🛡 <b>广告拦截</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")

	if ad.Enabled {
		if ad.Domains > 0 {
			fmt.Fprintf(&sb, "状态　<b>已开启</b>\n规则　<b>%d</b> 条拦截域名\n", ad.Domains)
		} else {
			sb.WriteString("状态　<b>已开启</b>\n⚠️ 规则集尚未载入（下载中或下载失败）\n")
		}
	} else {
		sb.WriteString("状态　<b>已关闭</b>\n")
	}
	fmt.Fprintf(&sb, "白名单　<b>%d</b> 条\n", ad.Allowlist)
	fmt.Fprintf(&sb, "今日成功　<b>%d</b> 次\n累计成功　<b>%d</b> 次\n\n", ad.Hits.Today, ad.Hits.Total)

	if len(ad.Hits.Recent) > 0 {
		sb.WriteString("🕘 <b>最近成功命中</b>\n<blockquote>")
		for i, ev := range ad.Hits.Recent {
			if i >= 5 {
				break
			}
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "<code>%s</code> · %s", html.EscapeString(ev.Host), time.Unix(ev.At, 0).Format("01-02 15:04"))
		}
		sb.WriteString("</blockquote>\n\n")
	}
	if len(ad.Hits.Top) > 0 {
		sb.WriteString("🔥 <b>高频拦截</b>\n<blockquote>")
		for i, item := range ad.Hits.Top {
			if i >= 5 {
				break
			}
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code> · %d 次", i+1, html.EscapeString(item.Host), item.Count)
		}
		sb.WriteString("</blockquote>\n\n")
	}

	sb.WriteString("<blockquote>在加密 DNS 入口返回 NXDOMAIN，全设备生效、无需安装 App。\n")
	sb.WriteString("“成功”仅在响应已经写回手机后计数；不记录客户端 IP 或正常访问明细。</blockquote>\n\n")
	sb.WriteString("<i>若某 App 白屏/加载不出，把其域名加入白名单即可救急。</i>")

	rows := [][]btn{}
	if ad.Enabled {
		rows = append(rows, []btn{{"🔴 关闭拦截", "adblock_off"}})
	} else {
		rows = append(rows, []btn{{"🟢 开启拦截", "adblock_on"}})
	}
	rows = append(rows,
		[]btn{{"➕ 加白名单", "ask_ad_allow"}, {"📋 白名单", "ad_allow_list"}},
		[]btn{{"« 返回主菜单", "menu"}},
	)
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// doAdBlockToggle 切换广告拦截。首次开启需下载约 2MB 规则集。
func (b *Bot) doAdBlockToggle(ctx context.Context, v view, on bool) {
	if on {
		b.render(ctx, v, "🛡 正在开启广告拦截…\n\n<i>首次需下载规则集（约 2MB / 10 万条），请稍候。</i>", "")
	}
	cctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	msg, err := b.Manager.SetAdBlock(cctx, on)
	cancel()
	if err != nil {
		b.render(ctx, v, errBox("操作失败", err), backTo("adblock"))
		return
	}
	b.render(ctx, v, "✅ "+html.EscapeString(msg), inlineKeyboard(
		[]btn{{"🛡 返回广告拦截", "adblock"}},
		[]btn{{"« 返回主菜单", "menu"}},
	))
}

// showAdAllowlist 列出白名单，每条一个删除按钮。
func (b *Bot) showAdAllowlist(ctx context.Context, v view) {
	list := b.Manager.AdAllowlist()

	var sb strings.Builder
	sb.WriteString("📋 <b>广告白名单</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	if len(list) == 0 {
		sb.WriteString("<blockquote>暂无白名单。\n某个 App 被误杀时，把它的域名加进来即可放行。</blockquote>")
	} else {
		sb.WriteString("<blockquote>")
		for i, d := range list {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code>", i+1, html.EscapeString(d))
		}
		sb.WriteString("</blockquote>")
	}

	rows := [][]btn{}
	for i, d := range list {
		if i >= 10 {
			break
		}
		rows = append(rows, []btn{{"🗑 " + truncateText(d, 24), fmt.Sprintf("ad_allow_del:%d", i)}})
	}
	rows = append(rows,
		[]btn{{"➕ 加白名单", "ask_ad_allow"}},
		[]btn{{"« 返回广告拦截", "adblock"}},
	)
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showRules(ctx context.Context, v view) {
	rules := b.Manager.Rules()

	var sb strings.Builder
	sb.WriteString("🧭 <b>分流规则</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString("<i>匹配顺序：内置保护 → 自定义规则 → 内置兜底，命中即停止。</i>\n\n")

	sb.WriteString("✏️ <b>自定义规则</b>\n")
	if len(rules) == 0 {
		sb.WriteString("<blockquote>暂无。国内直连、国外走出口已由内置规则完成，\n通常只在个别域名需要特殊处理时才添加。</blockquote>\n")
	} else {
		sb.WriteString("<blockquote>")
		for i, r := range rules {
			if i >= 20 {
				fmt.Fprintf(&sb, "\n… 另有 %d 条未显示", len(rules)-20)
				break
			}
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "%d. <code>%s</code>", i+1, html.EscapeString(r))
		}
		sb.WriteString("</blockquote>\n")
	}

	sb.WriteString("\n🔒 <b>内置规则</b>　<i>不可修改</i>\n")
	sb.WriteString("<blockquote expandable>优先于自定义（私网保护 + DoH 绕过阻断）：\n")
	for _, r := range config.BuiltinPre() {
		fmt.Fprintf(&sb, "<code>%s</code>\n", html.EscapeString(r))
	}
	for _, r := range config.BuiltinDoHBlock() {
		fmt.Fprintf(&sb, "<code>%s</code>\n", html.EscapeString(r))
	}
	sb.WriteString("\n自定义之后（Google 下载修复，跟随默认国外出口）：\n")
	for _, r := range config.BuiltinGoogleFix() {
		fmt.Fprintf(&sb, "<code>%s</code>\n", html.EscapeString(r))
	}
	sb.WriteString("\n最后兜底（国内直连）：\n")
	for i, r := range config.BuiltinPost() {
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "<code>%s</code>", html.EscapeString(r))
	}
	sb.WriteString("</blockquote>")

	var rows [][]btn
	rows = append(rows, []btn{{"➕ 添加规则", "ask_rule_add"}})
	if len(rules) > 0 {
		rows = append(rows, []btn{{"🗑 删除规则", "rule_del_menu"}})
	}
	rows = append(rows, []btn{{"« 返回主菜单", "menu"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// askRuleAdd 提示添加规则，动态列出可用出口名，支持分流到不同出口。
func (b *Bot) askRuleAdd(ctx context.Context, v view) {
	var sb strings.Builder
	sb.WriteString("➕ <b>添加分流规则</b>\n\n")
	sb.WriteString("格式：<code>类型,值,动作</code>\n\n")
	sb.WriteString("<b>动作</b>：<code>direct</code>（KFC 本机公网直出）· ")
	sb.WriteString("<code>block</code>（拦截）· <code>proxy:出口名</code>\n\n")

	names := b.Manager.SortedEgressNames()
	var proxies []string
	for _, n := range names {
		if n != "DIRECT" {
			proxies = append(proxies, n)
		}
	}
	if len(proxies) > 0 {
		sb.WriteString("<b>可用出口</b>：")
		for i, n := range proxies {
			if i > 0 {
				sb.WriteString(" · ")
			}
			fmt.Fprintf(&sb, "<code>%s</code>", html.EscapeString(n))
		}
		sb.WriteString("\n\n")
		fmt.Fprintf(&sb, "示例：\n<code>DOMAIN-SUFFIX,openai.com,proxy:%s</code>\n", html.EscapeString(proxies[0]))
	} else {
		sb.WriteString("示例：\n<code>DOMAIN-SUFFIX,openai.com,proxy:出口名</code>\n")
	}
	sb.WriteString("<code>DOMAIN-SUFFIX,example.cn,direct</code>\n")
	sb.WriteString("<code>DOMAIN-KEYWORD,ads,block</code>\n\n")
	sb.WriteString("新规则会插入到最前面，优先匹配；不同域名可分流到不同出口。")

	b.ask(ctx, v, "rule_add", sb.String())
}

// showRuleDelMenu 列出可删除的自定义规则，每条一个按钮，按钮上带规则内容。
func (b *Bot) showRuleDelMenu(ctx context.Context, v view) {
	rules := b.Manager.Rules()
	if len(rules) == 0 {
		b.showRules(ctx, v)
		return
	}

	var sb strings.Builder
	sb.WriteString("🗑 <b>删除规则</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString("<i>点击要删除的规则，删除前会再确认一次。</i>\n\n<blockquote>")
	for i, r := range rules {
		if i >= 12 {
			fmt.Fprintf(&sb, "\n… 另有 %d 条，请在内网面板中操作", len(rules)-12)
			break
		}
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%d. <code>%s</code>", i+1, html.EscapeString(r))
	}
	sb.WriteString("</blockquote>")

	var rows [][]btn
	for i, r := range rules {
		if i >= 12 {
			break
		}
		rows = append(rows, []btn{{fmt.Sprintf("🗑 %d · %s", i+1, truncateText(ruleGist(r), 24)),
			fmt.Sprintf("rule_del_ask:%d", i)}})
	}
	rows = append(rows, []btn{{"« 返回规则", "rules"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// askRuleDelete 删除前确认，展示完整规则内容。
func (b *Bot) askRuleDelete(ctx context.Context, v view, idx int) {
	rules := b.Manager.Rules()
	if idx < 0 || idx >= len(rules) {
		b.showRules(ctx, v)
		return
	}
	body := fmt.Sprintf("⚠️ <b>确认删除这条规则？</b>\n\n<code>%s</code>\n\n<i>删除后立即生效。</i>",
		html.EscapeString(rules[idx]))
	b.render(ctx, v, body, inlineKeyboard(
		[]btn{{"🗑 确认删除", fmt.Sprintf("rule_del_do:%d:%s", idx, ruleFingerprint(rules[idx]))}},
		[]btn{{"« 取消", "rule_del_menu"}},
	))
}

// doRuleDelete 校验指纹后删除：规则列表在确认期间可能已变化，
// 指纹不匹配时拒绝，避免误删错位后的其它规则。
func (b *Bot) doRuleDelete(ctx context.Context, v view, arg string) {
	parts := strings.SplitN(arg, ":", 2)
	idx, err := strconv.Atoi(parts[0])
	if err != nil {
		b.showRules(ctx, v)
		return
	}
	rules := b.Manager.Rules()
	if idx < 0 || idx >= len(rules) ||
		len(parts) < 2 || ruleFingerprint(rules[idx]) != parts[1] {
		b.render(ctx, v, "⚠️ <b>规则列表已变化</b>\n\n为避免误删，本次操作已取消，请重新选择。",
			backTo("rules"))
		return
	}
	if err := b.Manager.RemoveRule(idx); err != nil {
		b.render(ctx, v, errBox("删除失败", err), backTo("rules"))
		return
	}
	b.showRules(ctx, v)
}

// ruleGist 取规则中最有辨识度的部分（值），供按钮标签使用。
func ruleGist(r string) string {
	parts := strings.Split(r, ",")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return r
}

// ruleFingerprint 生成规则内容短指纹，用于确认删除时校验列表未变化。
func ruleFingerprint(r string) string {
	sum := sha256.Sum256([]byte(r))
	return hex.EncodeToString(sum[:4])
}

func (b *Bot) showClient(ctx context.Context, v view) {
	var sb strings.Builder
	sb.WriteString("📱 <b>客户端接入</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString("🍎 <b>iPhone / iPad</b>　<i>iOS 17 及以上</i>\n")
	sb.WriteString("<blockquote>安装一张描述文件，仅<b>蜂窝数据</b>下生效；连 Wi-Fi 自动停用，家里网络完全不受影响。\n\n国内域名/IP 由 GEOIP 判定后<b>手机本地直连</b>，不经网关；只有国外流量才走出口。</blockquote>\n")
	sb.WriteString("🤖 <b>Android</b>\n")
	sb.WriteString("<blockquote>在系统「私人 DNS」中填一个域名即可，同样无需安装应用。</blockquote>")

	rows := [][]btn{}
	if b.Manager.DNSProfileBytes != nil {
		rows = append(rows, []btn{{"📱 获取 iOS 描述文件", "ios_dns_profile"}})
	}
	rows = append(rows,
		[]btn{{"🤖 Android 接入方法", "android_guide"}},
		[]btn{{"« 返回主菜单", "menu"}},
	)
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func (b *Bot) showPanel(ctx context.Context, v view) {
	var sb strings.Builder
	sb.WriteString("🖥 <b>内网 Web 面板</b>\n\n")

	if b.PanelURL == "" {
		sb.WriteString("面板未启用。\n\n")
		sb.WriteString("如需开启：编辑 <code>/etc/5gpn-next/config.json</code>，\n")
		sb.WriteString("把 <code>panel.enabled</code> 设为 <code>true</code>，\n")
		sb.WriteString("然后执行 <code>systemctl restart 5gpn-next</code>。")
		b.render(ctx, v, sb.String(), backTo("menu"))
		return
	}

	sb.WriteString("在浏览器中管理出口、分流与诊断：\n\n")
	fmt.Fprintf(&sb, "<code>%s</code>\n\n", html.EscapeString(b.PanelURL))
	sb.WriteString("📱 手机连着内网卡时<b>直接打开即可</b>，无需登录。\n")
	sb.WriteString("🔒 仅内网卡来源可访问，公网完全无法连接。")

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🖥 打开面板", "url:" + b.PanelURL}},
		[]btn{{"« 返回主菜单", "menu"}},
	))
}

func (b *Bot) showAndroid(ctx context.Context, v view) {
	var g manage.AndroidGuide
	if b.Manager.AndroidInfo != nil {
		g = b.Manager.AndroidInfo()
	}

	var sb strings.Builder
	sb.WriteString("🤖 <b>Android 接入</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")

	if !g.Enabled {
		sb.WriteString("当前未启用 Android 支持。\n\n")
		sb.WriteString("开启方法：编辑 <code>/etc/5gpn-next/config.json</code>，\n")
		sb.WriteString("把 <code>dns.enabled</code> 设为 <code>true</code>，\n")
		sb.WriteString("然后执行 <code>systemctl restart 5gpn-next</code>。")
		b.render(ctx, v, sb.String(), backTo("client"))
		return
	}

	sb.WriteString("在手机上依次打开：\n\n")
	sb.WriteString("<b>设置 → 网络和互联网 → 私人 DNS</b>\n\n")
	sb.WriteString("选择「指定的私人 DNS 服务提供商主机名」，填入：\n\n")
	fmt.Fprintf(&sb, "<code>%s</code>\n\n", html.EscapeString(g.DoTHost))
	sb.WriteString("✅ 保存后立即生效，无需安装任何应用。\n\n")
	if g.Note != "" {
		fmt.Fprintf(&sb, "<i>%s</i>", html.EscapeString(g.Note))
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"« 返回客户端", "client"}},
		[]btn{{"« 返回主菜单", "menu"}},
	))
}

// ---------- 更新 ----------

func (b *Bot) showUpdate(ctx context.Context, v view) {
	checkOn, autoApply, interval := b.Manager.UpdateSettings()
	ignored := b.Manager.IgnoredVersions()
	rel, checkedAt, hasCache := b.Manager.CachedUpdate()

	var sb strings.Builder
	sb.WriteString("🚀 <b>版本更新</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(&sb, "🏷 当前版本　<code>%s</code>\n", html.EscapeString(b.Version))
	if checkOn {
		fmt.Fprintf(&sb, "🔁 自动检查　<b>开</b> · 每 %d 小时\n", interval)
	} else {
		sb.WriteString("🔁 自动检查　<b>关</b>\n")
	}
	fmt.Fprintf(&sb, "🤖 自动安装　<b>%s</b>\n", onOff(autoApply))
	if len(ignored) > 0 {
		fmt.Fprintf(&sb, "🔕 已忽略　<code>%s</code>\n", html.EscapeString(strings.Join(ignored, ", ")))
	}

	// 最近一次检查结果（缓存，不打网络）。
	var newTag string
	sb.WriteString("\n")
	if hasCache && rel != nil {
		if b.Manager.UpdateBanner() != "" {
			newTag = rel.Tag
			fmt.Fprintf(&sb, "🟢 <b>有新版本 %s</b>\n", html.EscapeString(rel.Tag))
			if !rel.Published.IsZero() {
				fmt.Fprintf(&sb, "📅 发布　%s\n", rel.Published.Format("2006-01-02 15:04"))
			}
			if notes := truncateText(strings.TrimSpace(rel.Notes), 800); notes != "" {
				fmt.Fprintf(&sb, "\n📋 <b>更新内容</b>\n<blockquote expandable>%s</blockquote>\n", html.EscapeString(notes))
			}
		} else if b.Manager.IsIgnoredVersion(rel.Tag) && rel.Tag != b.Version {
			fmt.Fprintf(&sb, "🔕 最新 <code>%s</code> 已被忽略\n", html.EscapeString(rel.Tag))
		} else {
			sb.WriteString("✅ 已是最新版本\n")
		}
		fmt.Fprintf(&sb, "<i>上次检查 %s</i>\n", checkedAt.Local().Format("01-02 15:04"))
	} else {
		sb.WriteString("<i>尚未检查过，点「立即检查」拉取最新版本信息。</i>\n")
	}
	sb.WriteString("\n<i>升级会校验哈希后替换程序并重启；启动失败自动回退。</i>")

	var rows [][]btn
	if newTag != "" {
		rows = append(rows, []btn{{"🚀 立即更新到 " + newTag, "update_apply:" + newTag}})
		rows = append(rows, []btn{{"🔕 忽略 " + newTag, "update_ignore:" + newTag}})
	}
	rows = append(rows, []btn{{"🔄 立即检查", "update_check"}, {autoApplyLabel(autoApply), "update_toggle_auto"}})
	rows = append(rows, []btn{{fmt.Sprintf("⏱ 检查间隔：%d 小时", interval), "ask_update_interval"}})
	rows = append(rows, []btn{{"🗂 备份列表", "update_backups"}, {"📋 升级历史", "update_history"}})
	if len(ignored) > 0 {
		rows = append(rows, []btn{{fmt.Sprintf("🧹 清空忽略（%d）", len(ignored)), "update_clear_ignored"}})
	}
	if len(b.Manager.RollbackVersions()) > 0 {
		rows = append(rows, []btn{{"⏪ 回退到旧版本", "update_rollback"}})
	}
	rows = append(rows, []btn{{"« 返回主菜单", "menu"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

func onOff(v bool) string {
	if v {
		return "开"
	}
	return "关"
}

func autoApplyLabel(on bool) string {
	if on {
		return "🤖 自动安装：开"
	}
	return "🚦 自动安装：关"
}

func (b *Bot) doUpdateCheck(ctx context.Context, v view) {
	b.render(ctx, v, "🔍 正在查询最新版本 …", "")

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	has, rel, err := b.Manager.CheckUpdate(cctx)
	if err != nil {
		b.render(ctx, v, errBox("查询失败", err), backTo("update"))
		return
	}
	if !has {
		b.render(ctx, v, fmt.Sprintf(
			"✅ <b>已是最新版本</b>\n\n当前 <code>%s</code>", html.EscapeString(b.Version)),
			backTo("update"))
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "🆕 <b>发现新版本 %s</b>\n", html.EscapeString(rel.Tag))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	fmt.Fprintf(&sb, "🏷 当前　<code>%s</code>\n", html.EscapeString(b.Version))
	if !rel.Published.IsZero() {
		fmt.Fprintf(&sb, "📅 发布　%s\n", rel.Published.Format("2006-01-02 15:04"))
	}
	if notes := truncateText(strings.TrimSpace(rel.Notes), 1000); notes != "" {
		fmt.Fprintf(&sb, "\n📋 <b>更新内容</b>\n<blockquote expandable>%s</blockquote>", html.EscapeString(notes))
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"🚀 立即升级到 " + rel.Tag, "update_apply:" + rel.Tag}},
		[]btn{{"« 返回", "update"}},
	))
}

// updateStages 是升级阶段的展示顺序与文案。
var updateStages = []struct{ key, label string }{
	{"download", "⬇️ 下载新版本"},
	{"verify", "🔎 校验哈希"},
	{"backup", "📦 备份当前版本"},
	{"restart", "🔄 重启生效"},
}

// renderUpdateProgress 渲染升级进度清单：已完成 ✅、进行中 ⏳、未开始 ○。
func renderUpdateProgress(tag, current string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>正在升级到 %s</b>\n", em("🚀"), html.EscapeString(tag))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	reached := true
	for _, st := range updateStages {
		switch {
		case st.key == current:
			fmt.Fprintf(&sb, "⏳ %s <b>← 进行中</b>\n", st.label)
			reached = false
		case reached:
			fmt.Fprintf(&sb, "✅ %s\n", st.label)
		default:
			fmt.Fprintf(&sb, "○ %s\n", st.label)
		}
	}
	sb.WriteString("\n<i>重启后由独立事务健康检查，失败自动回退。</i>")
	return sb.String()
}

func (b *Bot) doUpdateApply(ctx context.Context, v view, tag string) {
	b.render(ctx, v, renderUpdateProgress(tag, "download"), "")

	// 阶段回调：每步刷新同一条消息。回调来自升级 goroutine，
	// 用独立短超时 context，绝不阻塞升级本身。
	b.Manager.SetUpdateStageHook(func(stage, _ string) {
		sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
		b.render(sctx, v, renderUpdateProgress(tag, stage), "")
		scancel()
	})
	defer b.Manager.SetUpdateStageHook(nil)

	// 升级会重启本进程，用独立 context 避免被取消
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	msg, err := b.Manager.ApplyUpdate(cctx, tag)
	if err != nil {
		b.render(ctx, v, errBox("升级失败", err), backTo("update"))
		return
	}
	b.render(ctx, v, fmt.Sprintf("%s <b>升级任务已启动</b>\n\n%s", em("✅"), html.EscapeString(msg)), backTo("menu"))
}

func (b *Bot) showRollback(ctx context.Context, v view) {
	vs := b.Manager.RollbackVersions()
	if len(vs) == 0 {
		b.render(ctx, v, "⏪ <b>回退版本</b>\n\n没有可用的版本备份。", backTo("update"))
		return
	}
	var rows [][]btn
	for i, ver := range vs {
		if i >= 6 {
			break
		}
		rows = append(rows, []btn{{"⏪ 回退到 " + ver, "rollback:" + ver}})
	}
	rows = append(rows, []btn{{"« 返回", "update"}})
	b.render(ctx, v,
		"⏪ <b>回退版本</b>\n\n<i>回退后会自动重启并验证服务状态。</i>",
		inlineKeyboard(rows...))
}

func (b *Bot) doRollback(ctx context.Context, v view, tag string) {
	b.render(ctx, v, "⏪ 正在回退到 <code>"+html.EscapeString(tag)+"</code> …", "")
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	msg, err := b.Manager.Rollback(cctx, tag)
	if err != nil {
		b.render(ctx, v, errBox("回退失败", err), backTo("update"))
		return
	}
	b.render(ctx, v, "✅ <b>回退任务已启动</b>\n\n"+html.EscapeString(msg), backTo("menu"))
}

// ---------- 描述文件 ----------

// sendDNSProfile 下发「蜂窝 DNS 模式」描述文件。
func (b *Bot) sendDNSProfile(ctx context.Context, v view) {
	if b.Manager.DNSProfileBytes == nil {
		b.render(ctx, v, "<b>获取失败</b>\n\n蜂窝 DNS 模式需要启用 dns.enabled（DoT 入口）。", backTo("client"))
		return
	}
	data, err := b.Manager.DNSProfileBytes()
	if err != nil {
		b.render(ctx, v, errBox("生成失败", err), backTo("client"))
		return
	}

	profileURL := b.Manager.ProfileDownloadURL()
	sentQR := false
	if profileURL != "" {
		if png, qerr := qrcode.EncodePNG(profileURL); qerr != nil {
			log.Printf("Bot 生成描述文件二维码失败: %v", qerr)
		} else {
			qrCaption := "<b>iOS 蜂窝 DNS 描述文件</b>\n\n" +
				"<b>方式一：扫码安装</b>\n" +
				"1. 如已安装旧版 5gpn 描述文件，请先删除\n" +
				"2. 手机走<b>内网卡蜂窝数据</b>，用相机或 Safari 扫码\n" +
				"3. 打开 设置 → 通用 → VPN 与设备管理并安装\n\n" +
				"<b>方式二：点击下方文件下载</b>\n\n" +
				"链接：<code>" + html.EscapeString(profileURL) + "</code>\n\n" +
				"<i>✅ 仅蜂窝数据生效，Wi-Fi 完全不受影响；国内 IP 手机本地直连。\n" +
				"⚠️ 链接含随机串，请勿外传；仅内网卡来源可访问。</i>"
			if err := b.sendPhoto(ctx, v.chatID, "5gpn-next-dns.png", png, qrCaption); err != nil {
				log.Printf("Bot 发送描述文件二维码失败: %v", err)
			} else {
				sentQR = true
			}
		}
	}

	docCaption := "<b>iOS 蜂窝 DNS 描述文件</b>\n\n" +
		"1. 如已安装旧版 5gpn 描述文件，请先删除\n" +
		"2. 点击上方文件并选择下载\n" +
		"3. 打开 设置 → 通用 → VPN 与设备管理并安装\n\n" +
		"<i>✅ 仅蜂窝数据生效，Wi-Fi 完全不受影响；国内 IP 手机本地直连。\n" +
		"⚠️ 加密 DNS 无法识别少数无 SNI 私有协议，这是当前方案的明确边界。</i>"
	if sentQR {
		docCaption = "<b>描述文件</b>\n\n也可直接点开这个文件下载安装。"
	}

	if err := b.sendDocument(ctx, v.chatID, "5gpn-next-dns.mobileconfig", data, docCaption); err != nil {
		b.render(ctx, v, errBox("发送失败", err), backTo("client"))
		return
	}
	done := "<b>客户端接入</b>\n\n蜂窝 DNS 描述文件已发送，请查看上方文件。"
	if sentQR {
		done = "<b>客户端接入</b>\n\n二维码与描述文件都已发送。\n扫码或点开文件都可以安装。"
	}
	b.render(ctx, v, done,
		inlineKeyboard(
			[]btn{{"重新获取", "ios_dns_profile"}},
			[]btn{{"返回主菜单", "menu"}},
		))
}

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

func (b *Bot) sendPhoto(ctx context.Context, chatID int64, filename string, data []byte, caption string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	_ = mw.WriteField("caption", caption)
	_ = mw.WriteField("parse_mode", "HTML")
	fw, err := mw.CreateFormFile("photo", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendPhoto", b.Token)
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

// ---------- 键盘与排版 ----------

type btn struct {
	Text string
	Data string
}

// inlineKeyboard 渲染 inline 键盘。
//
// Data 以 "url:" 开头时渲染为链接按钮，其余为回调按钮。
func inlineKeyboard(rows ...[]btn) string {
	type ib struct {
		Text string `json:"text"`
		Data string `json:"callback_data,omitempty"`
		URL  string `json:"url,omitempty"`
	}
	out := make([][]ib, 0, len(rows))
	for _, r := range rows {
		row := make([]ib, 0, len(r))
		for _, e := range r {
			if strings.HasPrefix(e.Data, "url:") {
				row = append(row, ib{Text: e.Text, URL: strings.TrimPrefix(e.Data, "url:")})
				continue
			}
			row = append(row, ib{Text: e.Text, Data: e.Data})
		}
		out = append(out, row)
	}
	kb, _ := json.Marshal(map[string]any{"inline_keyboard": out})
	return string(kb)
}

func backTo(target string) string {
	if target == "menu" {
		return inlineKeyboard([]btn{{"返回主菜单", "menu"}})
	}
	return inlineKeyboard([]btn{{"返回", target}}, []btn{{"返回主菜单", "menu"}})
}

func errBox(title string, err error) string {
	return fmt.Sprintf("<b>%s</b>\n\n<code>%s</code>",
		html.EscapeString(title), html.EscapeString(err.Error()))
}

// pad 按显示宽度右侧补空格，中日韩字符按两格计算。
func pad(s string, width int) string {
	w := 0
	for _, r := range s {
		if r > 0x2E80 {
			w += 2
		} else {
			w++
		}
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
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
		return "IPv6 回落"
	}
	return k
}

// showUpdateBackups 展示可回退版本详情（学 Parrot 的备份列表）。
func (b *Bot) showUpdateBackups(ctx context.Context, v view) {
	backups := b.Manager.UpdateBackups()

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>本地版本备份</b>\n", em("♻️"))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	if len(backups) == 0 {
		sb.WriteString("暂无备份。首次升级时会自动保留当前版本。\n")
	} else {
		sb.WriteString("<i>升级时自动保留的历史二进制，可随时回退：</i>\n<blockquote>")
		for i, bk := range backups {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "💾 <code>%s</code>　%.1f MB", html.EscapeString(bk.Tag), bk.SizeMB)
			if !bk.ModTime.IsZero() {
				fmt.Fprintf(&sb, "　%s", bk.ModTime.Local().Format("01-02 15:04"))
			}
		}
		sb.WriteString("</blockquote>\n")
	}

	rows := [][]btn{}
	if len(backups) > 0 {
		rows = append(rows, []btn{{"⏪ 回退到旧版本", "update_rollback"}})
	}
	rows = append(rows, []btn{{"« 返回版本更新", "update"}})
	b.render(ctx, v, sb.String(), inlineKeyboard(rows...))
}

// showUpdateHistory 展示历次升级结果（学 Parrot 的更新日志）。
func (b *Bot) showUpdateHistory(ctx context.Context, v view) {
	hist := b.Manager.UpdateHistory(10)

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>升级历史</b>\n", em("📊"))
	sb.WriteString("━━━━━━━━━━━━━━━━━━\n\n")
	if len(hist) == 0 {
		sb.WriteString("暂无记录。升级完成后（无论成败）都会在这里留档。\n")
	} else {
		sb.WriteString("<blockquote>")
		for i, r := range hist {
			if i > 0 {
				sb.WriteString("\n")
			}
			icon := "❓"
			label := r.Status
			switch r.Status {
			case "success":
				icon, label = "✅", "成功"
			case "rolled_back":
				icon, label = "↩️", "已回退"
			case "install_failed":
				icon, label = "❌", "安装失败"
			case "rollback_failed":
				icon, label = "🆘", "回退失败"
			}
			fmt.Fprintf(&sb, "%s %s → %s　%s　%s",
				icon,
				html.EscapeString(r.From), html.EscapeString(r.To),
				label,
				time.Unix(r.At, 0).Local().Format("01-02 15:04"))
		}
		sb.WriteString("</blockquote>\n")
	}

	b.render(ctx, v, sb.String(), inlineKeyboard(
		[]btn{{"« 返回版本更新", "update"}},
	))
}
