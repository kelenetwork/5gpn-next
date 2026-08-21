// Package web 提供内网 Web 管理面板。
//
// 安全边界：面板只对内网卡来源开放 —— 应用层校验来源网段，
// 外层再叠加 nftables 限制。公网无法连接，因此不设登录，
// 手机连着内网卡打开域名即达。
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/manage"
)

//go:embed assets/*
var assets embed.FS

// Panel 是 Web 面板。
type Panel struct {
	Manager *manage.Manager
	Version string

	// AllowFrom 限定可访问的来源网段；为空时不做应用层限制
	// （仍受 nftables 约束，但双重防护更稳妥）。
	AllowFrom []netip.Prefix

	tmpl *template.Template
}

// New 构造面板。
func New(m *manage.Manager, version string, allowCIDRs []string) (*Panel, error) {
	p := &Panel{Manager: m, Version: version}
	for _, c := range allowCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("面板放行网段 %q 无效: %w", c, err)
		}
		p.AllowFrom = append(p.AllowFrom, pfx.Masked())
	}
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		return nil, err
	}
	t, err := template.New("index").Parse(string(b))
	if err != nil {
		return nil, err
	}
	p.tmpl = t
	return p, nil
}

// Handler 返回挂载在根路径的处理器。
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", p.guard(p.handleIndex))
	mux.HandleFunc("/style.css", p.serveAsset("assets/style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/app.js", p.serveAsset("assets/app.js", "application/javascript; charset=utf-8"))

	// 兼容旧地址：/panel 一律跳回根
	mux.HandleFunc("/panel", p.redirectRoot)
	mux.HandleFunc("/panel/", p.redirectRoot)

	// API
	mux.HandleFunc("/api/status", p.apiGuard(p.apiStatus))
	mux.HandleFunc("/api/adblock", p.apiGuard(p.apiAdBlock))
	mux.HandleFunc("/api/rules", p.apiGuard(p.apiRules))
	mux.HandleFunc("/api/egress", p.apiGuard(p.apiEgress))
	mux.HandleFunc("/api/probe", p.apiGuard(p.apiProbe))

	return mux
}

func (p *Panel) redirectRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

// ---------- 访问控制 ----------

// sourceAllowed 校验来源网段。
func (p *Panel) sourceAllowed(r *http.Request) bool {
	if len(p.AllowFrom) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	for _, pfx := range p.AllowFrom {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// guard 包装页面处理器：校验来源网段。
func (p *Panel) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.sourceAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// apiGuard 包装 API 处理器。
func (p *Panel) apiGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.sourceAllowed(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "来源不允许"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// 面板没有账号体系，网络来源是第一道认证；浏览器写请求还必须
			// 同源并使用 JSON，阻止用户访问恶意网页时被跨站静默改出口/规则。
			if !sameOriginWrite(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "拒绝跨站写请求"})
				return
			}
			if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "写请求必须使用 application/json"})
				return
			}
		}
		next(w, r)
	}
}

func sameOriginWrite(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// 非浏览器运维客户端通常不带 Origin；JSON Content-Type 仍是硬门槛。
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ---------- 页面 ----------

func (p *Panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = p.tmpl.Execute(w, map[string]any{"Version": p.Version})
}

func (p *Panel) serveAsset(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.sourceAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		b, err := assets.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(b)
	}
}

// ---------- API ----------

func (p *Panel) apiStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, p.Manager.Status(p.Version))
}

func (p *Panel) apiAdBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "方法不支持"})
		return
	}
	var body struct {
		Action  string `json:"action"` // toggle | allow | remove_allow
		Enabled bool   `json:"enabled"`
		Domain  string `json:"domain"`
		Index   int    `json:"index"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}

	var msg string
	var err error
	switch body.Action {
	case "toggle":
		ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
		msg, err = p.Manager.SetAdBlock(ctx, body.Enabled)
		cancel()
	case "allow":
		err = p.Manager.AllowAd(body.Domain)
		if err == nil {
			msg = "已加入广告白名单：" + strings.TrimSpace(body.Domain)
		}
	case "remove_allow":
		err = p.Manager.RemoveAdAllow(body.Index)
		if err == nil {
			msg = "白名单已更新"
		}
	default:
		err = fmt.Errorf("未知操作")
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": msg,
		"status":  p.Manager.Status(p.Version),
	})
}

func (p *Panel) apiRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"rules": p.Manager.Rules(),
			// DoH 阻断紧随私网保护，展示顺序与实际编译顺序一致。
			"builtin_pre": append(config.BuiltinPre(), config.BuiltinDoHBlock()...),
			// Google 下载修复排在国内直连兜底之前。
			"builtin_post": append(config.BuiltinGoogleFix(), config.BuiltinPost()...),
		})

	case http.MethodPost:
		var body struct {
			Rule string `json:"rule"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		if err := p.Manager.AddRule(body.Rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": p.Manager.Rules()})

	case http.MethodDelete:
		idx, err := strconv.Atoi(r.URL.Query().Get("index"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "序号无效"})
			return
		}
		if err := p.Manager.RemoveRule(idx); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": p.Manager.Rules()})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "方法不支持"})
	}
}

func (p *Panel) apiEgress(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Action string `json:"action"` // add | switch | remove | test
			Name   string `json:"name"`
			Link   string `json:"link"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		var err error
		var msg string
		switch body.Action {
		case "add":
			msg, err = p.Manager.AddEgress(body.Name, body.Link)
		case "switch":
			err = p.Manager.SwitchEgress(body.Name)
			msg = "国外默认出口已切换到 " + body.Name
		case "remove":
			err = p.Manager.RemoveEgress(body.Name)
			msg = "已删除 " + body.Name
		case "test":
			var d time.Duration
			d, err = p.Manager.TestEgress(body.Name)
			if err == nil {
				msg = fmt.Sprintf("出口 %s 连通，端到端耗时 %dms", body.Name, d.Milliseconds())
			}
		default:
			err = fmt.Errorf("未知操作")
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message": msg,
			"status":  p.Manager.Status(p.Version),
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "方法不支持"})
	}
}

func (p *Panel) apiProbe(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 target"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tr := p.Manager.Probe(ctx, target)
	writeJSON(w, http.StatusOK, map[string]any{
		"target": target,
		"ok":     tr.OK(),
		"total":  tr.TotalMS(),
		"steps":  tr.Steps(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
