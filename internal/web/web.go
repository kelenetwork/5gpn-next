// Package web 提供内网 Web 管理面板。
//
// 安全边界：只在内网卡来源可达（由 nftables 限制），并要求令牌登录。
// 公网无法连接，令牌仅存于服务端配置与浏览器 Cookie。
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/manage"
)

//go:embed assets/*
var assets embed.FS

// Panel 是 Web 面板。
type Panel struct {
	Manager *manage.Manager
	Token   string
	Version string

	// AllowFrom 限定可访问的来源网段；为空时不做应用层限制
	// （仍受 nftables 约束，但双重防护更稳妥）。
	AllowFrom []netip.Prefix

	tmpl *template.Template
}

// New 构造面板。
func New(m *manage.Manager, token, version string, allowCIDRs []string) (*Panel, error) {
	p := &Panel{Manager: m, Token: token, Version: version}
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

// Handler 返回挂载在 /panel 前缀下的处理器。
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/panel", p.guard(p.handleIndex))
	mux.HandleFunc("/panel/", p.guard(p.handleIndex))
	mux.HandleFunc("/panel/login", p.handleLogin)
	mux.HandleFunc("/panel/logout", p.handleLogout)
	mux.HandleFunc("/panel/style.css", p.serveAsset("assets/style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/panel/app.js", p.serveAsset("assets/app.js", "application/javascript; charset=utf-8"))

	// API
	mux.HandleFunc("/panel/api/status", p.apiGuard(p.apiStatus))
	mux.HandleFunc("/panel/api/rules", p.apiGuard(p.apiRules))
	mux.HandleFunc("/panel/api/egress", p.apiGuard(p.apiEgress))
	mux.HandleFunc("/panel/api/probe", p.apiGuard(p.apiProbe))

	return mux
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

func (p *Panel) authed(r *http.Request) bool {
	if p.Token == "" {
		return true
	}
	c, err := r.Cookie("fgpn_token")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(p.Token)) == 1
}

// guard 包装页面处理器：先查来源，再查登录。
func (p *Panel) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.sourceAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !p.authed(r) {
			p.renderLogin(w, "")
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
		if !p.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		next(w, r)
	}
}

// ---------- 页面 ----------

func (p *Panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = p.tmpl.Execute(w, map[string]any{"Version": p.Version})
}

func (p *Panel) renderLogin(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	esc := template.HTMLEscapeString(msg)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>5gpn-NEXT 登录</title><link rel="stylesheet" href="/panel/style.css"></head>
<body class="login-body"><form class="login" method="POST" action="/panel/login">
<h1>5gpn-NEXT</h1><p class="sub">管理面板</p>
%s<label>访问令牌</label>
<input type="password" name="token" autocomplete="current-password" autofocus required>
<button type="submit">登录</button>
<p class="hint">令牌见服务器 /etc/5gpn-next/config.json 的 panel.token</p>
</form></body></html>`,
		func() string {
			if esc == "" {
				return ""
			}
			return `<p class="err">` + esc + `</p>`
		}())
}

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !p.sourceAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/panel", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	if subtle.ConstantTimeCompare([]byte(r.FormValue("token")), []byte(p.Token)) != 1 {
		// 轻微延时，降低暴力尝试速率
		time.Sleep(500 * time.Millisecond)
		p.renderLogin(w, "令牌不正确")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "fgpn_token",
		Value:    p.Token,
		Path:     "/panel",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 3600,
	})
	http.Redirect(w, r, "/panel", http.StatusSeeOther)
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "fgpn_token", Value: "", Path: "/panel",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	http.Redirect(w, r, "/panel", http.StatusSeeOther)
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

func (p *Panel) apiRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"rules": p.Manager.Rules()})

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
			Action string `json:"action"` // add | switch | remove
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
			msg = "已切换到 " + body.Name
		case "remove":
			err = p.Manager.RemoveEgress(body.Name)
			msg = "已删除 " + body.Name
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
