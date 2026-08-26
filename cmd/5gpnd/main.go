// 5gpnd 是 5gpn-NEXT 的网关守护进程与命令行工具。
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/bot"
	"github.com/kelenetwork/5gpn-next/internal/config"
	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/fw"
	"github.com/kelenetwork/5gpn-next/internal/ingress/dot"
	"github.com/kelenetwork/5gpn-next/internal/ingress/hint"
	"github.com/kelenetwork/5gpn-next/internal/ingress/quicfwd"
	"github.com/kelenetwork/5gpn-next/internal/ingress/sniff"
	"github.com/kelenetwork/5gpn-next/internal/manage"
	"github.com/kelenetwork/5gpn-next/internal/monitor"
	"github.com/kelenetwork/5gpn-next/internal/node"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/probe"
	"github.com/kelenetwork/5gpn-next/internal/profile"
	"github.com/kelenetwork/5gpn-next/internal/ruleset"
	"github.com/kelenetwork/5gpn-next/internal/stats"
	"github.com/kelenetwork/5gpn-next/internal/trace"
	"github.com/kelenetwork/5gpn-next/internal/update"
	"github.com/kelenetwork/5gpn-next/internal/web"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "probe":
		err = cmdProbe(args)
	case "profile":
		err = cmdProfile(args)
	case "node-config":
		err = cmdNodeConfig(args)
	case "check":
		err = cmdCheck(args)
	case "version", "-v", "--version":
		fmt.Printf("5gpn-next %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("错误: %v", err)
	}
}

func usage() {
	fmt.Print(`5gpn-NEXT — 手机免客户端的加密 DNS 分流网关

用法:
  5gpnd run     -c <配置文件>            启动网关
  5gpnd probe   -c <配置文件> <目标>      端到端诊断（逐层输出）
  5gpnd profile -c <配置文件> -o <输出>   生成 iOS 描述文件
  5gpnd check   -c <配置文件>            校验配置（不启动服务）
  5gpnd node-config -link <文件> -out <文件>  由分享链接生成 mihomo 出口配置
  5gpnd version

说明:
  probe 用于自助排障，会逐层打印 入口→策略→出口→连接→应用 的结果，
  失败时精确指出是哪一层，而不是笼统的"连不上"。
`)
}

// ---------- 公共装配 ----------

type app struct {
	cfg    *config.Config
	engine *policy.Engine
	reg    *egress.Registry
}

func setup(cfgPath string, loadRules bool) (*app, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	// prefer_ipv4：让所有出口对 IPv6 字面量目标 0ms 快速失败。
	//
	// 生产实测：经 mihomo 代拨的 IPv6 对 Meta 这类多 edge 服务往往只是
	// "部分可达"，坏 edge 每个都要等一个看门狗周期；而完全没有 IPv6 的
	// 出口反而更快（用户实测 KFC 明显快于 usatt）。默认开启。
	v6Allowed := !cfg.IPv4Preferred()

	reg := egress.NewRegistry()
	for _, e := range cfg.Egress {
		switch e.Type {
		case "direct":
			if e.Name != "DIRECT" {
				reg.Register(egress.NewDirect(e.Name))
			}
		case "socks5":
			reg.Register(egress.NewSocks5(e.Name, e.Addr, e.HasIPv6 && v6Allowed))
		}
	}
	if !v6Allowed {
		reg.SetDirectIPv6(false)
	}

	eng := policy.New()
	eng.SetEgressHasV6(reg.Direct().HasIPv6())

	if loadRules {
		if err := loadRuleSets(cfg, eng); err != nil {
			return nil, err
		}
	}
	if err := applyRules(cfg, eng); err != nil {
		return nil, err
	}
	return &app{cfg: cfg, engine: eng, reg: reg}, nil
}

func loadRuleSets(cfg *config.Config, eng *policy.Engine) error {
	cacheDir := "/var/lib/5gpn-next/rulesets"
	f := ruleset.NewFetcher(cacheDir)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	for _, rs := range cfg.EffectiveRuleSets() {
		src := rs.Path
		if src == "" {
			// 缓存优先：有缓存立即用，服务秒级起监听；
			// 联网刷新由后台任务完成，不阻塞启动。
			// 否则每次升级/重启都要现场下载几 MB 规则库，
			// 期间规则不完整，手机访问会出现错误分流。
			if p, ok := f.Cached(rs.Name); ok {
				src = p
			} else {
				p, err := f.Fetch(ctx, rs.Name, rs.URL)
				if err != nil {
					log.Printf("警告: 规则集 %s 载入失败: %v（该规则将不生效）", rs.Name, err)
					continue
				}
				src = p
			}
		}
		// 走带缓存的载入：规则集载入后只读，热重载时若文件未变即复用
		// 已解析对象。否则每次重建引擎都要重新解析 20 余万条规则（实测
		// 每套约 11.8MB），新旧引擎并存时内存翻倍，会撞破 cgroup 上限
		// 触发 OOM→重启→再 OOM 的死循环。
		switch rs.Kind {
		case "domain":
			ds, err := ruleset.LoadDomainFileCached(src)
			if err != nil {
				log.Printf("警告: 解析域名规则集 %s 失败: %v", rs.Name, err)
				continue
			}
			eng.RegisterDomainSet(rs.Name, ds)
			log.Printf("规则集 %s: %d 条域名", rs.Name, ds.Len())
		case "ipcidr":
			cs, err := ruleset.LoadCIDRFileCached(src)
			if err != nil {
				log.Printf("警告: 解析 CIDR 规则集 %s 失败: %v", rs.Name, err)
				continue
			}
			eng.RegisterCIDRSet(rs.Name, cs)
			log.Printf("规则集 %s: %d 条网段", rs.Name, cs.Len())
		default:
			return fmt.Errorf("规则集 %s 类型未知: %s", rs.Name, rs.Kind)
		}
	}
	return nil
}

// applyRules 把配置里的规则字符串编译进引擎。
//
// 规则格式: TYPE,VALUE,ACTION   例如 DOMAIN-SUFFIX,openai.com,proxy:us-1
func applyRules(cfg *config.Config, eng *policy.Engine) error {
	// 编译顺序：
	//   内置前置（私网保护）
	//   → 用户规则（最高优先，可覆盖广告拦截）
	//   → 广告拦截（白名单 direct 在前、RULE-SET block 在后）
	//   → Google 下载链路修复（必须在国内直连之前）
	//   → 内置兜底（国内直连）
	//
	// 广告规则必须排在国内直连之前：国内 App 的广告域名大多也在
	// cn-domain 名单里，若放到后面会先命中 direct 而完全拦不到。
	// Google 修复同理：dl.google.com / gvt1.com 等下载域名经国内 DNS
	// 可能解析到 Google 中国节点 IP（GEOIP=CN），若落到 GEOIP 兜底
	// 会让手机直连被墙节点，表现为 Play 能浏览、下载永远转圈。
	// 内置规则不在配置文件里，Bot/面板改不到也删不掉。
	finalAct, finalEg := parseAction(cfg.Final)
	googleFix := config.BuiltinGoogleFix()
	if finalAct == policy.ActionProxy && finalEg != "" {
		// 跟随当前默认国外出口；切换出口会触发热重载，这里随之更新。
		for i := range googleFix {
			googleFix[i] += ":" + finalEg
		}
	}
	// DoH 阻断紧随私网保护：Google Play 服务会用 dns.google 绕过
	// 系统 DNS 拿真实 IP 直连（蜂窝上必然黑洞），必须优先于一切
	// 用户规则，否则「Play 能浏览、下载等待中」会复发。
	all := append([]string(nil), config.BuiltinPre()...)
	all = append(all, config.BuiltinDoHBlock()...)
	all = append(all, cfg.Rules...)
	all = append(all, cfg.BuiltinAdBlock()...)
	all = append(all, googleFix...)
	all = append(all, config.BuiltinPost()...)
	for i, line := range all {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) < 3 {
			return fmt.Errorf("第 %d 条规则格式错误: %q", i+1, line)
		}
		kind := policy.RuleKind(strings.ToUpper(strings.TrimSpace(parts[0])))
		val := strings.TrimSpace(parts[1])
		act, eg := parseAction(strings.TrimSpace(parts[2]))

		if err := eng.AddRule(policy.Rule{
			Kind: kind, Value: val, Action: act, Egress: eg,
		}); err != nil {
			// 规则集缺失时降级跳过，不让整个网关起不来
			log.Printf("警告: 跳过第 %d 条规则 %q: %v", i+1, line, err)
		}
	}
	// 安全边界：选了代理出口但国内直连规则尚未就绪时，绝不能把
	// FINAL 直接放行到代理，否则会退化成“国内外全局代理”。
	// 启动期先在运行态回落 DIRECT；后台规则刷新成功后会热重载，
	// 恢复磁盘里原本选择的国外出口。
	if finalAct == policy.ActionProxy && !eng.DomesticRulesReady() {
		log.Printf("严重警告: 国内直连规则未完整载入，FINAL 运行态暂时回落 DIRECT，防止国内流量误走代理")
		finalAct, finalEg = policy.ActionDirect, ""
	}
	eng.SetFinal(finalAct, finalEg)
	return nil
}

func parseAction(s string) (policy.Action, string) {
	s = strings.TrimSpace(s)
	switch {
	case s == "direct":
		return policy.ActionDirect, ""
	case s == "block", s == "reject":
		return policy.ActionBlock, ""
	case s == "proxy":
		return policy.ActionProxy, ""
	case strings.HasPrefix(s, "proxy:"):
		return policy.ActionProxy, strings.TrimPrefix(s, "proxy:")
	}
	return policy.ActionProxy, s
}

// ---------- run ----------

func cmdRun(args []string) error {
	// 两项都必须在载入规则集之前生效：启动阶段就是内存峰值所在。
	// 先关 THP，再设 GOMEMLIMIT——前者消除内核侧放大，后者约束 Go 堆。
	disableTHP()
	applyCgroupMemoryLimit()

	cfgPath := flagValue(args, "-c", "/etc/5gpn-next/config.json")
	a, err := setup(cfgPath, true)
	if err != nil {
		return err
	}
	cleanupRetiredArtifacts(cfgPath)

	var rec *trace.JSONLRecorder
	if a.cfg.LogPath != "" {
		rec, err = trace.NewJSONLRecorder(
			a.cfg.LogPath, trace.DefaultMaxLogSize, trace.DefaultLogBackups)
		if err != nil {
			log.Printf("警告: 初始化有界 trace 日志失败（继续运行）: %v", err)
			rec = nil
		} else {
			defer rec.Close()
		}
	}

	// 蜂窝 DNS 描述文件：唯一的 iOS 接入方式。
	// 沿用配置里原有的随机下载路径，保证已有安装链接不失效。
	profilePath := a.cfg.Gateway.ProfilePath
	buildProfile := func() ([]byte, error) {
		o := profile.DefaultDNS(a.cfg.Gateway.Host)
		if a.cfg.DNS.GatewayIP != "" {
			o.ServerAddresses = []string{a.cfg.DNS.GatewayIP}
		}
		return o.Build()
	}
	var profBytes []byte
	if profilePath != "" && a.cfg.DNS.Enabled {
		profBytes, err = buildProfile()
		if err != nil {
			return fmt.Errorf("生成 iOS 描述文件失败: %w", err)
		}
	}
	if len(profBytes) == 0 {
		profilePath = ""
	}

	// 运行态：策略引擎与出口注册表，热重载时原子替换指针。
	rt := &gatewayRuntime{}
	rt.SetRuntime(a.engine, a.reg)
	dnsStats := &dnsCounters{}

	// 管理层：Bot 与 Web 面板共用同一套动作实现
	mgr := manage.New(cfgPath, a.cfg, a.engine, a.reg)

	// 健康监控：出口探测 + 真实转发埋点 + DoT 上游耗时。纯观测，
	// 任何采样失败都不影响数据面。
	health := monitor.New()
	health.Targets = func() []monitor.Target {
		var out []monitor.Target
		for _, e := range a.cfg.Egress {
			if e.Server != "" {
				out = append(out, monitor.Target{Name: e.Name, Addr: e.Server})
			}
		}
		return out
	}
	mgr.Health = health
	// 计数器分散在 sniff（连接级）与 DoT（查询级），用闭包延迟聚合。
	var sniffSrv *sniff.Server
	var quicSrv *quicfwd.Server
	snapshot := func() map[string]int64 {
		out := map[string]int64{
			"dns_query":  dnsStats.Query.Load(),
			"dns_direct": dnsStats.Direct.Load(),
			"dns_proxy":  dnsStats.Proxy.Load(),
			"dns_block":  dnsStats.Block.Load(),
		}
		if sniffSrv != nil {
			out["handled"] = sniffSrv.Handled.Load()
			out["dial_fail"] = sniffSrv.Failed.Load()
			out["no_host"] = sniffSrv.NoHost.Load()
			out["hinted"] = sniffSrv.Hinted.Load()
			out["denied_source"] = sniffSrv.Denied.Load()
		}
		if quicSrv != nil {
			out["quic_handled"] = quicSrv.Handled.Load()
			out["quic_fail"] = quicSrv.Failed.Load()
			out["quic_no_host"] = quicSrv.NoHost.Load()
		}
		return out
	}
	mgr.Stats = statsFunc(snapshot)
	// 流量统计只保留聚合数据；连接级 trace 是独立的有界诊断日志。
	traffic := stats.New("/var/lib/5gpn-next/traffic.json")
	mgr.Traffic = traffic
	trafficDone := make(chan struct{})
	trafficStopped := make(chan struct{})
	go func() {
		defer close(trafficStopped)
		traffic.RunFlusher(trafficDone, 10*time.Second)
	}()
	// 等最终一次原子落盘完成再退出，避免正常升级/重启损失最后一个周期。
	defer func() {
		close(trafficDone)
		<-trafficStopped
	}()

	// 版本管理。先清理旧版自更新因进程被 restart 杀掉而永久遗留的
	// staging，并限制可回退二进制数量；失败只告警，不影响数据面启动。
	if err := update.CleanupState(); err != nil {
		log.Printf("警告: %v", err)
	}
	updater := update.New(version)
	mgr.Updater = updater

	// 描述文件生成器：供 Bot 直接以文件形式下发
	if a.cfg.DNS.Enabled {
		mgr.DNSProfileBytes = buildProfile
	}
	mgr.AndroidInfo = func() manage.AndroidGuide {
		g := manage.AndroidGuide{
			Enabled:   a.cfg.DNS.Enabled,
			DoTHost:   a.cfg.Gateway.Host,
			GatewayIP: a.cfg.DNS.GatewayIP,
		}
		if g.Enabled {
			g.Note = "国内网站直连，国外网站经网关分流；无需安装任何应用。"
		}
		return g
	}

	// 配置变更后重建策略与出口，无需重启进程
	mgr.Reload = func() (*policy.Engine, *egress.Registry, error) {
		nb, err := setup(cfgPath, true)
		if err != nil {
			return nil, nil, err
		}
		// 原子替换指针；绝不复制含 sync.RWMutex 的结构体。
		// Manager 的运行态由调用方（Manager 内部）装配，
		// 这里不得回调 mgr 的加锁方法，避免死锁。
		rt.SetRuntime(nb.engine, nb.reg)
		a.engine, a.reg, a.cfg = nb.engine, nb.reg, nb.cfg
		return nb.engine, nb.reg, nil
	}

	// 出口 IPv6 能力后台刷新：旧版本添加的出口 has_ipv6 恒为 false，
	// 而蜂窝多为 v6 环境（WhatsApp 优先连 Meta IPv6 字面量）。
	// 启动后实测一次 SOCKS ATYP=4 代拨能力，变化则持久化并热重载。
	go func() {
		time.Sleep(3 * time.Second) // 等 mihomo 实例就绪
		changed, err := mgr.RefreshEgressIPv6(4 * time.Second)
		if err != nil {
			log.Printf("出口 IPv6 能力刷新失败: %v", err)
			return
		}
		if len(changed) > 0 {
			log.Printf("出口 IPv6 能力已更新: %s", strings.Join(changed, ", "))
		}
	}()

	// 规则集后台刷新：启动用缓存秒起，下载移到后台；
	// 刷新成功后热重载引擎，服务全程在线。
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	defer refreshCancel()
	go func() {
		fetcher := ruleset.NewFetcher("/var/lib/5gpn-next/rulesets")
		// 启动后先刷一轮（缓存可能已陈旧或不存在）
		for {
			changed := false
			// 必须使用 EffectiveRuleSets：默认广告规则由 ad_block 动态注入，
			// 不在磁盘 rulesets 数组里。只遍历 cfg.RuleSets 会让广告库永不更新。
			for _, rs := range mgr.EffectiveRuleSets() {
				if rs.Path != "" || rs.URL == "" {
					continue
				}
				fctx, fcancel := context.WithTimeout(refreshCtx, 120*time.Second)
				_, upd, err := fetcher.FetchChanged(fctx, rs.Name, rs.URL)
				fcancel()
				if err != nil {
					log.Printf("规则集 %s 后台刷新失败: %v（继续用缓存）", rs.Name, err)
					continue
				}
				if upd {
					changed = true
				}
			}
			// 只有内容真的变了才热重载。ReloadRuntime 会在旧引擎仍存活时
			// 构建一份全新引擎（cn-domain 11 万条 + 广告库 10 万条），内存
			// 瞬时翻倍。旧实现无论内容是否变化都判定“已刷新”，于是每次
			// 启动都必定重载一次，峰值撞破 cgroup 上限被 OOM kill，重启后
			// 再次重复，形成 OOM→重启→再 OOM 的死循环（生产实测 7 天 200
			// 次），期间所有下载连接被反复掐断。
			if changed {
				if err := mgr.ReloadRuntime(); err != nil {
					log.Printf("规则集刷新后重载失败: %v", err)
				} else {
					log.Printf("规则集已后台刷新并生效")
				}
			}
			select {
			case <-refreshCtx.Done():
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()

	clientPfx, perr := netip.ParsePrefix(a.cfg.ClientCIDR)
	if perr != nil {
		return fmt.Errorf("client_cidr 无效: %w", perr)
	}

	// 自更新只替换二进制，不会重跑 install.sh。每次启动都在现有 fgpn
	// 链上幂等补齐客户端放行与公网 drop，确保安全修复覆盖生产存量机器。
	tcpPorts := []int{portOf(a.cfg.Gateway.Listen)}
	var udpPorts []int
	if a.cfg.DNS.Enabled {
		tcpPorts = append(tcpPorts,
			portOf(a.cfg.DNS.HTTPListen), portOf(a.cfg.DNS.TLSListen), portOf(a.cfg.DNS.DoTListen))
		if a.cfg.DNS.QUICTakeoverEnabled() {
			udpPorts = append(udpPorts, portOf(a.cfg.DNS.TLSListen))
		}
	}
	fwCtx, fwCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if changed, ferr := fw.EnsureIngressRestrictions(fwCtx, a.cfg.ClientCIDR, tcpPorts, udpPorts); ferr != nil {
		log.Printf("警告: 补齐入口访问控制失败（应用层限制仍生效）: %v", ferr)
	} else if changed {
		log.Printf("已补齐入口防火墙：仅允许 %s 访问网关端口", a.cfg.ClientCIDR)
	}
	fwCancel()

	// 内网 Web 面板：挂在根路径，仅内网卡来源可达，无需登录
	var panelHandler http.Handler
	if a.cfg.Panel.Enabled {
		p, err := web.New(mgr, version, []string{a.cfg.ClientCIDR})
		if err != nil {
			return fmt.Errorf("初始化面板失败: %w", err)
		}
		panelHandler = p.Handler()
		log.Printf("内网面板已启用: https://%s:%d/（仅 %s 可访问）",
			a.cfg.Gateway.Host, portOf(a.cfg.Gateway.Listen), a.cfg.ClientCIDR)
	}

	// iOS 与 Android 共用的加密 DNS 接入：DoT + SNI/Host 嗅探。
	// 系统 DNS 入口拿不到应用层目的地，只能靠 DNS 改写把流量引回
	// 网关，再从 SNI/Host 或 DNS 线索还原目标。
	ingressCtx, ingressCancel := context.WithCancel(context.Background())
	defer ingressCancel()

	if a.cfg.DNS.Enabled {
		gwIP, perr := netip.ParseAddr(a.cfg.DNS.GatewayIP)
		if perr != nil {
			return fmt.Errorf("dns.gateway_ip 无效: %w", perr)
		}
		// 登记自身 IP，开启出站拨号的自连接防护。DoT 把域名改写到
		// 网关 IP，若出站时又解析回同一地址，会连回自己的接管端口形成
		// 无限环路：生产实测 TIME_WAIT 被瞬间打满至 tcp_max_tw_buckets
		// 上限，cgroup 内存由 51MB 暴涨到 511MB 触发 OOM kill。
		egress.SetGatewayIP(gwIP)
		// 同时登记域名：SOCKS5 由远端解析目标，DIRECT 的 ControlContext
		// 看不到它的最终 IP；精确拦截网关域名可防跨出口递归回本机。
		egress.SetGatewayHost(a.cfg.Gateway.Host)
		// DNS 线索表：DoT 改写时记录「客户端→域名」，无 SNI 私有协议
		// （如 WhatsApp Noise）嗅探失败时用它回退还原目的地。
		hints := hint.New()

		sn := &sniff.Server{
			Policy:     rt.Policy,
			Egress:     rt.Egress,
			Recorder:   rec,
			OnConn:     traffic.Conn,
			OnTraffic:  traffic.Traffic,
			HintLookup: hints.Lookup,
			ClientCIDR: clientPfx,
			OnDial:     health.RecordForward,
		}
		sniffSrv = sn
		health.SniffActive = sn.ActiveConns
		go func() {
			if e := sn.ListenAndServe(ingressCtx, a.cfg.DNS.TLSListen, true); e != nil {
				log.Printf("加密 DNS TLS 接管入口退出: %v", e)
			}
		}()
		go func() {
			if e := sn.ListenAndServe(ingressCtx, a.cfg.DNS.HTTPListen, false); e != nil {
				log.Printf("加密 DNS HTTP 接管入口退出: %v", e)
			}
		}()

		ds := &dot.Server{
			Listen:     a.cfg.DNS.DoTListen,
			GatewayIP:  gwIP,
			OnRewrite:  hints.Add,
			ClientCIDR: clientPfx,
			Upstream:   a.cfg.DNS.Upstream,
			CertFile:   a.cfg.Gateway.CertFile,
			KeyFile:    a.cfg.Gateway.KeyFile,
			Policy:     rt.Policy,
			OnDecision: func(_ string, action string) {
				dnsStats.record(action)
			},
			OnUpstream: health.RecordDNS,
			OnResponse: func(qname, action string) {
				// 内置 DoH 阻断是链路修复，不计入广告拦截统计。
				if action == "block" && !config.IsBuiltinDoHBlocked(qname) {
					traffic.AdBlockSuccess(qname)
				}
			},
		}
		go func() {
			if e := ds.ListenAndServe(ingressCtx); e != nil {
				log.Printf("DoT 入口退出: %v", e)
			}
		}()

		// QUIC 接管：Google Play 下载器（Cronet）走 HTTP/3，被 reject 后
		// 不回落 TCP 只无限重试，表现为「下载永远等待中」。接管后解析
		// Initial 包的 SNI 并按策略转发 UDP，让 HTTP/3 直接走通。
		if a.cfg.DNS.QUICTakeoverEnabled() {
			qs := &quicfwd.Server{
				Policy:     rt.Policy,
				Egress:     rt.Egress,
				Recorder:   rec,
				OnConn:     traffic.Conn,
				OnTraffic:  traffic.Traffic,
				HintLookup: hints.Lookup,
				ClientCIDR: clientPfx,
				OnDial:     health.RecordForward,
			}
			quicSrv = qs
			health.QUICActive = qs.ActiveSessions
			// 先放行防火墙再起监听：顺序反了会有一小段时间客户端收到
			// 拒绝而放弃 QUIC。放行失败不致命，服务照常降级运行。
			fwCtx, fwCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if changed, ferr := fw.EnsureQUICAccept(fwCtx, a.cfg.ClientCIDR); ferr != nil {
				log.Printf("警告: 放行 QUIC(UDP 443) 失败，接管可能收不到流量: %v", ferr)
			} else if changed {
				log.Printf("防火墙已放行 QUIC(UDP 443)，来源 %s", a.cfg.ClientCIDR)
			}
			fwCancel()
			// 周期性重新确认：开机时 5gpn-next-nft.service 或用户手工
			// reload 防火墙都可能把旧的 reject 规则带回来，那会让接管
			// 静默收不到流量。幂等检查，已放行时不做任何修改。
			go func() {
				t := time.NewTicker(2 * time.Minute)
				defer t.Stop()
				for {
					select {
					case <-ingressCtx.Done():
						return
					case <-t.C:
						c, cancel := context.WithTimeout(ingressCtx, 10*time.Second)
						if changed, ferr := fw.EnsureQUICAccept(c, a.cfg.ClientCIDR); ferr == nil && changed {
							log.Printf("防火墙 QUIC 放行规则已自动补回")
						}
						cancel()
					}
				}
			}()
			go func() {
				if e := qs.ListenAndServe(ingressCtx, a.cfg.DNS.TLSListen); e != nil {
					log.Printf("QUIC 接管入口退出: %v", e)
				}
			}()
		} else {
			// 显式关闭接管：恢复 reject，避免客户端 QUIC 石沉大海。
			fwCtx, fwCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if changed, ferr := fw.RestoreQUICReject(fwCtx, a.cfg.ClientCIDR); ferr != nil {
				log.Printf("警告: 恢复 QUIC 拒绝规则失败: %v", ferr)
			} else if changed {
				log.Printf("QUIC 接管已关闭，防火墙恢复拒绝 UDP 443")
			}
			fwCancel()
		}
	}

	// 健康监控探测循环：随 ingress 生命周期一起停。
	go health.Run(ingressCtx)

	// Telegram Bot
	botCtx, botCancel := context.WithCancel(context.Background())
	defer botCancel()
	if a.cfg.Bot.Token != "" && len(a.cfg.Bot.Admins) > 0 {
		tb := bot.New(a.cfg.Bot.Token, a.cfg.Bot.Admins, mgr, version)
		health.Notify = func(text string) {
			nctx, ncancel := context.WithTimeout(botCtx, 30*time.Second)
			tb.Notify(nctx, text)
			ncancel()
		}
		if panelHandler != nil {
			tb.PanelURL = fmt.Sprintf("https://%s:%d/",
				a.cfg.Gateway.Host, portOf(a.cfg.Gateway.Listen))
		}
		go tb.Run(botCtx)

		// 启动通知只在版本变化时发一次：
		// 日常 restart / 崩溃拉起不再刷屏。
		if markStartupNotified(version) {
			go func() {
				time.Sleep(2 * time.Second)
				tb.Notify(botCtx, "✅ <b>5gpn-NEXT 已就绪</b>\n\n"+
					"版本  <code>"+version+"</code>\n"+
					"发送 /start 打开管理菜单")
			}()
		}

		// 周期检查新版本并推送。默认只通知不安装，
		// 避免在用户不知情时替换正在运行的二进制。
		if a.cfg.Update.CheckEnabled {
			// 兜底值必须与配置默认值同源，否则 interval_hours=0 的配置会
			// 悄悄退回旧的 12 小时，与新默认脱节。
			iv := time.Duration(a.cfg.Update.IntervalHours) * time.Hour
			if iv <= 0 {
				iv = config.DefaultUpdateIntervalHours * time.Hour
			}
			go func() {
				t := time.NewTicker(iv)
				defer t.Stop()
				// 启动后先查一次再进入周期循环。否则新装或刚重启的机器要空等
				// 满一个周期才可能收到提醒，期间用户完全不知道
				// 已有新版本。延迟 20 秒是为了让 Bot 与网络就绪，避免开机瞬间
				// 查询失败白白浪费这一次。
				first := time.NewTimer(20 * time.Second)
				defer first.Stop()
				for {
					select {
					case <-botCtx.Done():
						return
					case <-first.C:
					case <-t.C:
					}
					cctx, cancel := context.WithTimeout(botCtx, 60*time.Second)
					has, rel, err := updater.HasUpdate(cctx)
					cancel()
					if err != nil || !has || mgr.IsIgnoredVersion(rel.Tag) || !updater.ShouldNotify(rel.Tag) {
						continue
					}
					tb.Notify(botCtx, fmt.Sprintf(
						"\U0001F514 <b>发现新版本 %s</b>%s当前 <code>%s</code>%s%s%s在菜单「更新」中可一键升级。",
						rel.Tag, nl2, version, nl2, htmlPre(rel.Notes, 800), nl2))
					if a.cfg.Update.AutoApply {
						actx, acancel := context.WithTimeout(context.Background(), 5*time.Minute)
						if out, aerr := updater.Apply(actx, rel.Tag); aerr == nil {
							tb.Notify(botCtx, "\u2705 "+out)
						} else {
							tb.Notify(botCtx, "\u26A0\uFE0F 自动升级失败："+aerr.Error())
						}
						acancel()
					}
				}
			}()
		}
	}

	// HTTPS 端点：描述文件下载、内网面板与运行状态。
	root := &httpService{
		ProfilePath:  profilePath,
		ProfileBytes: profBytes,
		Panel:        panelHandler,
		Stats:        snapshot,
		Runtime:      rt,
		Version:      version,
		ClientCIDR:   clientPfx,
	}

	cert, err := tls.LoadX509KeyPair(a.cfg.Gateway.CertFile, a.cfg.Gateway.KeyFile)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
	}

	hs := &http.Server{
		Addr:              a.cfg.Gateway.Listen,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		IdleTimeout: 5 * time.Minute,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}()

	log.Printf("5gpn-next %s 启动 listen=%s rules=%d egress=%v ipv6=%v",
		version, a.cfg.Gateway.Listen, a.engine.Len(), a.reg.Names(), a.engine.EgressHasV6())

	if err := hs.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// cleanupRetiredArtifacts 收尾已删除功能留下的本机状态。
func cleanupRetiredArtifacts(cfgPath string) {
	if changed, err := config.MigrateLegacyFile(cfgPath); err != nil {
		log.Printf("警告: 旧版配置迁移失败: %v（继续使用内存中的兼容配置）", err)
	} else if changed {
		log.Printf("旧版配置已迁移为 gateway/dns schema")
	}

	const legacyCADir = "/var/lib/5gpn-next/ca"
	if _, err := os.Lstat(legacyCADir); err != nil {
		return
	}
	if err := os.RemoveAll(legacyCADir); err != nil {
		log.Printf("警告: 清理退役定位 CA 失败: %v", err)
		return
	}
	log.Printf("已清理退役定位功能的服务端 CA")
}

// ---------- probe ----------

func cmdProbe(args []string) error {
	cfgPath := flagValue(args, "-c", "/etc/5gpn-next/config.json")
	target := lastNonFlag(args)
	if target == "" {
		return fmt.Errorf("请指定目标，例如: 5gpnd probe -c /etc/5gpn-next/config.json chatgpt.com")
	}
	a, err := setup(cfgPath, true)
	if err != nil {
		return err
	}
	p := &probe.Prober{Policy: a.engine, Egress: a.reg}
	tr := p.Run(context.Background(), manage.NormalizeTarget(target))
	fmt.Print(tr.Human())
	if !tr.OK() {
		os.Exit(1)
	}
	return nil
}

// ---------- profile ----------

func cmdProfile(args []string) error {
	cfgPath := flagValue(args, "-c", "/etc/5gpn-next/config.json")
	out := flagValue(args, "-o", "")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if !cfg.DNS.Enabled {
		return fmt.Errorf("描述文件依赖 DoT 入口，请先启用 dns.enabled")
	}

	o := profile.DefaultDNS(cfg.Gateway.Host)
	if cfg.DNS.GatewayIP != "" {
		o.ServerAddresses = []string{cfg.DNS.GatewayIP}
	}
	b, err := o.Build()
	if err != nil {
		return err
	}
	if out == "" || out == "-" {
		os.Stdout.Write(b)
		return nil
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("已生成 %s\n  DoT = %s:853\n  仅蜂窝数据启用，Wi-Fi 不受影响\n", out, cfg.Gateway.Host)
	return nil
}

// ---------- 小工具 ----------

func flagValue(args []string, name, def string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return def
}

func lastNonFlag(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		if i > 0 && strings.HasPrefix(args[i-1], "-") {
			continue
		}
		return args[i]
	}
	return ""
}

func portOf(listen string) int {
	i := strings.LastIndex(listen, ":")
	if i < 0 {
		return 443
	}
	p := 0
	for _, c := range listen[i+1:] {
		if c < '0' || c > '9' {
			return 443
		}
		p = p*10 + int(c-'0')
	}
	if p == 0 {
		return 443
	}
	return p
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "."
	}
	return p[:i]
}

// ---------- check ----------

func cmdCheck(args []string) error {
	cfgPath := flagValue(args, "-c", "/etc/5gpn-next/config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	// 只做静态校验，不拉取远程规则集，便于安装脚本快速验证
	eng := policy.New()
	if err := applyRules(cfg, eng); err != nil {
		return err
	}
	fmt.Printf("配置有效: %s\n  监听=%s 出口=%d 规则=%d\n",
		cfgPath, cfg.Gateway.Listen, len(cfg.Egress), len(cfg.Rules))
	return nil
}

// ---------- node-config ----------

func cmdNodeConfig(args []string) error {
	linkPath := flagValue(args, "-link", "")
	outPath := flagValue(args, "-out", "")
	socks := portOf(":" + flagValue(args, "-socks", "7891"))
	if linkPath == "" || outPath == "" {
		return fmt.Errorf("用法: 5gpnd node-config -link <链接文件> -out <输出文件> [-socks 7891]")
	}

	raw, err := os.ReadFile(linkPath)
	if err != nil {
		return fmt.Errorf("读取节点链接失败: %w", err)
	}
	n, err := node.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	yaml, err := n.MihomoConfig(socks)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(yaml), 0o600); err != nil {
		return err
	}
	// 只打印脱敏摘要，绝不回显密钥
	fmt.Printf("  节点解析成功: %s\n", n.Redacted())
	if n.Name != "" {
		fmt.Printf("  备注名: %s\n", n.Name)
	}
	return nil
}

// markStartupNotified 判断本次启动是否需要推送启动通知。
//
// 规则：状态文件里记录的版本与当前一致 → 普通重启，不再打扰；
// 版本变化（升级/回退/首装）→ 通知一次并落盘。
// 状态目录不可写时保守起见仍通知（宁可多一条，不吞掉升级结果）。
func markStartupNotified(version string) bool {
	const marker = "/var/lib/5gpn-next/last-start-version"
	if b, err := os.ReadFile(marker); err == nil &&
		strings.TrimSpace(string(b)) == version {
		return false
	}
	_ = os.MkdirAll("/var/lib/5gpn-next", 0o750)
	_ = os.WriteFile(marker, []byte(version+"\n"), 0o640)
	return true
}

// nl2 是两个换行，避免在字符串字面量里内联转义序列。
const nl2 = "\n\n"

// htmlPre 把发布说明包成可安全发送的 <pre> 片段。
func htmlPre(s string, limit int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) > limit {
		s = string(r[:limit]) + "\n…"
	}
	rep := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return "<pre>" + rep.Replace(s) + "</pre>"
}
