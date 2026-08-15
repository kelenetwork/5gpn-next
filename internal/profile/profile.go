// Package profile 生成 Apple Network Relay 描述文件（.mobileconfig）。
//
// 字段依据 Apple DeviceManagement/Relay 官方文档，PayloadType 为
// com.apple.relay.managed（iOS 17+）。
//
// P0 实测要点：
//   - 自建服务端下发即可安装，不需要 MDM。
//   - RelayUUID 必须稳定，否则 iOS 会把每次生成当成新配置并存。
//   - iOS 26+ 的 UIToggleEnabled / AllowDNSFailover 是重要安全阀：
//     前者允许用户自行关闭，后者保证 Relay 故障时不整机断网。
package profile

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// PayloadTypeRelay 是 Relay 载荷类型。
const PayloadTypeRelay = "com.apple.relay.managed"

// Options 是生成参数。
type Options struct {
	// Host / Port 构成 HTTP2RelayURL
	Host string
	Port int
	Path string // 通常为 "/"

	// Token 写入 AdditionalHTTPHeaderFields
	TokenHeader string
	Token       string

	// ExcludedDomains 为用户追加的手机侧直连名单（第一层分流）。
	// 生产配置会自动合并 BuiltinExcludedDomains，避免国内流量先绕境外网关。
	ExcludedDomains []string

	// MatchDomains 非空时改为白名单模式（仅测试用）。
	MatchDomains []string

	Organization string
	DisplayName  string
	Description  string

	// 稳定标识：同一网关的后续版本必须复用
	ProfileIdentifier string
	RelayIdentifier   string
	RelayUUID         string
	ProfileUUID       string
	RelayPayloadUUID  string
}

// Default 返回填好稳定标识的默认参数。
func Default(host string, port int) Options {
	return Options{
		Host:              host,
		Port:              port,
		Path:              "/",
		TokenHeader:       "X-5gpn-Token",
		Organization:      "5gpn-NEXT",
		DisplayName:       "5gpn-NEXT",
		Description:       "5gpn-NEXT 系统级网络中继，同时作用于蜂窝与 Wi-Fi。可在「设置 → 通用 → VPN 与设备管理」中关闭或删除。",
		ProfileIdentifier: "de.ke1e.5gpn.next",
		RelayIdentifier:   "de.ke1e.5gpn.next.relay",
	}
}

// Build 渲染 plist。
func (o Options) Build() ([]byte, error) {
	if o.Host == "" {
		return nil, fmt.Errorf("host 不能为空")
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.Path == "" {
		o.Path = "/"
	}
	if o.RelayUUID == "" {
		o.RelayUUID = deriveUUID("relay-config:" + o.Host)
	}
	if o.ProfileUUID == "" {
		o.ProfileUUID = deriveUUID("profile:" + o.Host)
	}
	if o.RelayPayloadUUID == "" {
		o.RelayPayloadUUID = deriveUUID("relay-payload:" + o.Host)
	}

	relayURL := fmt.Sprintf("https://%s:%d%s", o.Host, o.Port, o.Path)

	inner := dict{}
	inner.set("HTTP2RelayURL", str(relayURL))
	if o.Token != "" {
		hdr := dict{}
		hdr.set(o.TokenHeader, str(o.Token))
		inner.set("AdditionalHTTPHeaderFields", hdr)
	}

	relay := dict{}
	relay.set("PayloadType", str(PayloadTypeRelay))
	relay.set("PayloadVersion", integer(1))
	relay.set("PayloadIdentifier", str(o.RelayIdentifier))
	relay.set("PayloadUUID", str(o.RelayPayloadUUID))
	relay.set("PayloadDisplayName", str(o.DisplayName))
	relay.set("PayloadDescription", str(o.Description))
	relay.set("PayloadOrganization", str(o.Organization))
	relay.set("RelayUUID", str(o.RelayUUID))
	// iOS 26+ 安全阀
	relay.set("UIToggleEnabled", boolean(true))
	relay.set("AllowDNSFailover", boolean(true))
	relay.set("Relays", array{inner})

	if len(o.MatchDomains) > 0 {
		relay.set("MatchDomains", strArray(o.MatchDomains))
	} else {
		// iOS 的 Relay 一旦接管连接，服务端 DIRECT 也只是从境外网关本机
		// 直出，无法再回到手机本地网络。国内常用域名必须在客户端侧排除，
		// 才是真正“不绕 KFC/不受国外出口影响”。
		relay.set("ExcludedDomains", strArray(EffectiveExcludedDomains(o.ExcludedDomains)))
	}

	root := dict{}
	root.set("PayloadType", str("Configuration"))
	root.set("PayloadVersion", integer(1))
	root.set("PayloadIdentifier", str(o.ProfileIdentifier))
	root.set("PayloadUUID", str(o.ProfileUUID))
	root.set("PayloadDisplayName", str(o.DisplayName))
	root.set("PayloadDescription", str(o.Description))
	root.set("PayloadOrganization", str(o.Organization))
	root.set("PayloadRemovalDisallowed", boolean(false))
	root.set("PayloadContent", array{relay})

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	root.render(&buf, 0)
	buf.WriteString("</plist>\n")
	return buf.Bytes(), nil
}

// BuiltinExcludedDomains 返回 iOS 手机侧直连的内置域名后缀。
//
// 不能把完整 11 万条 direct-list 塞进 mobileconfig：体积、安装耗时和
// iOS 每次匹配成本都不可控。这里覆盖全部 .cn 与国内头部 App 的核心
// 域名；遗漏项仍由服务端 cn-domain/GEOIP 走 KFC DIRECT，用户也可通过
// config.excluded_domains 追加后缀。
func BuiltinExcludedDomains() []string {
	return []string{
		"10010.com", "10086.cn", "12306.cn", "126.net", "163.com", "1688.com", "189.cn",
		"360buyimg.com", "alibaba.com", "alicdn.com", "alipay.com", "alipayobjects.com",
		"aliyun.com", "aliyuncs.com", "amemv.com", "baidu.com", "baidupcs.com", "bcebos.com",
		"bdimg.com", "bdstatic.com", "biliapi.net", "bilibili.com", "byteacctimg.com",
		"bytecdn.cn", "bytegoofy.com", "byteicdn.com", "bytedance.com", "bytednsdoc.com",
		"byteimg.com", "chinamobile.com", "chinatelecom.com.cn", "chinaunicom.cn", "cn",
		"cmpassport.com", "cnki.net", "ctrip.com", "dbankcdn.com", "dianping.com", "douyin.com",
		"douyincdn.com", "douyinpic.com", "douyinstatic.com", "douyinvod.com", "ecombdapi.com",
		"edu.cn", "feishu.cn", "gov.cn", "gtimg.cn", "hdslb.com", "heytapimage.com",
		"heytapmobi.com", "hicloud.com", "hitv.com", "huawei.com", "iesdouyin.com", "iqiyi.com",
		"iqiyipic.com", "ixigua.com", "jd.com", "jdcloud.com", "kuaishou.com", "kwimgs.com",
		"meituan.com", "meituan.net", "mgtv.com", "mi.com", "miui.com", "mmstat.com",
		"myqcloud.com", "netease.com", "ntes.net", "oppo.com", "org.cn", "pddpic.com",
		"pinduoduo.com", "pstatp.com", "qiyi.com", "qlogo.cn", "qpic.cn", "qq.com",
		"sina.com.cn", "sinaimg.cn", "snssdk.com", "taobao.com", "taobaocdn.com", "tenpay.com",
		"tmall.com", "toutiao.com", "tripcdn.cn", "unicom.com.cn", "vivo.com.cn", "vmall.com",
		"volccdn.com", "volcengine.com", "volces.com", "volcvideo.com", "wechat.com", "weibo.com",
		"weibocdn.com", "weixin.qq.com", "wo.cn", "xiaomi.com", "xiaomicdn.com", "yangkeduo.com",
		"ykimg.com", "youku.com", "yximgs.com", "zhihu.com", "zhimg.com", "zijieapi.com",
		// 以下来自用户实测（ipinfo.cv 国内站点检测）补充：这些域名不在名单时
		// 会进入 Relay，即使命中国内规则也只能从网关公网 IP 出去，
		// 表现为“国内站点显示网关 IP 而非手机运营商 IP”。
		"ipip.net", "qualcomm.com", "qq.com.cn", "tencent.com", "tencentcs.com",
		"tencentyun.com", "qcloud.com", "gtimg.com", "idqqimg.com", "qqmail.com",
		"alipay.com.cn", "antfin.com", "antgroup.com", "alibabausercontent.com",
		"aliapp.org", "alikunlun.com", "alibabacorp.com", "tbcache.com",
		"douyinliving.com", "douyinstatic.cn", "ixiguavideo.com", "toutiaoapi.com",
		"toutiaocloud.com", "toutiaostatic.com", "toutiaovod.com", "bytefcdn.com",
		"bytescm.com", "byted.org", "bdxiguavideo.com",
		"bilivideo.com", "bilivideo.cn", "biliapi.com", "bilicomic.com", "bilibiligame.net",
		"mi-img.com", "mifile.cn", "miwifi.com", "xiaomiev.com", "duokan.com",
		"163yun.com", "lofter.com", "youdao.com", "yddoc.com", "netease.im",
		"iqiyi.net", "qy.net", "71.am", "pptv.com", "letv.com", "le.com",
		"sohu.com", "sohucs.com", "sogou.com", "sogoucdn.com",
		"huaweicloud.com", "hicloud.cn", "honor.com", "hihonorcdn.com",
		"oppomobile.com", "oppo.cn", "heytap.com", "realme.com",
		"vivo.com", "vivoglobal.com", "iqoo.com",
		"jd.hk", "jdpay.com", "jcloudcs.com", "360buy.com",
		"lazada.com", "cainiao.com", "cainiaoyizhan.com", "ele.me", "elemecdn.com",
		"didiglobal.com", "xiaojukeji.com", "didichuxing.com",
		"kuaishouzt.com", "gifshow.com", "kwaicdn.com", "yximgs.cn",
		"zhihuistatic.com", "zhihu.cn",
		"weixinbridge.com", "wx.qq.com", "servicewechat.com", "wxs.qq.com",
		"amap.com", "autonavi.com", "amapauto.com",
		"ctrip.cn", "trip.com", "qunar.com", "tuniu.com",
		"12306.com", "chsi.com.cn", "chinaums.com", "unionpay.com", "95516.com",
		"icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "cmbchina.com",
		"pingan.com", "cebbank.com", "psbc.com", "bankcomm.com",
		"weibo.cn", "sinajs.cn", "sina.cn", "miaopai.com",
		"ximalaya.com", "kugou.com", "kuwo.cn", "music.163.com", "qqmusic.qq.com",
		"douban.com", "doubanio.com", "zhipin.com", "lagou.com", "51job.com",
		"csdn.net", "cnblogs.com", "gitee.com", "coding.net", "aliyuncs.cn",
	}
}

// EffectiveExcludedDomains 合并内置与用户追加的手机侧直连域名。
func EffectiveExcludedDomains(custom []string) []string {
	return dedupeSorted(append(BuiltinExcludedDomains(), custom...))
}

// ---------- 极简 plist 渲染（避免引入依赖） ----------

type node interface {
	render(b *bytes.Buffer, indent int)
}

type str string

func (s str) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	b.WriteString("<string>")
	xml.EscapeText(b, []byte(string(s)))
	b.WriteString("</string>\n")
}

type integer int

func (i integer) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	fmt.Fprintf(b, "<integer>%d</integer>\n", int(i))
}

type boolean bool

func (v boolean) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	if v {
		b.WriteString("<true/>\n")
	} else {
		b.WriteString("<false/>\n")
	}
}

type array []node

func (a array) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	b.WriteString("<array>\n")
	for _, n := range a {
		n.render(b, ind+1)
	}
	pad(b, ind)
	b.WriteString("</array>\n")
}

// dict 保持插入顺序，便于 diff 与人工核对。
type dict struct {
	keys []string
	vals map[string]node
}

func (d *dict) set(k string, v node) {
	if d.vals == nil {
		d.vals = map[string]node{}
	}
	if _, dup := d.vals[k]; !dup {
		d.keys = append(d.keys, k)
	}
	d.vals[k] = v
}

func (d dict) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	b.WriteString("<dict>\n")
	for _, k := range d.keys {
		pad(b, ind+1)
		b.WriteString("<key>")
		xml.EscapeText(b, []byte(k))
		b.WriteString("</key>\n")
		d.vals[k].render(b, ind+1)
	}
	pad(b, ind)
	b.WriteString("</dict>\n")
}

func strArray(ss []string) array {
	out := make(array, 0, len(ss))
	for _, s := range ss {
		out = append(out, str(s))
	}
	return out
}

func pad(b *bytes.Buffer, n int) {
	for i := 0; i < n; i++ {
		b.WriteByte('\t')
	}
}

func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, ".")))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// deriveUUID 由稳定输入派生 UUID 形状的字符串（FNV-1a 扩展）。
//
// 目的是让同一网关每次生成同一份标识，避免 iPhone 上堆积多份配置。
func deriveUUID(seed string) string {
	var h [16]byte
	const off = uint64(14695981039346656037)
	const pr = uint64(1099511628211)
	for i := 0; i < 2; i++ {
		v := off ^ uint64(i+1)
		for j := 0; j < len(seed); j++ {
			v ^= uint64(seed[j])
			v *= pr
		}
		for k := 0; k < 8; k++ {
			h[i*8+k] = byte(v >> (8 * k))
		}
	}
	h[6] = (h[6] & 0x0f) | 0x40 // version 4
	h[8] = (h[8] & 0x3f) | 0x80 // variant
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]))
}
