// Package profile 生成 iOS 描述文件（.mobileconfig）。
//
// 当前只生成「蜂窝加密 DNS」描述文件（见 dns.go）：
// 仅蜂窝数据下启用 DoT，Wi-Fi 自动停用，国内目标由 GEOIP 判定后
// 手机本地直连。Relay 模式已于 v0.12.0 移除（它会让所有流量从
// 境外网关落地，国内流量绕远且无法按 IP 排除）。
package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// ---------- 极简 plist 渲染（避免引入依赖） ----------

type node interface {
	render(b *bytes.Buffer, indent int)
}

// data 渲染 <data> 节点（base64），用于内嵌根证书 DER。
type data []byte

func (d data) render(b *bytes.Buffer, ind int) {
	pad(b, ind)
	b.WriteString("<data>")
	b.WriteString(base64.StdEncoding.EncodeToString(d))
	b.WriteString("</data>\n")
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
