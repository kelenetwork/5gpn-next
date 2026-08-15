package relay

// RFC 9298 connect-udp over HTTP/2（Extended CONNECT + RFC 9297 capsule）。
//
// iOS Relay 对 UDP（QUIC 等）流量发起：
//
//	:method = CONNECT
//	:protocol = connect-udp
//	:path = /.well-known/masque/udp/{target_host}/{target_port}/
//
// 数据面走 stream 上的 DATAGRAM capsule（type 0x00），
// capsule payload = ContextID varint（0 = UDP payload）+ 原始 UDP 数据报。
//
// 抖音/TikTok 等短视频 App 大量使用 QUIC，此前网关返回 501，
// 客户端回落 TCP 不积极导致刷不出下一条视频 —— 本文件补齐 UDP 路径。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kelenetwork/5gpn-next/internal/egress"
	"github.com/kelenetwork/5gpn-next/internal/policy"
	"github.com/kelenetwork/5gpn-next/internal/trace"
)

// udpIdleTimeout 是 UDP 会话空闲上限。QUIC 有自己的 keepalive，
// 65s 覆盖常见 30s PING 间隔；超时即回收，防会话泄漏。
const udpIdleTimeout = 65 * time.Second

// maxDatagramLen 拒绝异常超大 capsule，防内存放大。
const maxDatagramLen = 64 * 1024

// ---------- QUIC varint（RFC 9000 §16） ----------

func readVarint(r io.ByteReader) (uint64, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (b0 >> 6)
	v := uint64(b0 & 0x3f)
	for i := 1; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// parseVarintPrefix 从字节切片头部解析 varint，返回值与消费的字节数。
func parseVarintPrefix(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("空 varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("varint 不完整")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

// buildDatagramCapsule 构造 DATAGRAM capsule（ContextID=0）。
func buildDatagramCapsule(payload []byte) []byte {
	inner := make([]byte, 0, 1+len(payload))
	inner = appendVarint(inner, 0) // Context ID = 0：UDP payload
	inner = append(inner, payload...)

	out := make([]byte, 0, 2+8+len(inner))
	out = appendVarint(out, 0) // capsule type DATAGRAM
	out = appendVarint(out, uint64(len(inner)))
	return append(out, inner...)
}

// parseMasqueUDPPath 解析 RFC 9298 默认模板路径。
// IPv6 字面量按模板要求百分号编码（2001%3Adb8%3A...）。
func parseMasqueUDPPath(p string) (string, error) {
	rest := strings.TrimPrefix(p, "/.well-known/masque/udp/")
	if rest == p {
		return "", fmt.Errorf("非 masque udp 路径")
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("masque 路径缺少 host/port")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("host 解码失败: %w", err)
	}
	port, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", fmt.Errorf("port 解码失败: %w", err)
	}
	host = strings.Trim(host, "[]")
	if err := validateMasqueHost(host); err != nil {
		return "", err
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return "", fmt.Errorf("masque 端口 %q 无效", port)
	}
	return net.JoinHostPort(host, port), nil
}

// validateMasqueHost 拒绝空值与含有控制字符/路径分隔符的 host。
//
// 客户端可对 host 段做百分号编码，解码后可能出现 "../etc" 这类
// 垃圾值。它们不会被当成文件路径，但作为目的地既无意义又会污染
// 策略匹配与 trace 日志，应在入口层 fail-closed。
func validateMasqueHost(host string) error {
	if host == "" || len(host) > 255 {
		return fmt.Errorf("masque host 长度非法")
	}
	if strings.ContainsAny(host, "/\\ \t\r\n?#@") {
		return fmt.Errorf("masque host 含非法字符")
	}
	if strings.Contains(host, "..") {
		return fmt.Errorf("masque host 含非法序列")
	}
	return nil
}

// handleConnectUDP 处理一条 connect-udp 会话。
func (s *Server) handleConnectUDP(w http.ResponseWriter, r *http.Request) {
	target, err := parseMasqueUDPPath(r.URL.Path)
	if err != nil {
		http.Error(w, "bad masque path", http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("u%d", s.seq.Add(1))
	tr := trace.New(id, target, clientIP(r.RemoteAddr))
	defer func() {
		if s.Recorder != nil {
			s.Recorder.Record(tr)
		}
	}()
	tr.Step(trace.StageIngress, trace.StatusOK, "relay/connect-udp（QUIC 等 UDP 流量）")

	// 策略判定与 TCP 完全一致：自定义规则 → 国内直连 → 国外出口
	t, _ := policy.ParseTarget(target)
	pol := s.Policy()
	reg := s.Egress()
	dec := pol.MatchContext(r.Context(), t)

	actionName := "proxy"
	switch dec.Action {
	case policy.ActionBlock:
		s.Stats.Blocked.Add(1)
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 拦截", dec.Rule)
		s.report(t.Host, "block", 0, 0, false)
		http.Error(w, "blocked by policy", http.StatusForbidden)
		return
	case policy.ActionDirect:
		actionName = "direct"
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 直连", dec.Rule)
	default:
		tr.Step(trace.StagePolicy, trace.StatusOK, "%s → 代理:%s", dec.Rule, orDefault(dec.Egress, "默认"))
	}

	var dialer egress.Dialer
	if dec.Action == policy.ActionDirect {
		dialer = reg.Direct()
	} else {
		d, ok := reg.Get(dec.Egress)
		if !ok {
			tr.Fail(trace.StageEgress, fmt.Errorf("出口 %q 不存在", dec.Egress),
				"出口缺失，已回退 %s", d.Name())
		}
		dialer = d
	}
	ud, ok := dialer.(egress.UDPDialer)
	if !ok {
		tr.Fail(trace.StageEgress, fmt.Errorf("出口 %s 不支持 UDP", dialer.Name()), "UDP 不可用")
		http.Error(w, "udp not supported on egress", http.StatusNotImplemented)
		return
	}
	tr.Step(trace.StageEgress, trace.StatusOK, "%s (ipv6=%v)", dialer.Name(), dialer.HasIPv6())

	dctx, cancel := context.WithTimeout(r.Context(), egress.DialTimeout)
	uc, err := ud.DialUDPContext(dctx, target)
	cancel()
	if err != nil {
		if errors.Is(err, egress.ErrNoIPv6) {
			s.Stats.V6FastFail.Add(1)
			tr.Fail(trace.StageConnect, err, "IPv6 目标快速失败，促使客户端回落 IPv4")
		} else {
			s.Stats.DialFail.Add(1)
			tr.Fail(trace.StageConnect, err, "UDP 建立失败 %s", target)
		}
		s.report(t.Host, actionName, 0, 0, true)
		http.Error(w, "udp dial failed", http.StatusBadGateway)
		return
	}
	defer uc.Close()
	tr.Step(trace.StageConnect, trace.StatusOK, "UDP 会话已建立")

	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	var upN, downN int64
	done := make(chan struct{})

	// 下行：客户端 capsule → UDP 目标
	go func() {
		defer close(done)
		defer uc.Close() // 客户端断开时解除上行阻塞
		br := bufio.NewReaderSize(r.Body, 32*1024)
		for {
			typ, err := readVarint(br)
			if err != nil {
				return
			}
			length, err := readVarint(br)
			if err != nil || length > maxDatagramLen {
				return
			}
			buf := make([]byte, length)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			if typ != 0 { // 非 DATAGRAM capsule：按规范忽略
				continue
			}
			ctxID, n, err := parseVarintPrefix(buf)
			if err != nil || ctxID != 0 {
				continue
			}
			if _, err := uc.Write(buf[n:]); err != nil {
				return
			}
			upN += int64(len(buf) - n)
		}
	}()

	// 上行：UDP 目标 → 客户端 capsule
	buf := make([]byte, maxDatagramLen)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := uc.Read(buf)
		if err != nil {
			break
		}
		if _, err := w.Write(buildDatagramCapsule(buf[:n])); err != nil {
			break
		}
		if flusher != nil {
			flusher.Flush()
		}
		downN += int64(n)
	}
	uc.Close()
	<-done

	tr.Step(trace.StageApp, trace.StatusOK, "UDP 会话关闭 up=%dB down=%dB", upN, downN)
	s.report(t.Host, actionName, upN, downN, false)
}
