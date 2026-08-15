package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Spoofer 实现 Apple 网络定位改写。
//
// 生命周期：功能关闭时 cmd 层直接注入 nil，连接路径上零开销；
// 开启但未设坐标时 Active() 为 false，同样全部透传。
type Spoofer struct {
	// caDir 为 CA 存放目录；ca 延迟到首次启用时才生成，
	// 这样未启用的部署不会凭空多出一张根证书。
	caDir string

	mu      sync.RWMutex
	ca      *CA
	enabled bool
	lat     float64
	lon     float64
	hasLoc  bool

	rewrites uint64
	failures uint64
	lastErr  string
}

// Failures 返回改写失败次数。
func (s *Spoofer) Failures() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failures
}

// LastError 返回最近一次改写失败原因（成功后清空）。
func (s *Spoofer) LastError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

// New 构造 Spoofer；CA 延迟生成（见 EnsureCA）。
func New(caDir string) *Spoofer { return &Spoofer{caDir: caDir} }

// EnsureCA 载入或生成根 CA。首次启用定位功能时调用。
//
// CA 一旦生成即长期复用（10 年有效），重启不会变化，
// 因此已安装的描述文件不会因为开关功能而失效。
func (s *Spoofer) EnsureCA() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ca != nil {
		return nil
	}
	ca, err := LoadOrCreateCA(s.caDir)
	if err != nil {
		return err
	}
	s.ca = ca
	return nil
}

// HasCA 报告根证书是否已就绪（决定描述文件是否内嵌证书）。
func (s *Spoofer) HasCA() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca != nil
}

// SetEnabled 开关功能。
func (s *Spoofer) SetEnabled(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = v
}

// SetLocation 设置目标坐标。
func (s *Spoofer) SetLocation(lat, lon float64) error {
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return fmt.Errorf("坐标超出范围: %f,%f", lat, lon)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lat, s.lon, s.hasLoc = lat, lon, true
	return nil
}

// ClearLocation 清除坐标，恢复真实定位。
func (s *Spoofer) ClearLocation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hasLoc = false
}

// Location 返回当前坐标与是否已设置。
func (s *Spoofer) Location() (float64, float64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lat, s.lon, s.hasLoc
}

// Enabled 报告功能开关状态。
func (s *Spoofer) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// Rewrites 返回累计改写次数，便于用户确认功能真的生效。
func (s *Spoofer) Rewrites() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rewrites
}

// Active 报告是否应该拦截：必须同时启用、已设坐标且 CA 就绪。
func (s *Spoofer) Active() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled && s.hasLoc && s.ca != nil
}

// Handles 报告主机是否在中间人白名单内。
func (s *Spoofer) Handles(host string) bool { return Allowed(host) }

// CACertDER 返回根证书 DER（写入描述文件）；CA 未就绪时返回 nil。
func (s *Spoofer) CACertDER() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ca == nil {
		return nil
	}
	return s.ca.CertDER()
}

// CAFingerprint 返回根证书指纹，便于用户核对。
func (s *Spoofer) CAFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ca == nil {
		return ""
	}
	return s.ca.Fingerprint()
}

// mitmTimeout 是单次定位请求的处理上限。
//
// 定位请求本身很快；超时即放弃改写，绝不拖住客户端。
const mitmTimeout = 15 * time.Second

// Serve 在客户端连接上终止 TLS，把请求转发到真实服务器，
// 并改写响应中的坐标。
//
// 返回本次会话内成功改写的响应数。注意：err == nil 不等于改写成功
// —— 解析失败时会原样透传（功能降级而非损坏），此时 n == 0，
// 调用方必须据此如实上报，不得统一报“改写完成”。
func (s *Spoofer) Serve(client, upstream net.Conn, host string) (int, error) {
	if !Allowed(host) {
		return 0, fmt.Errorf("主机 %q 不在白名单内", host)
	}
	lat, lon, ok := s.Location()
	if !ok {
		return 0, fmt.Errorf("未设置目标坐标")
	}
	s.mu.RLock()
	ca := s.ca
	s.mu.RUnlock()
	if ca == nil {
		return 0, fmt.Errorf("根证书未就绪")
	}
	leaf, err := ca.LeafFor(host)
	if err != nil {
		return 0, err
	}
	done := 0

	deadline := time.Now().Add(mitmTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	// 与客户端完成 TLS 握手（用我们签发的证书）
	cs := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := cs.Handshake(); err != nil {
		return done, fmt.Errorf("与客户端 TLS 握手失败: %w", err)
	}
	defer cs.Close()

	// 与真实服务器建立 TLS（正常校验证书，不降低上游安全性）
	us := tls.Client(upstream, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := us.Handshake(); err != nil {
		return done, fmt.Errorf("与上游 TLS 握手失败: %w", err)
	}
	defer us.Close()

	cr := bufio.NewReader(cs)
	ur := bufio.NewReader(us)

	for {
		_ = client.SetDeadline(time.Now().Add(mitmTimeout))
		_ = upstream.SetDeadline(time.Now().Add(mitmTimeout))

		req, err := http.ReadRequest(cr)
		if err != nil {
			return done, nil // 客户端结束会话属正常
		}
		// 原样转发请求（含 body）
		req.URL.Scheme = "https"
		req.URL.Host = host
		if err := req.Write(us); err != nil {
			return done, fmt.Errorf("转发请求失败: %w", err)
		}

		resp, err := http.ReadResponse(ur, req)
		if err != nil {
			return done, fmt.Errorf("读取上游响应失败: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxWlocBody))
		resp.Body.Close()
		if err != nil {
			return done, fmt.Errorf("读取响应体失败: %w", err)
		}

		newBody, rerr := RewriteResponse(body, lat, lon)
		if rerr == nil {
			body = newBody
			done++
			s.mu.Lock()
			s.rewrites++
			s.lastErr = ""
			s.mu.Unlock()
		} else {
			// 改写失败时原样返回（功能降级而非损坏），
			// 但必须记录真实原因，不能静默失败后还报“完成”。
			s.mu.Lock()
			s.failures++
			s.lastErr = rerr.Error()
			s.mu.Unlock()
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.TransferEncoding = nil
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if err := resp.Write(cs); err != nil {
			return done, fmt.Errorf("回写响应失败: %w", err)
		}
		if req.Close || resp.Close {
			return done, nil
		}
	}
}
