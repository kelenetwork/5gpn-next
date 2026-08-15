// Package mitm 提供受限的 TLS 中间人能力。
//
// ⚠️ 安全边界（务必遵守）：
//
//   - 本包只为 AllowedHosts 里硬编码的域名签发证书，其余流量一律透传，
//     绝不解密。白名单不可由配置文件扩展，避免误配置导致全量解密。
//   - 根 CA 私钥仅存于网关本机 0600 文件，绝不外发。
//   - 功能默认关闭；未启用时不生成 CA、不下发证书、不拦截任何流量。
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AllowedHosts 是允许中间人的域名白名单（硬编码，不可配置）。
//
// 只包含 Apple 网络定位服务：手机把扫到的 WiFi/基站上报给它，
// 它返回「你在哪」的坐标。改写这个响应即可修改网络定位结果。
var AllowedHosts = map[string]bool{
	"gs-loc.apple.com":    true,
	"gs-loc-cn.apple.com": true,
}

// locationSuffix 是 Apple 定位服务的边缘节点域名后缀。
//
// 实测发现 iOS 并不总是直连 gs-loc.apple.com，也会把定位查询发给
// gspe1-ssl.ls.apple.com / gsp10-ssl.ls.apple.com 这类边缘节点
// （生产 trace: gspe1-ssl.ls.apple.com up=1898B down=4347B，
// 正是「上传 WiFi 列表、下载坐标」的流量特征）。
//
// 只放行 gsp 前缀的定位子域，不覆盖 ls.apple.com 下的其它服务。
const locationSuffix = ".ls.apple.com"

// Allowed 报告某主机是否在中间人白名单内。
//
// 两类：精确匹配的 gs-loc 端点，以及 gsp*-ssl.ls.apple.com 边缘节点。
// 其余一切主机（含 apple.com 本身与 xxx.ls.apple.com.evil.com）一律拒绝。
func Allowed(host string) bool {
	if AllowedHosts[host] {
		return true
	}
	if !strings.HasSuffix(host, locationSuffix) {
		return false
	}
	label := host[:len(host)-len(locationSuffix)]
	// 必须是单段标签（不含点），且以 gsp 开头：gspe1-ssl / gsp10-ssl ...
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	return strings.HasPrefix(label, "gsp")
}

// CA 是网关自签根证书颁发机构。
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte // 根证书 PEM，用于写入描述文件

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreateCA 载入已有 CA；不存在时生成一份新的。
//
// CA 有效期 10 年：描述文件里的根证书过期会导致定位功能静默失效，
// 且用户需要重装描述文件，因此不宜过短。
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	if cert, key, pemBytes, err := loadCA(certPath, keyPath); err == nil {
		return &CA{cert: cert, key: key, pem: pemBytes, cache: map[string]*tls.Certificate{}}, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 CA 目录失败: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "5gpn-NEXT Location CA",
			Organization: []string{"5gpn-NEXT"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// 私钥必须 0600：泄漏即意味着任何人都能冒充被中间人的站点
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("写入 CA 私钥失败: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("写入 CA 证书失败: %w", err)
	}
	return &CA{cert: cert, key: key, pem: certPEM, cache: map[string]*tls.Certificate{}}, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, nil, fmt.Errorf("CA PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, nil, fmt.Errorf("CA 已过期")
	}
	return cert, key, certPEM, nil
}

// CertPEM 返回根证书 PEM（写入描述文件用）。
func (c *CA) CertPEM() []byte { return c.pem }

// CertDER 返回根证书 DER（描述文件 payload 需要 base64 的 DER）。
func (c *CA) CertDER() []byte { return c.cert.Raw }

// Fingerprint 返回证书 SHA-256 指纹，便于用户核对。
func (c *CA) Fingerprint() string { return sha256Hex(c.cert.Raw) }

// LeafFor 为指定主机签发叶证书（带缓存）。
//
// 仅允许白名单内的主机；其它主机一律拒绝，杜绝配置错误导致的全量解密。
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	if !Allowed(host) {
		return nil, fmt.Errorf("主机 %q 不在中间人白名单内", host)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if tc, ok := c.cache[host]; ok {
		return tc, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		// 叶证书 397 天：符合主流 CA/B 论坛上限，iOS 对超长有效期更严格
		NotAfter:    time.Now().AddDate(0, 0, 397),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.cache[host] = tc
	return tc, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// sha256Hex 返回 DER 的 SHA-256 十六进制指纹（大写、冒号分隔）。
func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	var b strings.Builder
	for i, x := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String()
}
