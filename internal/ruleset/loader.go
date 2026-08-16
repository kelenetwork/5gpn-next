package ruleset

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadDomainFile 从本地文件载入域名规则集。
func LoadDomainFile(path string) (*DomainSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDomains(f)
}

// LoadCIDRFile 从本地文件载入 CIDR 规则集。
func LoadCIDRFile(path string) (*CIDRSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCIDRs(f)
}

func parseDomains(r io.Reader) (*DomainSet, error) {
	ds := NewDomainSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ds.AddRule(sc.Text())
	}
	return ds, sc.Err()
}

func parseCIDRs(r io.Reader) (*CIDRSet, error) {
	cs := NewCIDRSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		cs.AddRule(sc.Text())
	}
	cs.Finalize()
	return cs, sc.Err()
}

// Fetcher 负责下载并缓存远程规则集。
//
// 缓存策略：下载成功才原子替换缓存；下载失败时回退到已有缓存，
// 保证网络异常不会让分流规则整体失效（fail-safe）。
type Fetcher struct {
	CacheDir string
	Client   *http.Client
}

// NewFetcher 构造 Fetcher。
func NewFetcher(cacheDir string) *Fetcher {
	return &Fetcher{
		CacheDir: cacheDir,
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// cachePath 返回规则集缓存文件路径。
func (f *Fetcher) cachePath(name string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(name)
	return filepath.Join(f.CacheDir, safe+".list")
}

// Cached 返回已有缓存的路径；无缓存时 ok=false。
// 用于启动加速：有缓存就先用，联网刷新放到后台做。
func (f *Fetcher) Cached(name string) (string, bool) {
	dst := f.cachePath(name)
	if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
		return dst, true
	}
	return "", false
}

// Fetch 下载规则集到缓存；失败时若已有缓存则返回缓存路径与 nil。
func (f *Fetcher) Fetch(ctx context.Context, name, url string) (string, error) {
	path, _, err := f.FetchChanged(ctx, name, url)
	return path, err
}

// FetchChanged 下载规则集并报告内容是否真的发生变化。
//
// changed 语义至关重要：调用方据此决定要不要热重载策略引擎。重载会
// 在旧引擎仍存活时构建一份全新引擎（cn-domain 11 万条 + 广告库 10 万条），
// 内存瞬时翻倍。生产事故：旧实现无论内容是否变化、甚至下载失败回退
// 缓存时都返回“成功”，启动自检那一轮必定触发一次全量重载，峰值撞破
// cgroup 上限被 OOM kill，重启后再次重复，形成 OOM→重启→再 OOM 的
// 死循环（实测 7 天 200 次），期间所有下载连接被反复掐断。
//
// 因此只有字节内容确实不同才返回 changed=true；网络失败回退缓存、
// 内容一致、无 url 走缓存等情况一律 changed=false。
func (f *Fetcher) FetchChanged(ctx context.Context, name, url string) (string, bool, error) {
	dst := f.cachePath(name)
	if url == "" {
		if _, err := os.Stat(dst); err == nil {
			return dst, false, nil
		}
		return "", false, fmt.Errorf("规则集 %s 无 url 且无缓存", name)
	}

	if err := os.MkdirAll(f.CacheDir, 0o755); err != nil {
		return "", false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "5gpn-next/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, false, nil // fail-safe：回退缓存，未变化
		}
		return "", false, fmt.Errorf("下载 %s 失败: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, false, nil
		}
		return "", false, fmt.Errorf("下载 %s 返回 %d", name, resp.StatusCode)
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return "", false, err
	}
	// 边写边算摘要，避免为比对再整file读一遍（规则库数 MB）。
	sum := sha256.New()
	// 限制单个规则集大小，防止异常来源撑爆磁盘
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, 64<<20))
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return "", false, err
	}
	if n == 0 {
		os.Remove(tmp)
		return "", false, fmt.Errorf("规则集 %s 内容为空", name)
	}

	// 内容与现有缓存一致：丢弃临时文件，不动缓存，也不触发重载。
	if old, err := fileSHA256(dst); err == nil && bytes.Equal(old, sum.Sum(nil)) {
		os.Remove(tmp)
		return dst, false, nil
	}

	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", false, err
	}
	return dst, true, nil
}

// fileSHA256 返回文件内容摘要；文件不存在时返回错误。
func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
