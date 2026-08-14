package ruleset

import (
	"bufio"
	"context"
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
	dst := f.cachePath(name)
	if url == "" {
		if _, err := os.Stat(dst); err == nil {
			return dst, nil
		}
		return "", fmt.Errorf("规则集 %s 无 url 且无缓存", name)
	}

	if err := os.MkdirAll(f.CacheDir, 0o755); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "5gpn-next/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, nil // fail-safe：回退缓存
		}
		return "", fmt.Errorf("下载 %s 失败: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if _, statErr := os.Stat(dst); statErr == nil {
			return dst, nil
		}
		return "", fmt.Errorf("下载 %s 返回 %d", name, resp.StatusCode)
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	// 限制单个规则集大小，防止异常来源撑爆磁盘
	n, err := io.Copy(out, io.LimitReader(resp.Body, 64<<20))
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if n == 0 {
		os.Remove(tmp)
		return "", fmt.Errorf("规则集 %s 内容为空", name)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}
