// Package update 负责版本检查、升级与回退。
//
// 安全约束：
//   - 只从固定仓库的 Releases 下载，不接受任意 URL
//   - 下载后校验 SHA256SUMS，校验失败即中止
//   - 升级前保留当前二进制副本，回退时直接换回
//   - 任何一步失败都不替换正在运行的二进制
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	repo       = "kelenetwork/5gpn-next"
	binPath    = "/usr/local/bin/5gpnd"
	stateDir   = "/var/lib/5gpn-next"
	backupDir  = stateDir + "/versions"
	maxBinSize = 80 << 20
)

// Release 是一个发布版本。
type Release struct {
	Tag        string    `json:"tag"`
	Name       string    `json:"name"`
	Notes      string    `json:"notes"`
	Published  time.Time `json:"published"`
	Prerelease bool      `json:"prerelease"`
}

// Manager 管理版本。
type Manager struct {
	Current string
	client  *http.Client

	mu           sync.Mutex
	lastSeen     string // 最近一次已通知过的版本，避免重复推送
	notifiedPath string // 测试可注入；生产固定在 stateDir
	busy         bool
}

// New 构造 Manager。
func New(current string) *Manager {
	return &Manager{
		Current:      current,
		client:       &http.Client{Timeout: 60 * time.Second},
		notifiedPath: notifiedFile,
	}
}

// Latest 查询最新正式版本。
func (m *Manager) Latest(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "5gpn-next")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询更新失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub 返回 %d", resp.StatusCode)
	}
	var r struct {
		TagName     string    `json:"tag_name"`
		Name        string    `json:"name"`
		Body        string    `json:"body"`
		PublishedAt time.Time `json:"published_at"`
		Prerelease  bool      `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, err
	}
	return &Release{
		Tag: r.TagName, Name: r.Name, Notes: r.Body,
		Published: r.PublishedAt, Prerelease: r.Prerelease,
	}, nil
}

// HasUpdate 判断是否存在比当前更新的版本。
func (m *Manager) HasUpdate(ctx context.Context) (bool, *Release, error) {
	rel, err := m.Latest(ctx)
	if err != nil {
		return false, nil, err
	}
	return Newer(rel.Tag, m.Current), rel, nil
}

// notifiedFile 记录最近一次已推送过的版本。
//
// 必须落盘：旧实现只存内存，服务一重启就忘干净，同一个版本会被反复
// 推送。网关重启本来就不罕见（升级、改配置、异常拉起），不持久化会让
// 用户反复收到同一条新版本提醒。
const notifiedFile = stateDir + "/notified-version"

// ShouldNotify 判断是否需要推送通知（同一版本只通知一次，跨重启有效）。
func (m *Manager) ShouldNotify(tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.notifiedPath
	if path == "" {
		path = notifiedFile
	}
	if m.lastSeen == "" {
		// 首次调用：从磁盘恢复，避免重启后重复提醒。
		if b, err := os.ReadFile(path); err == nil {
			m.lastSeen = strings.TrimSpace(string(b))
		}
	}
	if m.lastSeen == tag {
		return false
	}
	m.lastSeen = tag
	// 落盘失败不影响本次通知，最坏退化成旧的「重启后重复提醒一次」。
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err == nil {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(tag+"\n"), 0o600); err == nil {
			if err := os.Rename(tmp, path); err != nil {
				_ = os.Remove(tmp)
			}
		}
	}
	return true
}

// Apply 下载并安装指定版本，成功后重启服务。
//
// 流程：下载 → 校验 SHA256 → 备份当前 → 原子替换 → 重启 → 验证。
// 重启后若服务未起来，自动回退到备份版本。
func (m *Manager) Apply(ctx context.Context, tag string) (string, error) {
	// 幂等保护：目标不比当前新一律拒绝。
	// 典型场景是 Telegram 重投旧的「立即升级」回调 ——
	// 若不拦截会造成 升级→重启→重放→再升级 的死循环。
	if tag == m.Current {
		return "", fmt.Errorf("当前已是 %s，无需重复安装", tag)
	}
	if !Newer(tag, m.Current) {
		return "", fmt.Errorf("目标 %s 不比当前 %s 新，已忽略；如需降级请使用回退功能", tag, m.Current)
	}

	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return "", fmt.Errorf("已有更新任务在执行中")
	}
	m.busy = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.busy = false
		m.mu.Unlock()
	}()

	arch := goarch()
	asset := fmt.Sprintf("5gpnd-linux-%s", arch)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, tag)

	// staging 必须放在 stateDir（ReadWritePaths）下：
	// 服务开启 PrivateTmp 时 /tmp 是私有挂载，
	// 沙箱外的 systemd-run 安装通道看不到里面的文件。
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return "", err
	}
	tmpDir, err := os.MkdirTemp(stateDir, "update-")
	if err != nil {
		return "", err
	}
	scheduled := false
	defer func() {
		if !scheduled {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	binTmp := filepath.Join(tmpDir, asset)
	if err := m.download(ctx, base+"/"+asset, binTmp, maxBinSize); err != nil {
		return "", fmt.Errorf("下载二进制失败: %w", err)
	}

	// 校验 SHA256：清单缺失时拒绝安装，不做无校验升级
	sumTmp := filepath.Join(tmpDir, "SHA256SUMS")
	if err := m.download(ctx, base+"/SHA256SUMS", sumTmp, 1<<20); err != nil {
		return "", fmt.Errorf("下载校验清单失败，已中止升级: %w", err)
	}
	want, err := lookupSum(sumTmp, asset)
	if err != nil {
		return "", err
	}
	got, err := fileSHA256(binTmp)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", fmt.Errorf("校验失败：期望 %s，实际 %s", short(want), short(got))
	}

	// 备份当前版本
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return "", err
	}
	backup := filepath.Join(backupDir, "5gpnd-"+sanitizeTag(m.Current))
	b, err := os.ReadFile(binPath)
	if err != nil {
		return "", fmt.Errorf("读取当前版本用于回退失败: %w", err)
	}
	if err := os.WriteFile(backup, b, 0o755); err != nil {
		return "", fmt.Errorf("备份当前版本失败: %w", err)
	}

	// 必须让独立 transient unit 执行替换、重启和验证。若在主服务内
	// systemctl restart 后继续验证，调用进程会先被 systemd 杀掉，后续
	// 代码与 defer 根本不会运行，也就不可能真正自动回退。
	if err := scheduleTransaction(ctx, binTmp, backup, m.Current, tag, tmpDir); err != nil {
		return "", err
	}
	scheduled = true
	return fmt.Sprintf("%s 已下载并通过哈希校验；5 秒后重启，失败会由独立事务自动回退到 %s", tag, m.Current), nil
}

// Versions 列出可回退的备份版本。
func (m *Manager) Versions() []string {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "5gpnd-") {
			continue
		}
		out = append(out, strings.TrimPrefix(e.Name(), "5gpnd-"))
	}
	sort.Slice(out, func(i, j int) bool {
		if Newer(out[i], out[j]) {
			return true
		}
		if Newer(out[j], out[i]) {
			return false
		}
		return out[i] > out[j]
	})
	return out
}

// Rollback 回退到指定备份版本。
func (m *Manager) Rollback(ctx context.Context, tag string) (string, error) {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return "", fmt.Errorf("已有更新任务在执行中")
	}
	m.busy = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.busy = false
		m.mu.Unlock()
	}()

	backup := filepath.Join(backupDir, "5gpnd-"+sanitizeTag(tag))
	if _, err := os.Stat(backup); err != nil {
		return "", fmt.Errorf("没有 %s 的备份", tag)
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(stateDir, "update-")
	if err != nil {
		return "", err
	}
	scheduled := false
	defer func() {
		if !scheduled {
			_ = os.RemoveAll(staging)
		}
	}()

	// 回退前先把当前版本也备份，若目标版本起不来可恢复。
	cur := filepath.Join(backupDir, "5gpnd-"+sanitizeTag(m.Current))
	b, err := os.ReadFile(binPath)
	if err != nil {
		return "", fmt.Errorf("读取当前版本用于回退保护失败: %w", err)
	}
	if err := os.WriteFile(cur, b, 0o755); err != nil {
		return "", fmt.Errorf("保存当前版本失败: %w", err)
	}
	if err := scheduleTransaction(ctx, backup, cur, m.Current, tag, staging); err != nil {
		return "", err
	}
	scheduled = true
	return fmt.Sprintf("已排队回退到 %s；5 秒后重启，若目标版本无法启动会恢复 %s", tag, m.Current), nil
}

// ---------- 内部工具 ----------

func (m *Manager) download(ctx context.Context, url, dst string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "5gpn-next")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("下载内容为空")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lookupSum(path, asset string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("校验清单中没有 %s 的记录", asset)
}

func goarch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

func sanitizeTag(t string) string {
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	s := b.String()
	if s == "" {
		s = "unknown"
	}
	return s
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Newer 比较语义化版本，判断 a 是否比 b 新。
func Newer(a, b string) bool {
	pa, sa := parseVer(a)
	pb, sb := parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	// 主版本相同：无预发布后缀者更新
	if sa == "" && sb != "" {
		return true
	}
	if sa != "" && sb == "" {
		return false
	}
	return sa > sb
}

func parseVer(v string) ([3]int, string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	var suffix string
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		suffix = v[i+1:]
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimFunc(part, func(r rune) bool {
			return r < '0' || r > '9'
		}))
		out[i] = n
	}
	return out, suffix
}
