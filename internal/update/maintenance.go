package update

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxVersionBackups = 5
	staleUpdateAge    = time.Hour
)

// CleanupState 清理上一次自更新因进程重启而来不及执行 defer 留下的 staging，
// 并限制可回退二进制数量。旧实现每个版本会永久留下“下载副本 + 备份副本”
// 两份文件，生产一周已积累 42 个 staging 与 34 个版本、约 670MiB。
func CleanupState() error {
	return cleanupState(stateDir, time.Now(), maxVersionBackups)
}

func cleanupState(root string, now time.Time, keepVersions int) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []string
	liveTransaction := false
	cutoff := now.Add(-staleUpdateAge)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "update-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		dir := filepath.Join(root, e.Name())
		// 只有带 transaction.sh 的新鲜目录才可能属于刚排队、尚未完成的
		// 独立事务。旧版升级 staging 从不含该文件，可在新版本首次启动时
		// 立即清掉，不必再多占一小时磁盘。
		if !info.ModTime().Before(cutoff) {
			if _, err := os.Stat(filepath.Join(dir, "transaction.sh")); err == nil {
				liveTransaction = true
				continue
			}
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, err.Error())
		}
	}
	// 新服务会在外部更新事务的 5 秒验证窗口内启动。此时 fallback 仍由
	// transaction.sh 持有；若恰好把它当“旧版本”裁掉，新版本随后崩溃就
	// 无法回退。只要存在新鲜事务，本次完全跳过版本裁剪，留到下次启动。
	if !liveTransaction {
		if err := pruneVersions(filepath.Join(root, "versions"), keepVersions); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("清理更新状态失败: %s", strings.Join(errs, "; "))
	}
	return nil
}

type versionBackup struct {
	name string
	tag  string
}

func pruneVersions(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var versions []versionBackup
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "5gpnd-") {
			continue
		}
		versions = append(versions, versionBackup{
			name: e.Name(), tag: strings.TrimPrefix(e.Name(), "5gpnd-"),
		})
	}
	sort.Slice(versions, func(i, j int) bool {
		if Newer(versions[i].tag, versions[j].tag) {
			return true
		}
		if Newer(versions[j].tag, versions[i].tag) {
			return false
		}
		return versions[i].name > versions[j].name
	})
	if keep < 0 {
		keep = 0
	}
	var errs []string
	for _, v := range versions[keep:] {
		if err := os.Remove(filepath.Join(dir, v.name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("裁剪版本备份失败: %s", strings.Join(errs, "; "))
	}
	return nil
}
