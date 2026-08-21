package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShouldNotifyDedupesSameVersion(t *testing.T) {
	m := New("v0.13.5")
	m.notifiedPath = filepath.Join(t.TempDir(), "notified-version")
	m.lastSeen = "v0.13.6"

	if m.ShouldNotify("v0.13.6") {
		t.Fatal("同一版本不应重复通知")
	}
	if !m.ShouldNotify("v0.13.7") {
		t.Fatal("新版本应当通知")
	}
	if m.ShouldNotify("v0.13.7") {
		t.Fatal("刚通知过的版本不应再次通知")
	}
}

// TestShouldNotifyPersistsAcrossRestart 锁定回归：旧实现只把状态存在内存，
// 服务一重启就会对同一个 Release 重复推送。
func TestShouldNotifyPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notified-version")
	first := New("v0.13.5")
	first.notifiedPath = path
	if !first.ShouldNotify("v0.13.6") {
		t.Fatal("首次看到新版本应通知")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("状态文件应落盘: %v", err)
	}
	if string(b) != "v0.13.6\n" {
		t.Fatalf("状态文件内容=%q, want v0.13.6", b)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("状态文件权限=%v err=%v, want 0600", st, err)
	}

	// 模拟进程重启：新 Manager 从同一文件恢复。
	second := New("v0.13.5")
	second.notifiedPath = path
	if second.ShouldNotify("v0.13.6") {
		t.Fatal("重启后不应对同一版本重复通知")
	}
	if !second.ShouldNotify("v0.13.7") {
		t.Fatal("重启后仍应通知真正的新版本")
	}
}

// TestNotifiedFileUnderStateDir 状态文件必须落在 systemd ReadWritePaths 允许
// 的目录下，否则沙箱会让写入静默失败，持久化形同虚设。
func TestNotifiedFileUnderStateDir(t *testing.T) {
	if filepath.Dir(notifiedFile) != stateDir {
		t.Fatalf("notifiedFile=%q 不在 stateDir=%q 下，沙箱会阻止写入",
			notifiedFile, stateDir)
	}
}
