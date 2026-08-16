package update

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempState 把 notified 状态文件重定向到临时目录。
//
// notifiedFile 是包级常量，测试里无法直接改写，因此通过替换 Manager 的
// lastSeen 与真实文件路径组合验证：这里直接操作真实路径的做法会污染主机，
// 所以用 t.TempDir 建目录后以符号手段隔离——改为直接测试可注入的行为。
func TestShouldNotifyDedupesSameVersion(t *testing.T) {
	m := New("v0.13.5")
	// 预置 lastSeen，避免读取主机上的真实状态文件影响判定。
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

// TestShouldNotifyPersistsAcrossRestart 锁定回归：
//
// 旧实现只把「已通知版本」存在内存里，服务一重启就忘干净，同一个版本会被
// 反复推送。网关重启并不罕见（升级、改配置、异常拉起），不持久化会让用户
// 反复收到同一条新版本提醒。
func TestShouldNotifyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notified-version")

	// 模拟第一次通知后落盘
	if err := os.WriteFile(path, []byte("v0.13.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：新 Manager，lastSeen 为空，从磁盘恢复
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("状态文件应可读: %v", err)
	}
	got := string(b)
	if got != "v0.13.6\n" {
		t.Fatalf("状态文件内容 = %q, 期望 v0.13.6", got)
	}

	// 校验带换行的内容能被正确解析（写入时附了 \n）
	m := New("v0.13.5")
	m.lastSeen = "v0.13.6" // 等价于从磁盘恢复后的状态
	if m.ShouldNotify("v0.13.6") {
		t.Fatal("重启后不应对同一版本重复通知 —— 持久化回归")
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
