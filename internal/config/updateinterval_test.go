package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeCfg 写一个最小可加载的配置，update 段由调用方指定。
func writeCfg(t *testing.T, updateRaw string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	body := `{
  "gateway": { "listen": ":20443", "host": "gw.example.com",
               "cert_file": "/tmp/cert.pem", "key_file": "/tmp/key.pem" },
  "egress": [ { "name": "DIRECT", "type": "direct" } ],
  "final": "direct",
  "client_cidr": "172.22.0.0/16",
  "dns": { "enabled": true, "dot_listen": ":853", "http_listen": ":80",
           "tls_listen": ":443", "gateway_ip": "10.0.0.1",
           "upstream": ["223.5.5.5:53"] },
  "update": ` + updateRaw + `
}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLegacyIntervalMigratedToNewDefault 锁定本次修复：
//
// 已安装机器的 config.json 里硬写着 interval_hours: 12，只改代码默认值
// 对它们无效——会一直沿用 12 小时。实践证明 12 小时太钝：一次发布最坏
// 要等 12 小时才提醒，且检查点绑在进程启动时刻，重启一次就漂移一次，
// 连发几个版本会全部掉进检查间隙，用户一条提醒都收不到。
func TestLegacyIntervalMigratedToNewDefault(t *testing.T) {
	p := writeCfg(t, `{ "check_enabled": true, "interval_hours": 12, "auto_apply": false }`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if c.Update.IntervalHours != DefaultUpdateIntervalHours {
		t.Fatalf("旧默认值 12 应迁移为 %d，实际 %d",
			DefaultUpdateIntervalHours, c.Update.IntervalHours)
	}
}

func TestLegacyIntervalMigrationIsPersisted(t *testing.T) {
	p := writeCfg(t, `{ "check_enabled": true, "interval_hours": 12, "auto_apply": false }`)
	changed, err := MigrateLegacyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("disk config with legacy default should be rewritten")
	}
	var raw struct {
		Update UpdateConfig `json:"update"`
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Update.IntervalHours != DefaultUpdateIntervalHours {
		t.Fatalf("persisted interval=%d, want %d",
			raw.Update.IntervalHours, DefaultUpdateIntervalHours)
	}
}

// TestExplicitIntervalPreserved 用户显式设置的间隔不得被覆盖。
// 迁移只认「恰好等于旧默认值」这一种情况，其它取值都是主动选择。
func TestExplicitIntervalPreserved(t *testing.T) {
	for _, want := range []int{1, 2, 6, 24, 48} {
		if want == LegacyUpdateIntervalHours {
			continue
		}
		raw := `{ "check_enabled": true, "interval_hours": ` +
			jsonInt(want) + `, "auto_apply": false }`
		c, err := Load(writeCfg(t, raw))
		if err != nil {
			t.Fatalf("interval=%d 加载失败: %v", want, err)
		}
		if c.Update.IntervalHours != want {
			t.Fatalf("用户显式设置的 %d 被改成了 %d", want, c.Update.IntervalHours)
		}
	}
}

// TestZeroIntervalFallsBackToDefault 0 表示「用默认值」，运行时兜底处理。
func TestZeroIntervalFallsBackToDefault(t *testing.T) {
	c, err := Load(writeCfg(t, `{ "check_enabled": true, "interval_hours": 0 }`))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	// 0 不参与迁移，保持原样，由 cmdRun 兜底成默认值
	if c.Update.IntervalHours != 0 {
		t.Fatalf("interval_hours=0 应保持原样交由运行时兜底，实际 %d",
			c.Update.IntervalHours)
	}
}

// TestDefaultConfigUsesNewInterval 全新安装必须直接用新默认值。
func TestDefaultConfigUsesNewInterval(t *testing.T) {
	d := Default()
	if d.Update.IntervalHours != DefaultUpdateIntervalHours {
		t.Fatalf("默认配置 interval_hours = %d, 期望 %d",
			d.Update.IntervalHours, DefaultUpdateIntervalHours)
	}
	if !d.Update.CheckEnabled {
		t.Fatal("默认应开启版本检查")
	}
}

// TestNewDefaultIsReasonable 新默认值必须显著优于旧值，且不至于把
// GitHub API 打爆（未认证限额 60 次/小时）。
func TestNewDefaultIsReasonable(t *testing.T) {
	if DefaultUpdateIntervalHours >= LegacyUpdateIntervalHours {
		t.Fatalf("新默认 %d 未优于旧默认 %d",
			DefaultUpdateIntervalHours, LegacyUpdateIntervalHours)
	}
	if DefaultUpdateIntervalHours < 1 {
		t.Fatalf("间隔 %d 小时过于激进，会浪费 API 限额",
			DefaultUpdateIntervalHours)
	}
	perDay := 24 / DefaultUpdateIntervalHours
	if perDay > 24 {
		t.Fatalf("每天 %d 次检查过多", perDay)
	}
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
