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

// TestTwelveHourIntervalIsPreserved 12 小时是合法的显式选择，不得再被
// 当成「从未改过的旧默认」改写成 1。那会让想保持 12 小时的人保不住。
func TestTwelveHourIntervalIsPreserved(t *testing.T) {
	p := writeCfg(t, `{ "check_enabled": true, "interval_hours": 12, "auto_apply": false }`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if c.Update.IntervalHours != LegacyUpdateIntervalHours {
		t.Fatalf("显式 12 小时被改成了 %d", c.Update.IntervalHours)
	}
}

func TestTwelveHourIntervalIsNotRewrittenOnDisk(t *testing.T) {
	p := writeCfg(t, `{ "check_enabled": true, "interval_hours": 12, "auto_apply": false }`)
	changed, err := MigrateLegacyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("current-schema config with interval_hours=12 must not be rewritten")
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
	if raw.Update.IntervalHours != LegacyUpdateIntervalHours {
		t.Fatalf("persisted interval=%d, want 12", raw.Update.IntervalHours)
	}
}

// TestExplicitIntervalPreserved 用户显式设置的间隔不得被覆盖，包括 12。
func TestExplicitIntervalPreserved(t *testing.T) {
	for _, want := range []int{1, 2, 6, 12, 24, 48} {
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

func TestExampleConfigUsesNewInterval(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Update UpdateConfig `json:"update"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Update.IntervalHours != DefaultUpdateIntervalHours {
		t.Fatalf("config.example.json interval_hours=%d, want %d",
			raw.Update.IntervalHours, DefaultUpdateIntervalHours)
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
