// Package trace 提供连接级决策链路追踪。
//
// 设计动机来自 P0 实测：WhatsApp 商业版注册失败时，用户只看到
// "没有互联网连接"，而真实原因是「出口无 IPv6 + 拨号超时过长」。
// 没有分层 trace，这种问题无法自助定位。
package trace

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Stage 是链路中的一层。
type Stage string

const (
	StageIngress Stage = "ingress" // 入口：DoT / 本地诊断
	StagePolicy  Stage = "policy"  // 策略：命中哪条规则
	StageEgress  Stage = "egress"  // 出口：选中哪个落地
	StageConnect Stage = "connect" // 连接：TCP 建立
	StageApp     Stage = "app"     // 应用：TLS / 首字节
)

// Status 是每层的结果。
type Status string

const (
	StatusOK      Status = "ok"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
	// StatusWarn 表示该层可继续，但存在需要用户知晓的隐患。
	// 例如策略要求走代理却未配置任何代理出口。
	StatusWarn Status = "warn"
)

// Step 是一层的记录。
type Step struct {
	Stage  Stage   `json:"stage"`
	Status Status  `json:"status"`
	Detail string  `json:"detail"`
	DurMS  float64 `json:"dur_ms"`
	Err    string  `json:"err,omitempty"`
}

// Trace 汇总一次连接的全部决策。
type Trace struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Client string `json:"client,omitempty"`

	mu    sync.Mutex
	steps []Step
	start time.Time
	last  time.Time
}

// New 开始一次追踪。
func New(id, target, client string) *Trace {
	now := time.Now()
	return &Trace{
		ID:     id,
		Target: target,
		Client: client,
		start:  now,
		last:   now,
	}
}

// Step 记录一层结果，耗时自上一层结束起算。
func (t *Trace) Step(s Stage, st Status, format string, args ...any) {
	if t == nil {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.steps = append(t.steps, Step{
		Stage:  s,
		Status: st,
		Detail: fmt.Sprintf(format, args...),
		DurMS:  float64(now.Sub(t.last).Microseconds()) / 1000,
	})
	t.last = now
}

// Fail 记录失败层。
func (t *Trace) Fail(s Stage, err error, format string, args ...any) {
	if t == nil {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := ""
	if err != nil {
		e = err.Error()
	}
	t.steps = append(t.steps, Step{
		Stage:  s,
		Status: StatusFail,
		Detail: fmt.Sprintf(format, args...),
		DurMS:  float64(now.Sub(t.last).Microseconds()) / 1000,
		Err:    e,
	})
	t.last = now
}

// Steps 返回步骤快照。
func (t *Trace) Steps() []Step {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Step, len(t.steps))
	copy(out, t.steps)
	return out
}

// TotalMS 返回总耗时。
func (t *Trace) TotalMS() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return float64(time.Since(t.start).Microseconds()) / 1000
}

// OK 表示没有任何一层失败。
func (t *Trace) OK() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.steps {
		if s.Status == StatusFail {
			return false
		}
	}
	return true
}

// JSON 序列化为一行结构化日志。
func (t *Trace) JSON() []byte {
	type out struct {
		TS      string  `json:"ts"`
		ID      string  `json:"id"`
		Target  string  `json:"target"`
		Client  string  `json:"client,omitempty"`
		OK      bool    `json:"ok"`
		TotalMS float64 `json:"total_ms"`
		Steps   []Step  `json:"steps"`
	}
	b, _ := json.Marshal(out{
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		ID:      t.ID,
		Target:  t.Target,
		Client:  t.Client,
		OK:      t.OK(),
		TotalMS: t.TotalMS(),
		Steps:   t.Steps(),
	})
	return b
}

// Human 渲染为 probe 命令的可读输出。
func (t *Trace) Human() string {
	icon := map[Status]string{
		StatusOK:      "✅",
		StatusFail:    "❌",
		StatusSkipped: "⏭",
		StatusWarn:    "⚠️",
	}
	s := ""
	for i, st := range t.Steps() {
		name := map[Stage]string{
			StageIngress: "入口",
			StagePolicy:  "策略",
			StageEgress:  "出口",
			StageConnect: "连接",
			StageApp:     "应用",
		}[st.Stage]
		if name == "" {
			name = string(st.Stage)
		}
		s += fmt.Sprintf("[%d] %-4s %-46s %s %7.1fms\n",
			i+1, name, truncate(st.Detail, 46), icon[st.Status], st.DurMS)
		if st.Err != "" {
			s += fmt.Sprintf("        └─ %s\n", st.Err)
		}
	}
	verdict := "正常"
	if !t.OK() {
		verdict = "失败"
	}
	s += fmt.Sprintf("结论：%s（总计 %.1fms）\n", verdict, t.TotalMS())
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
