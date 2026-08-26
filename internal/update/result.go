package update

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// TxResult 是独立升级事务落盘的最终结果。
type TxResult struct {
	Status string `json:"status"` // success | rolled_back | install_failed | rollback_failed
	From   string `json:"from"`
	To     string `json:"to"`
	At     int64  `json:"at"`
}

// historyFile 记录历次升级结果（JSON lines，追加写，最多保留 50 条）。
const historyFile = stateDir + "/update-history.jsonl"

// ConsumeLastResult 读取并删除上次升级事务的结果文件；同时把结果追加
// 进历史。返回 ok=false 表示没有待消费的结果（正常启动）。
//
// 必须消费式读取：结果只应通知一次，重启后不能反复推送同一条。
func ConsumeLastResult() (TxResult, bool) {
	b, err := os.ReadFile(transactionResultFile)
	if err != nil {
		return TxResult{}, false
	}
	_ = os.Remove(transactionResultFile)
	var r TxResult
	if err := json.Unmarshal(b, &r); err != nil || r.Status == "" {
		return TxResult{}, false
	}
	appendHistory(r)
	return r, true
}

func appendHistory(r TxResult) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	f, err := os.OpenFile(historyFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
	trimHistory(50)
}

func trimHistory(keep int) {
	b, err := os.ReadFile(historyFile)
	if err != nil {
		return
	}
	lines := splitLines(b)
	if len(lines) <= keep {
		return
	}
	out := []byte{}
	for _, l := range lines[len(lines)-keep:] {
		out = append(out, l...)
		out = append(out, '\n')
	}
	tmp := historyFile + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err == nil {
		_ = os.Rename(tmp, historyFile)
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// History 返回历史升级记录，新的在前，最多 limit 条。
func History(limit int) []TxResult {
	b, err := os.ReadFile(historyFile)
	if err != nil {
		return nil
	}
	var all []TxResult
	for _, l := range splitLines(b) {
		var r TxResult
		if err := json.Unmarshal(l, &r); err == nil && r.Status != "" {
			all = append(all, r)
		}
	}
	var out []TxResult
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out
}

// BackupInfo 是一个可回退版本的详情。
type BackupInfo struct {
	Tag     string
	SizeMB  float64
	ModTime time.Time
}

// Backups 返回可回退版本详情，新版本在前。
func (m *Manager) Backups() []BackupInfo {
	var out []BackupInfo
	for _, tag := range m.Versions() {
		info := BackupInfo{Tag: tag}
		if st, err := os.Stat(fmt.Sprintf("%s/5gpnd-%s", backupDir, sanitizeTag(tag))); err == nil {
			info.SizeMB = float64(st.Size()) / (1 << 20)
			info.ModTime = st.ModTime()
		}
		out = append(out, info)
	}
	return out
}
