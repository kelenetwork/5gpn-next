package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const transactionResultFile = stateDir + "/last-update-result.json"

// scheduleTransaction 把“替换 → 重启 → 验证 → 失败回退”交给独立的
// transient systemd unit。不能在 5gpn-next 自己的进程里 restart 后再验证：
// restart 会先杀掉调用者，后面的 sleep/验证/defer 永远不可能执行；生产中
// 每次升级遗留 update-* 目录正是这条错误执行模型的硬证据。
func scheduleTransaction(ctx context.Context, src, fallback, from, to, staging string) error {
	for _, p := range []string{src, fallback, staging} {
		if p == "" {
			return fmt.Errorf("更新事务路径为空")
		}
	}
	from = sanitizeTag(from)
	to = sanitizeTag(to)
	scriptPath := filepath.Join(staging, "transaction.sh")
	script := transactionScript(src, fallback, from, to, staging)
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return err
	}

	unit := fmt.Sprintf("5gpn-next-update-%d", time.Now().UnixNano())
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "systemd-run",
		"--quiet", "--collect", "--no-block",
		"--unit="+unit,
		"--property=Type=oneshot",
		"/bin/bash", scriptPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("启动独立更新事务失败: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func transactionScript(src, fallback, from, to, staging string) string {
	q := shellQuote
	return fmt.Sprintf(`#!/bin/bash
set -u
BIN=%s
SRC=%s
FALLBACK=%s
FROM=%s
TO=%s
STAGING=%s
RESULT=%s

write_result() {
  local status=$1
  local tmp="${RESULT}.tmp"
  printf '{"status":"%%s","from":"%%s","to":"%%s","at":%%s}\n' \
    "$status" "$FROM" "$TO" "$(date +%%s)" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$RESULT"
}
install_one() {
  cp -f "$1" "${BIN}.new" && chmod 755 "${BIN}.new" && mv -f "${BIN}.new" "$BIN"
}
version_ok() {
  [ "$("$BIN" version 2>/dev/null)" = "5gpn-next $1" ]
}
cleanup() {
  rm -rf "$STAGING"
}

# 给 Bot 留出发送“已校验，准备重启”确认消息的窗口。
sleep 5
if ! install_one "$SRC"; then
  write_result install_failed
  cleanup
  exit 1
fi
systemctl restart 5gpn-next.service >/dev/null 2>&1 || true
sleep 5
if systemctl is-active --quiet 5gpn-next.service && version_ok "$TO"; then
  write_result success
  cleanup
  exit 0
fi

# 新版本未稳定启动：由本 transient unit 在主服务之外完成真实回退。
if install_one "$FALLBACK"; then
  systemctl restart 5gpn-next.service >/dev/null 2>&1 || true
  sleep 5
  if systemctl is-active --quiet 5gpn-next.service && version_ok "$FROM"; then
    write_result rolled_back
    cleanup
    exit 1
  fi
fi
write_result rollback_failed
cleanup
exit 2
`, q(binPath), q(src), q(fallback), q(from), q(to), q(staging), q(transactionResultFile))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
