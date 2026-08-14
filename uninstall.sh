#!/bin/bash
# 5gpn-NEXT 卸载脚本
#
#   ./uninstall.sh           停服务、删 systemd 单元与防火墙规则，保留配置与证书
#   ./uninstall.sh --purge   连配置、规则集缓存、日志一起删除（证书仍保留）
#
# 证书由 certbot 管理，本脚本一律不动，避免影响同机其它服务。
set -uo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

say() { printf '  %s\n' "$*"; }

echo "==> 停止并禁用服务"
for u in 5gpn-next 5gpn-next-nft mihomo-5gpn; do
  if systemctl list-unit-files 2>/dev/null | grep -q "^${u}.service"; then
    systemctl disable --now "${u}.service" >/dev/null 2>&1 || true
    say "已停止 ${u}"
  fi
done

echo "==> 移除 systemd 单元"
for u in 5gpn-next 5gpn-next-nft mihomo-5gpn; do
  rm -f "/etc/systemd/system/${u}.service"
done
systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true

echo "==> 清理防火墙规则"
# 只删本项目加的规则，按 comment 精确定位，绝不整表 flush
for table in "inet 5gpn" "inet pdg"; do
  set -- $table
  fam=$1; tbl=$2
  nft list chain "$fam" "$tbl" input >/dev/null 2>&1 || continue
  while :; do
    handle=$(nft -a list chain "$fam" "$tbl" input 2>/dev/null \
      | grep '"5gpn-next"' | grep -oE 'handle [0-9]+' | head -1 | awk '{print $2}')
    [ -z "$handle" ] && break
    nft delete rule "$fam" "$tbl" input handle "$handle" 2>/dev/null || break
    say "已删除 ${fam} ${tbl} 规则 handle=${handle}"
  done
done
# 本项目自建的独立表可整表删除
if nft list table inet 5gpn >/dev/null 2>&1; then
  nft delete table inet 5gpn 2>/dev/null && say "已删除 nft 表 inet 5gpn"
fi

echo "==> 移除二进制"
rm -f /usr/local/bin/5gpnd /usr/local/bin/5gpnd.new
say "已删除 /usr/local/bin/5gpnd"
if [ -x /usr/local/bin/mihomo ] && [ ! -d /etc/mihomo ]; then
  rm -f /usr/local/bin/mihomo
  say "已删除 /usr/local/bin/mihomo（未发现其它 mihomo 配置）"
elif [ -x /usr/local/bin/mihomo ]; then
  say "保留 /usr/local/bin/mihomo（检测到 /etc/mihomo，可能被其它服务使用）"
fi

if [ "$PURGE" = "1" ]; then
  echo "==> 清除配置与数据（--purge）"
  rm -rf /etc/5gpn-next /etc/mihomo-5gpn /var/lib/5gpn-next /var/lib/mihomo-5gpn /var/log/5gpn-next
  say "已删除配置、规则集缓存与日志"
  say "证书未删除：如需清理请自行处理 /etc/letsencrypt"
else
  echo "==> 保留配置"
  say "配置仍在 /etc/5gpn-next，重装可直接复用"
  say "如需彻底清除：./uninstall.sh --purge"
fi

echo
echo "卸载完成。"
echo "提示：iPhone 上的描述文件需手动删除"
echo "      设置 → 通用 → VPN 与设备管理 → 5gpn-NEXT → 移除"
