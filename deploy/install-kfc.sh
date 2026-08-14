#!/bin/bash
# 部署 5gpn-next 到 KFC 机的 :20444（与 P0 探针 :20443 并存，互不影响）
set -euo pipefail

BIN=/usr/local/bin/5gpnd
UNIT=5gpn-next
CFGDIR=/etc/5gpn-next
BK=/root/backups/5gpn-next-install-$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$BK"
nft list ruleset > "$BK/nftables.ruleset.before"
systemctl list-units --type=service --state=running --no-pager --plain > "$BK/services.before" 2>/dev/null || true
echo "BACKUP=$BK"

# 1. 二进制上位
if [ -f "${BIN}.new" ]; then
  systemctl stop ${UNIT}.service 2>/dev/null || true
  mv -f "${BIN}.new" "$BIN"
fi
chmod 755 "$BIN"
"$BIN" version

# 2. 目录
install -d -m 700 "$CFGDIR"
install -d -m 755 /var/lib/5gpn-next/rulesets
install -d -m 755 /var/log/5gpn-next
chmod 600 "$CFGDIR/config.json"

# 3. nft 放行 20444（仅内网卡段）
if nft list chain inet pdg input >/dev/null 2>&1; then
  if nft list chain inet pdg input | grep -q '20444'; then
    echo "NFT_20444_EXISTS"
  else
    nft add rule inet pdg input ip saddr 172.22.0.0/16 tcp dport 20444 accept comment '"5gpn-next"'
    echo "NFT_20444_ADDED"
  fi
fi

# 4. nft 幂等补回脚本（pdg 重建表会丢规则）
cat > /etc/5gpn-next/nft-restore.sh <<'EOF'
#!/bin/bash
set -uo pipefail
nft list chain inet pdg input >/dev/null 2>&1 || exit 0
nft list chain inet pdg input | grep -q '20444' && exit 0
nft add rule inet pdg input ip saddr 172.22.0.0/16 tcp dport 20444 accept comment '"5gpn-next"'
EOF
chmod 755 /etc/5gpn-next/nft-restore.sh

cat > /etc/systemd/system/5gpn-next-nft.service <<'EOF'
[Unit]
Description=5gpn-next nft allow rule (idempotent)
After=nftables.service
Wants=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/5gpn-next/nft-restore.sh

[Install]
WantedBy=multi-user.target
EOF

# 5. 主服务
cat > /etc/systemd/system/${UNIT}.service <<'EOF'
[Unit]
Description=5gpn-NEXT gateway (Apple Network Relay)
Documentation=https://github.com/kelenetwork/5gpn-next
After=network-online.target
Wants=network-online.target
StartLimitBurst=10
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/5gpnd run -c /etc/5gpn-next/config.json
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
MemoryMax=256M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now 5gpn-next-nft.service >/dev/null 2>&1
systemctl enable --now ${UNIT}.service >/dev/null 2>&1

sleep 4
echo "--- state ---"
systemctl is-active ${UNIT}.service || true
systemctl is-enabled ${UNIT}.service || true
echo "--- listener ---"
ss -lntp | grep -E '20443|20444' || echo NOT_LISTENING
echo "--- startup log ---"
journalctl -u ${UNIT}.service -n 12 --no-pager | tail -12
