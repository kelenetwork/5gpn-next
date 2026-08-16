#!/bin/bash
# 5gpn-NEXT 一键安装
#
#   curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/install.sh | sudo bash
#
# 非交互安装（所有变量可预置）：
#   sudo FGPN_DOMAIN=gw.example.com \
#        FGPN_EMAIL=you@example.com \
#        FGPN_NODE='ss://...' \
#        FGPN_NONINTERACTIVE=1 bash install.sh
#
# 本脚本只做四件事：装二进制、签证书、写配置、起服务。
# 所有业务逻辑在 5gpnd 里，脚本保持可读。
set -euo pipefail

REPO="kelenetwork/5gpn-next"
MIHOMO_VER="v1.19.29"
CLIENT_CIDR="${FGPN_CLIENT_CIDR:-172.22.0.0/16}"
LISTEN_PORT="${FGPN_PORT:-20443}"

CFGDIR=/etc/5gpn-next
LIBDIR=/var/lib/5gpn-next
LOGDIR=/var/log/5gpn-next

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
ok()   { printf '%s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
die()  { printf '%s✗%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }
step() { printf '\n%s==>%s %s\n' "$C_OK" "$C_OFF" "$*"; }
dim()  { printf '%s  %s%s\n' "$C_DIM" "$*" "$C_OFF"; }

[ "$(id -u)" = "0" ] || die "需要 root 权限，请用 sudo 运行"

# ---------------------------------------------------------------- 0. 环境检查
step "检查运行环境"

. /etc/os-release 2>/dev/null || die "无法识别操作系统"
case "${ID:-}" in
  debian|ubuntu) ok "系统 $PRETTY_NAME" ;;
  *) warn "未在 $PRETTY_NAME 上测试过，继续但可能需要手动调整" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "不支持的架构：$ARCH（仅支持 x86_64 / aarch64）" ;;
esac
ok "架构 $ARCH"

MEM_MB=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
[ "$MEM_MB" -ge 400 ] || warn "内存仅 ${MEM_MB}MB，建议 512MB 以上"
ok "内存 ${MEM_MB}MB"

# 缺依赖时自动安装。裸系统（尤其容器/云镜像）常常没有 nftables，
# 让用户先手执行一遍 apt 再回来跑安装器是多余的——脚本已经是 root，
# 且后面签证书时本来就会自动装 certbot，前后行为应当一致。
MISSING_PKGS=""
need_pkg() {  # need_pkg <命令> <包名>
  command -v "$1" >/dev/null 2>&1 && return 0
  case " $MISSING_PKGS " in
    *" $2 "*) ;;
    *) MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }$2" ;;
  esac
}

need_pkg curl curl
need_pkg nft nftables

if [ -n "$MISSING_PKGS" ]; then
  command -v apt-get >/dev/null 2>&1 \
    || die "缺少依赖：$MISSING_PKGS，且本系统无 apt-get，请手动安装后重试"
  dim "安装缺少依赖：$MISSING_PKGS"
  apt-get update -qq >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING_PKGS >/dev/null 2>&1 || true
  for c in curl nft; do
    command -v "$c" >/dev/null 2>&1 \
      || die "依赖 $c 自动安装失败，请手动执行：apt install -y $MISSING_PKGS"
  done
  ok "已自动安装：$MISSING_PKGS"
fi

# systemctl 属于 init 系统，装不了，只能明确报错。
command -v systemctl >/dev/null 2>&1 \
  || die "未找到 systemctl：本安装器仅支持 systemd 系统（容器环境请改用宿主机或支持 systemd 的镜像）"

ok "依赖齐全"

# ---------------------------------------------------------------- 1. 收集参数
step "配置参数"

ask() {  # ask <变量名> <提示> <默认值>
  local __var=$1 __prompt=$2 __default=${3:-} __val
  __val=$(eval "printf '%s' \"\${$__var:-}\"")
  if [ -n "$__val" ]; then printf '%s' "$__val"; return; fi
  if [ "${FGPN_NONINTERACTIVE:-0}" = "1" ]; then printf '%s' "$__default"; return; fi
  if [ -n "$__default" ]; then
    read -r -p "  $__prompt [$__default]: " __val </dev/tty || true
    printf '%s' "${__val:-$__default}"
  else
    read -r -p "  $__prompt: " __val </dev/tty || true
    printf '%s' "$__val"
  fi
}

PUBIP=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
[ -n "$PUBIP" ] && dim "本机公网 IP：$PUBIP"

DOMAIN=$(FGPN_DOMAIN="${FGPN_DOMAIN:-}" ask FGPN_DOMAIN "网关域名（需已 A 记录指向本机）")
[ -n "$DOMAIN" ] || die "域名不能为空"

echo
dim "证书邮箱：用于接收证书到期提醒，可留空。"
EMAIL=$(FGPN_EMAIL="${FGPN_EMAIL:-}" ask FGPN_EMAIL "证书邮箱" "")
if [ -z "$EMAIL" ]; then
  CERT_EMAIL_ARG="--register-unsafely-without-email"
  dim "未填写邮箱，将以无邮箱方式注册（收不到到期提醒）"
else
  CERT_EMAIL_ARG="--email $EMAIL"
fi

echo
dim "落地节点：外网流量的出口。留空则由本机直出（被墙目标将无法访问）。"
dim "支持 ss:// vmess:// vless:// trojan:// hysteria2:// 等 mihomo 可解析的链接。"
NODE=$(FGPN_NODE="${FGPN_NODE:-}" ask FGPN_NODE "落地节点链接（可留空）")

echo
dim "Telegram Bot：在聊天窗口查看状态、增删出口、改分流、跑诊断、收告警。"
dim "先找 @BotFather 建 Bot 拿 Token，再找 @userinfobot 查你的数字 ID。"
BOT_TK=$(FGPN_BOT_TOKEN="${FGPN_BOT_TOKEN:-}" ask FGPN_BOT_TOKEN "Bot Token（可留空跳过）")
BOT_IDS=""
if [ -n "$BOT_TK" ]; then
  BOT_IDS=$(FGPN_BOT_ADMINS="${FGPN_BOT_ADMINS:-}" ask FGPN_BOT_ADMINS "你的 Telegram 数字 ID（多个用英文逗号分隔）")
  if [ -z "$BOT_IDS" ]; then
    warn "未填写管理员 ID，Bot 不会响应任何人，已跳过 Bot 配置"
    BOT_TK=""
  fi
fi

# iOS 蜂窝加密 DNS 与 Android 私人 DNS 共用同一套接入与分流策略。
DNS_ON=true

# 域名解析校验
RESOLVED=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
if [ -z "$RESOLVED" ]; then
  die "域名 $DOMAIN 无法解析。请先添加 A 记录指向本机（Cloudflare 须用「仅 DNS / 灰云」）"
elif [ -n "$PUBIP" ] && [ "$RESOLVED" != "$PUBIP" ]; then
  warn "域名解析到 $RESOLVED，与本机 $PUBIP 不一致"
  warn "若使用 Cloudflare，请确认已关闭橙云代理（证书签发需要）"
  [ "${FGPN_NONINTERACTIVE:-0}" = "1" ] || {
    read -r -p "  仍要继续？[y/N]: " yn </dev/tty || true
    case "${yn:-N}" in y|Y) ;; *) die "已取消" ;; esac
  }
else
  ok "域名 $DOMAIN → $RESOLVED"
fi

# ---------------------------------------------------------------- 2. 装二进制
step "安装 5gpnd"

TAG=$(curl -fsS --max-time 20 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)

install -d -m 755 /usr/local/bin
if [ -n "$TAG" ]; then
  URL="https://github.com/${REPO}/releases/download/${TAG}/5gpnd-linux-${GOARCH}"
  if curl -fsSL --max-time 120 "$URL" -o /usr/local/bin/5gpnd.new 2>/dev/null; then
    mv -f /usr/local/bin/5gpnd.new /usr/local/bin/5gpnd
    chmod 755 /usr/local/bin/5gpnd
    ok "5gpnd $TAG 已安装"
  else
    rm -f /usr/local/bin/5gpnd.new
    TAG=""
  fi
fi
if [ -z "$TAG" ]; then
  command -v go >/dev/null 2>&1 || die "未找到发布版且本机无 Go，无法安装。请先安装 Go 1.23+ 或等待 release 发布"
  warn "未找到发布版，从源码构建"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp" --strip-components=1
  ( cd "$tmp" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/5gpnd ./cmd/5gpnd )
  chmod 755 /usr/local/bin/5gpnd
  ok "已从源码构建"
fi
/usr/local/bin/5gpnd version 2>&1 | sed -n '1p' | sed 's/^/  /'

# ---------------------------------------------------------------- 3. 证书
step "申请 TLS 证书"

install -d -m 700 "$CFGDIR"
install -d -m 755 "$LIBDIR/rulesets" "$LOGDIR"

CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

if [ -s "$CERT" ] && [ -s "$KEY" ]; then
  ok "已存在证书，跳过签发"
else
  command -v certbot >/dev/null 2>&1 || {
    dim "安装 certbot..."
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null 2>&1 \
      || die "certbot 安装失败，请手动安装后重试"
  }
  # HTTP-01 需要 80 端口，临时放行
  nft list chain inet fgpn input >/dev/null 2>&1 && \
    nft add rule inet fgpn input tcp dport 80 accept comment '"5gpn-acme-tmp"' 2>/dev/null || true

  # shellcheck disable=SC2086
  certbot certonly --standalone --non-interactive --agree-tos \
    $CERT_EMAIL_ARG -d "$DOMAIN" --keep-until-expiring >/dev/null 2>&1 \
    || die "证书签发失败。请确认：域名已指向本机、80 端口公网可达、云厂商安全组已放行 80"
  ok "证书签发成功"
fi

# ---------------------------------------------------------------- 4. 落地节点
step "配置出口"

EGRESS_JSON='{ "name": "DIRECT", "type": "direct" }'
FINAL="direct"

if [ -n "$NODE" ]; then
  umask 077
  printf '%s\n' "$NODE" > "$CFGDIR/node.link"
  chmod 600 "$CFGDIR/node.link"

  if [ ! -x /usr/local/bin/mihomo ]; then
    dim "下载 mihomo $MIHOMO_VER..."
    tmpm=$(mktemp -d)
    curl -fsSL --max-time 180 \
      "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${GOARCH}-${MIHOMO_VER}.gz" \
      -o "$tmpm/m.gz" || die "mihomo 下载失败"
    gunzip -c "$tmpm/m.gz" > /usr/local/bin/mihomo
    chmod 755 /usr/local/bin/mihomo
    rm -rf "$tmpm"
  fi
  ok "mihomo $(/usr/local/bin/mihomo -v 2>&1 | sed -n '1p' | awk '{print $3}')"

  install -d -m 700 /etc/mihomo-5gpn
  install -d -m 750 /var/lib/mihomo-5gpn

  /usr/local/bin/5gpnd node-config \
    -link "$CFGDIR/node.link" \
    -out /etc/mihomo-5gpn/config.yaml \
    -socks 7891 || die "节点链接解析失败，请检查格式"
  chmod 600 /etc/mihomo-5gpn/config.yaml

  /usr/local/bin/mihomo -t -d /var/lib/mihomo-5gpn -f /etc/mihomo-5gpn/config.yaml >/dev/null 2>&1 \
    || die "mihomo 配置校验失败"

  cat > /etc/systemd/system/mihomo-5gpn.service <<'EOF'
[Unit]
Description=mihomo egress for 5gpn-next
Documentation=https://github.com/MetaCubeX/mihomo
After=network-online.target
Wants=network-online.target
StartLimitBurst=10
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/local/bin/mihomo -d /var/lib/mihomo-5gpn -f /etc/mihomo-5gpn/config.yaml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/mihomo-5gpn
MemoryMax=192M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now mihomo-5gpn.service >/dev/null 2>&1
  sleep 2
  systemctl is-active --quiet mihomo-5gpn.service || die "mihomo 启动失败：journalctl -u mihomo-5gpn -n 30"

  EXIT_IP=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:7891 https://api.ipify.org 2>/dev/null || echo "")
  if [ -n "$EXIT_IP" ] && [ "$EXIT_IP" != "$PUBIP" ]; then
    ok "出口已生效：$EXIT_IP"
  elif [ -n "$EXIT_IP" ]; then
    warn "出口 IP 与本机相同（$EXIT_IP），节点可能未生效"
  else
    warn "出口连通性测试失败，稍后可用 5gpnd probe 排查"
  fi

  EGRESS_JSON='{ "name": "DIRECT", "type": "direct" },
    { "name": "node", "type": "socks5", "addr": "127.0.0.1:7891", "has_ipv6": false }'
  # 只登记节点，不在安装阶段擅自切换国外默认出口。
  # 用户应在 Bot/面板确认国内规则与节点连通均正常后再切换。
  FINAL="direct"
  warn "节点已添加；国外默认出口仍为 DIRECT，请在 Bot/面板验证后手动切换"
else
  warn "未配置落地节点，国外流量将由本机 DIRECT 直出"
fi

# 加密 DNS 接入需要一个“客户端可路由到”的网关地址写入 DNS 应答。
# 优先取落在客户端网段内的本机地址；没有则回退公网 IP。
GW_IP=""
if [ "$DNS_ON" = "true" ]; then
  CPFX=${CLIENT_CIDR%%/*}
  CPFX=${CPFX%.*.*}
  GW_IP=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
          | grep "^${CPFX}\." | head -1 || true)
  if [ -z "$GW_IP" ]; then
    GW_IP="$PUBIP"
    warn "未发现属于 ${CLIENT_CIDR} 的本机地址，加密 DNS 网关地址回退为 ${GW_IP}"
    warn "若手机无法访问该地址，请手工修改 config.json 的 dns.gateway_ip"
  else
    ok "加密 DNS 网关地址：${GW_IP}"
  fi
fi

# ---------------------------------------------------------------- 5. 写配置
step "生成配置"

DLPATH="/dl/$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')/5gpn-next.mobileconfig"

# 重装时沿用既有描述文件下载路径，避免用户保存的安装链接失效。
# 同时兼容新版 gateway 与旧版 relay 配置键。
if [ -s "$CFGDIR/config.json" ]; then
  OLD_DLPATH=$(python3 -c 'import json,sys;c=json.load(open(sys.argv[1]));print((c.get("gateway") or c.get("relay") or {}).get("profile_path",""))' "$CFGDIR/config.json" 2>/dev/null || true)
  if [ -z "$OLD_DLPATH" ]; then
    OLD_DLPATH=$(sed -n 's/.*"profile_path": *"\([^"]*\)".*/\1/p' "$CFGDIR/config.json" | head -1)
  fi
  if [ -n "$OLD_DLPATH" ]; then
    DLPATH="$OLD_DLPATH"
  fi
fi
# Bot 管理员 JSON 数组
BOT_IDS_JSON=$(printf '%s' "$BOT_IDS" | tr -d ' ' | sed 's/,\{2,\}/,/g; s/^,//; s/,$//')

if [ -s "$CFGDIR/config.json" ]; then
  cp -a "$CFGDIR/config.json" "$CFGDIR/config.json.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  dim "已备份原配置"
fi

cat > "$CFGDIR/config.json" <<EOF
{
  "gateway": {
    "listen": ":${LISTEN_PORT}",
    "host": "${DOMAIN}",
    "cert_file": "${CERT}",
    "key_file": "${KEY}",
    "profile_path": "${DLPATH}"
  },
  "egress": [
    ${EGRESS_JSON}
  ],
  "rules": [],
  "final": "${FINAL}",
  "rulesets": [
    {
      "name": "cn-domain",
      "kind": "domain",
      "interval_hours": 24,
      "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
    },
    {
      "name": "geoip:cn",
      "kind": "ipcidr",
      "interval_hours": 24,
      "url": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"
    }
  ],
  "bot": {
    "token": "${BOT_TK}",
    "admins": [${BOT_IDS_JSON}]
  },
  "panel": {
    "enabled": true
  },
  "dns": {
    "enabled": ${DNS_ON},
    "dot_listen": ":853",
    "gateway_ip": "${GW_IP}",
    "http_listen": ":80",
    "tls_listen": ":443",
    "upstream": ["223.5.5.5:53", "119.29.29.29:53"]
  },
  "update": {
    "check_enabled": true,
    "interval_hours": 12,
    "auto_apply": false
  },
  "client_cidr": "${CLIENT_CIDR}",
  "log_path": "${LOGDIR}/trace.jsonl"
}
EOF
chmod 600 "$CFGDIR/config.json"
/usr/local/bin/5gpnd check -c "$CFGDIR/config.json" >/dev/null 2>&1 || die "配置校验失败"
ok "配置已写入 $CFGDIR/config.json"

# ---------------------------------------------------------------- 6. 防火墙
step "配置防火墙"

DNS_NFT=""
if [ "$DNS_ON" = "true" ]; then
  # QUIC（UDP 443）由网关接管：解析 Initial 包的 SNI 后按策略转发。
  # 旧版在此 reject 指望客户端回落 TCP，但 Google Play 下载器不回落，
  # 只会无限重试，表现为「下载永远等待中」，因此必须放行。
  DNS_NFT=$(cat <<NFTEOF
    ip saddr ${CLIENT_CIDR} tcp dport { 53, 80, 443, 853 } accept comment "5gpn-dns"
    ip saddr ${CLIENT_CIDR} udp dport 53 accept comment "5gpn-dns"
    ip saddr ${CLIENT_CIDR} udp dport 443 accept comment "5gpn-quic-takeover"
NFTEOF
)
  DNS_NFT="${DNS_NFT}
"
fi

# 使用独立表，不触碰其它表（Docker / fail2ban / 既有规则均不受影响）
# 表名必须以字母开头：nftables 标识符不允许数字开头，"5gpn" 会解析失败
nft list table inet fgpn >/dev/null 2>&1 && nft delete table inet fgpn 2>/dev/null || true
nft -f - <<EOF
table inet fgpn {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr ${CLIENT_CIDR} tcp dport ${LISTEN_PORT} accept comment "5gpn-next"
${DNS_NFT}  }
}
EOF
ok "已放行 ${LISTEN_PORT}/tcp（仅来源 ${CLIENT_CIDR}）"
if [ "$DNS_ON" = "true" ]; then
  ok "已放行 853/80/443（加密 DNS 接入，仅来源 ${CLIENT_CIDR}）"
fi

cat > "$CFGDIR/nft-restore.sh" <<EOF
#!/bin/bash
# 幂等补回放行规则（开机及防火墙重载后执行）
set -uo pipefail
nft list table inet fgpn >/dev/null 2>&1 && exit 0
nft -f - <<'RULES'
table inet fgpn {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr ${CLIENT_CIDR} tcp dport ${LISTEN_PORT} accept comment "5gpn-next"
${DNS_NFT}  }
}
RULES
EOF
chmod 755 "$CFGDIR/nft-restore.sh"

cat > /etc/systemd/system/5gpn-next-nft.service <<'EOF'
[Unit]
Description=5gpn-next firewall rule (idempotent)
After=nftables.service
Wants=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/5gpn-next/nft-restore.sh

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- 7. 起服务
step "启动服务"

cat > /etc/systemd/system/5gpn-next.service <<'EOF'
[Unit]
Description=5gpn-NEXT encrypted DNS gateway
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
ReadWritePaths=/var/lib/5gpn-next /var/log/5gpn-next
# 内存上限必须同时容纳 Go 堆与内核侧记账。生产实测 OOM 现场：
#   anon 132MB（Go 堆）+ slab_unreclaimable 123MB（socket 缓冲等
#   内核对象）= 255MB，恰好卡死在旧的 256M 门槛上。
# 内核 slab 不受 GOMEMLIMIT 约束，也无法由应用侧回收，只能预留额度。
MemoryMax=512M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now 5gpn-next-nft.service >/dev/null 2>&1
systemctl enable --now 5gpn-next.service >/dev/null 2>&1
sleep 4

systemctl is-active --quiet 5gpn-next.service \
  || die "启动失败，请查看：journalctl -u 5gpn-next -n 40 --no-pager"
ok "5gpn-next 已启动"

# 证书续期后自动重载
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || true
cat > /etc/letsencrypt/renewal-hooks/deploy/5gpn-next.sh <<'EOF'
#!/bin/bash
systemctl is-active --quiet 5gpn-next.service && systemctl restart 5gpn-next.service
exit 0
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/5gpn-next.sh 2>/dev/null || true

# ---------------------------------------------------------------- 8. 自检
step "安装自检"

for t in weibo.com chatgpt.com; do
  if /usr/local/bin/5gpnd probe -c "$CFGDIR/config.json" "$t" >/dev/null 2>&1; then
    ok "$t 可达"
  else
    warn "$t 诊断未通过，稍后运行：5gpnd probe -c $CFGDIR/config.json $t"
  fi
done

if [ -n "$BOT_TK" ]; then
  BOT_HINT="已启用。向你的 Bot 发送 /start 打开菜单。"
else
  BOT_HINT="未配置。如需启用：编辑 ${CFGDIR}/config.json 的 bot 段，再 systemctl restart 5gpn-next"
fi

# ---------------------------------------------------------------- 完成
cat <<EOF

$(printf '%s' "$C_OK")━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(printf '%s' "$C_OFF")

  安装完成

  Android
    设置 → 网络和互联网 → 私人 DNS
    选择「指定的私人 DNS 服务提供商主机名」，填入：
    ${DOMAIN}

  iPhone / iPad（iOS 17+）
    用 Safari 打开以下链接安装描述文件（须走内网卡蜂窝数据）：

    https://${DOMAIN}:${LISTEN_PORT}${DLPATH}

    安装后：设置 → 通用 → VPN 与设备管理 → 安装描述文件

  内网 Web 面板
    https://${DOMAIN}:${LISTEN_PORT}/
    手机连内网卡直接打开，无需登录；仅内网卡来源可访问，公网无法连接。

  Telegram Bot
    ${BOT_HINT}

  常用命令
    5gpnd probe -c ${CFGDIR}/config.json <域名>   诊断某个目标
    systemctl status 5gpn-next                    查看状态
    journalctl -u 5gpn-next -f                    实时日志
    tail -f ${LOGDIR}/trace.jsonl                 决策记录

  重要提示
    · 描述文件链接含随机串，等同密码，请勿外传
    · 该链接仅内网卡来源可访问（${CLIENT_CIDR}）
    · 卸载：curl -fsSL https://raw.githubusercontent.com/${REPO}/main/uninstall.sh | sudo bash

$(printf '%s' "$C_OK")━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(printf '%s' "$C_OFF")

EOF
