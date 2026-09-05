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
# 已有 /etc/5gpn-next/config.json 时默认保留配置，只更新程序与服务。
# 强制重写配置：FGPN_FORCE_RECONFIG=1
#
# 本脚本只做四件事：装二进制、签证书、写配置、起服务。
# 所有业务逻辑在 5gpnd 里，脚本保持可读。
# Release 二进制必须通过 SHA256SUMS 校验后才会落地。
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

remove_acme_nft_rules() {
  local handle
  while read -r handle; do
    [ -n "$handle" ] || continue
    nft delete rule inet fgpn input handle "$handle" 2>/dev/null || true
  done < <(nft -a list chain inet fgpn input 2>/dev/null \
    | awk '/comment "5gpn-acme-tmp"/ { for (i=1; i<=NF; i++) if ($i=="handle") print $(i+1) }')
}

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
need_pkg sha256sum coreutils
need_pkg python3 python3

if [ -n "$MISSING_PKGS" ]; then
  command -v apt-get >/dev/null 2>&1 \
    || die "缺少依赖：$MISSING_PKGS，且本系统无 apt-get，请手动安装后重试"
  dim "安装缺少依赖：$MISSING_PKGS"
  apt-get update -qq >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING_PKGS >/dev/null 2>&1 || true
  for c in curl nft sha256sum python3; do
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

# 读取已有配置的关键字段。失败返回非 0，调用方不得覆盖原文件。
read_existing_config() {
  local cfg="$1"
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$cfg" <<'PY'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
g = c.get("gateway") or c.get("relay") or {}
d = c.get("dns") or c.get("android") or {}
host = (g.get("host") or "").strip()
listen = (g.get("listen") or ":20443").strip() or ":20443"
port = listen.rsplit(":", 1)[-1]
if not port.isdigit():
    port = "20443"
cidr = (c.get("client_cidr") or "172.22.0.0/16").strip()
dns_on = "true" if d.get("enabled", True) else "false"
if not host or not cidr:
    sys.exit(1)
path = (g.get("profile_path") or "").strip()
print(host)
print(port)
print(cidr)
print(dns_on)
print(path)
PY
}


# 把首次安装配置写成合法 JSON。用户输入一律经 json 编码，先写临时文件再 mv。
write_config_json() {
  local out="$1" tmp rc
  tmp=$(mktemp "${out}.XXXXXX") || return 1
  FGPN_WRITE_DOMAIN="$DOMAIN" \
  FGPN_WRITE_LISTEN_PORT="$LISTEN_PORT" \
  FGPN_WRITE_CERT="$CERT" \
  FGPN_WRITE_KEY="$KEY" \
  FGPN_WRITE_DLPATH="$DLPATH" \
  FGPN_WRITE_CLIENT_CIDR="$CLIENT_CIDR" \
  FGPN_WRITE_DNS_ON="$DNS_ON" \
  FGPN_WRITE_GW_IP="${GW_IP:-}" \
  FGPN_WRITE_LOGDIR="$LOGDIR" \
  FGPN_WRITE_BOT_TOKEN="${BOT_TK:-}" \
  FGPN_WRITE_BOT_IDS="${BOT_IDS:-}" \
  FGPN_WRITE_HAS_NODE="${HAS_NODE:-0}" \
  python3 - "$tmp" <<'PY'
import json, os, sys

path = sys.argv[1]

def env(name):
    return os.environ.get(name, "")

domain = env("FGPN_WRITE_DOMAIN")
listen_port = env("FGPN_WRITE_LISTEN_PORT") or "20443"
cert = env("FGPN_WRITE_CERT")
key = env("FGPN_WRITE_KEY")
dlpath = env("FGPN_WRITE_DLPATH")
client_cidr = env("FGPN_WRITE_CLIENT_CIDR")
dns_on = env("FGPN_WRITE_DNS_ON").lower() == "true"
gw_ip = env("FGPN_WRITE_GW_IP")
logdir = env("FGPN_WRITE_LOGDIR")
bot_token = env("FGPN_WRITE_BOT_TOKEN")
bot_ids = env("FGPN_WRITE_BOT_IDS")
has_node = env("FGPN_WRITE_HAS_NODE") == "1"

admins = []
if bot_token:
    raw = bot_ids.replace(" ", "")
    if not raw:
        bot_token = ""
    else:
        seen = set()
        for part in raw.split(","):
            if part == "":
                continue
            if not part.isdigit():
                sys.stderr.write("管理员 ID 必须是正整数，收到 %r\n" % part)
                sys.exit(2)
            n = int(part)
            if n <= 0:
                sys.stderr.write("管理员 ID 必须是正整数，收到 %r\n" % part)
                sys.exit(2)
            if n in seen:
                sys.stderr.write("管理员 ID 重复: %s\n" % n)
                sys.exit(2)
            seen.add(n)
            admins.append(n)
        if not admins:
            bot_token = ""

egress = [{"name": "DIRECT", "type": "direct"}]
if has_node:
    egress.append({
        "name": "node",
        "type": "socks5",
        "addr": "127.0.0.1:7891",
        "has_ipv6": False,
    })

cfg = {
    "gateway": {
        "listen": ":" + listen_port,
        "host": domain,
        "cert_file": cert,
        "key_file": key,
        "profile_path": dlpath,
    },
    "egress": egress,
    "rules": [],
    "final": "direct",
    "rulesets": [
        {
            "name": "cn-domain",
            "kind": "domain",
            "interval_hours": 24,
            "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        },
        {
            "name": "geoip:cn",
            "kind": "ipcidr",
            "interval_hours": 24,
            "url": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
        },
    ],
    "bot": {"token": bot_token, "admins": admins},
    "panel": {"enabled": True},
    "dns": {
        "enabled": dns_on,
        "dot_listen": ":853",
        "gateway_ip": gw_ip,
        "http_listen": ":80",
        "tls_listen": ":443",
        "upstream": ["223.5.5.5:53", "119.29.29.29:53"],
    },
    "update": {
        "check_enabled": True,
        "interval_hours": 1,
        "auto_apply": False,
    },
    "client_cidr": client_cidr,
    "log_path": "%s/trace.jsonl" % logdir,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
  rc=$?
  if [ "$rc" -ne 0 ]; then
    rm -f "$tmp"
    return "$rc"
  fi
  chmod 600 "$tmp"
  mv -f "$tmp" "$out"
}

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

REUSE_CONFIG=0
if [ -s "$CFGDIR/config.json" ] && [ "${FGPN_FORCE_RECONFIG:-0}" != "1" ]; then
  if EXISTING_FIELDS=$(read_existing_config "$CFGDIR/config.json"); then
    REUSE_CONFIG=1
    DOMAIN=$(printf '%s\n' "$EXISTING_FIELDS" | sed -n '1p')
    LISTEN_PORT=$(printf '%s\n' "$EXISTING_FIELDS" | sed -n '2p')
    CLIENT_CIDR=$(printf '%s\n' "$EXISTING_FIELDS" | sed -n '3p')
    DNS_ON=$(printf '%s\n' "$EXISTING_FIELDS" | sed -n '4p')
    DLPATH=$(printf '%s\n' "$EXISTING_FIELDS" | sed -n '5p')
    [ -n "$DOMAIN" ] || die "已有配置缺少 gateway.host，拒绝覆盖"
    ok "检测到已有配置，将保留 $CFGDIR/config.json（只更新程序与服务）"
    dim "如需重新生成配置：FGPN_FORCE_RECONFIG=1 sudo bash install.sh"
  else
    die "已有 $CFGDIR/config.json 但无法解析，拒绝覆盖。修复该文件，或设 FGPN_FORCE_RECONFIG=1 强制重写"
  fi
fi

if [ "$REUSE_CONFIG" = "1" ]; then
  NODE=""
  BOT_TK=""
  BOT_IDS=""
  EMAIL="${FGPN_EMAIL:-}"
  if [ -z "$EMAIL" ]; then
    CERT_EMAIL_ARG="--register-unsafely-without-email"
  else
    CERT_EMAIL_ARG="--email $EMAIL"
  fi
else
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
  else
    FGPN_WRITE_BOT_IDS="$BOT_IDS" python3 - <<'PY' || die "管理员 ID 必须是正整数（多个用英文逗号分隔），且不能重复"
import os, sys
raw = os.environ.get("FGPN_WRITE_BOT_IDS", "").replace(" ", "")
seen = set()
ok = False
for part in raw.split(","):
    if part == "":
        continue
    if not part.isdigit() or int(part) <= 0:
        sys.exit(2)
    n = int(part)
    if n in seen:
        sys.exit(2)
    seen.add(n)
    ok = True
if not ok:
    sys.exit(2)
PY
  fi
fi

# iOS 蜂窝加密 DNS 与 Android 私人 DNS 共用同一套接入与分流策略。
DNS_ON=true
fi

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
install_release_bin() {
  local tag="$1" arch="$2"
  local asset="5gpnd-linux-${arch}"
  local base="https://github.com/${REPO}/releases/download/${tag}"
  local tmpdir bin sums want got
  tmpdir=$(mktemp -d)
  bin="$tmpdir/$asset"
  sums="$tmpdir/SHA256SUMS"
  curl -fsSL --max-time 120 "$base/$asset" -o "$bin" || { rm -rf "$tmpdir"; return 1; }
  curl -fsSL --max-time 30 "$base/SHA256SUMS" -o "$sums" \
    || die "已找到 $tag 但缺少 SHA256SUMS，拒绝安装未校验产物"
  want=$(awk -v f="$asset" '$2==f || $2=="*"f {print tolower($1); exit}' "$sums")
  [ -n "$want" ] || die "SHA256SUMS 中没有 $asset"
  got=$(sha256sum "$bin" | awk '{print tolower($1)}')
  [ "$got" = "$want" ] || die "校验失败：$asset 期望 $want，实际 $got"
  mv -f "$bin" /usr/local/bin/5gpnd
  chmod 755 /usr/local/bin/5gpnd
  rm -rf "$tmpdir"
}

if [ -n "$TAG" ]; then
  if install_release_bin "$TAG" "$GOARCH"; then
    ok "5gpnd $TAG 已安装（SHA256 已校验）"
  else
    die "下载 $TAG 的 $GOARCH 二进制失败"
  fi
else
  command -v go >/dev/null 2>&1 || die "未找到发布版且本机无 Go，无法安装。请先安装 Go 1.23+ 或等待 release 发布"
  warn "未找到发布版，从源码构建"
  tmp=$(mktemp -d)
  curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp" --strip-components=1
  SRC_SHA=$(curl -fsS --max-time 20 "https://api.github.com/repos/${REPO}/commits/main" 2>/dev/null \
            | sed -n 's/.*"sha": *"\([a-f0-9]\{7\}\).*/\1/p' | head -1)
  SRC_VER="dev"
  [ -n "$SRC_SHA" ] && SRC_VER="dev-${SRC_SHA}"
  ( cd "$tmp" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${SRC_VER}" -o /usr/local/bin/5gpnd ./cmd/5gpnd )
  chmod 755 /usr/local/bin/5gpnd
  rm -rf "$tmp"
  ok "已从源码构建（version=${SRC_VER}）"
fi
/usr/local/bin/5gpnd version 2>&1 | sed -n '1p' | sed 's/^/  /'

# ---------------------------------------------------------------- 3. 证书
step "申请 TLS 证书"

install -d -m 700 "$CFGDIR"
install -d -m 755 "$LIBDIR/rulesets" "$LOGDIR"

CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

# 清掉中断的旧签发流程可能遗留的临时公网放行。
remove_acme_nft_rules
if [ -s "$CERT" ] && [ -s "$KEY" ]; then
  ok "已存在证书，跳过签发"
else
  command -v certbot >/dev/null 2>&1 || {
    dim "安装 certbot..."
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null 2>&1 \
      || die "certbot 安装失败，请手动安装后重试"
  }
  # HTTP-01 需要公网访问 80；insert 保证临时规则位于兜底 drop 之前。
  if nft list chain inet fgpn input >/dev/null 2>&1; then
    nft insert rule inet fgpn input tcp dport 80 accept comment '"5gpn-acme-tmp"' \
      || die "临时放行 ACME 端口失败"
  fi

  cert_rc=0
  # shellcheck disable=SC2086
  certbot certonly --standalone --non-interactive --agree-tos \
    $CERT_EMAIL_ARG -d "$DOMAIN" --keep-until-expiring >/dev/null 2>&1 \
    || cert_rc=$?
  remove_acme_nft_rules
  [ "$cert_rc" -eq 0 ] \
    || die "证书签发失败。请确认：域名已指向本机、80 端口公网可达、云厂商安全组已放行 80"
  ok "证书签发成功"
fi

# ---------------------------------------------------------------- 4. 落地节点
if [ "$REUSE_CONFIG" = "1" ]; then
  dim "保留已有出口与节点配置"
else
step "配置出口"

HAS_NODE=0
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
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
UMask=0077
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

  HAS_NODE=1
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

fi

# ---------------------------------------------------------------- 5. 写配置
if [ "$REUSE_CONFIG" = "1" ]; then
  /usr/local/bin/5gpnd check -c "$CFGDIR/config.json" >/dev/null 2>&1 \
    || die "已有配置校验失败，拒绝继续。修复 $CFGDIR/config.json 或设 FGPN_FORCE_RECONFIG=1"
  ok "已保留 $CFGDIR/config.json"
else
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
# 用 python3 写出合法 JSON，避免域名/Token 中的引号破坏配置。
if [ -s "$CFGDIR/config.json" ]; then
  cp -a "$CFGDIR/config.json" "$CFGDIR/config.json.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  dim "已备份原配置"
fi
write_config_json "$CFGDIR/config.json" \
  || die "生成配置失败。管理员 ID 须为正整数；域名与 Token 中的特殊字符会按 JSON 转义。"
chmod 600 "$CFGDIR/config.json"
/usr/local/bin/5gpnd check -c "$CFGDIR/config.json" >/dev/null 2>&1 || die "配置校验失败"
ok "配置已写入 $CFGDIR/config.json"
fi

# ---------------------------------------------------------------- 6. 防火墙
step "配置防火墙"

DNS_NFT=""
if [ "$DNS_ON" = "true" ]; then
  # QUIC（UDP 443）由网关接管：解析 Initial 包的 SNI 后按策略转发。
  # 旧版在此 reject 指望客户端回落 TCP，但 Google Play 下载器不回落，
  # 只会无限重试，表现为「下载永远等待中」，因此必须放行。
  DNS_NFT=$(cat <<NFTEOF
    ip saddr ${CLIENT_CIDR} tcp dport { 80, 443, 853 } accept comment "5gpn-dns"
    ip saddr ${CLIENT_CIDR} udp dport 443 accept comment "5gpn-quic-takeover"
    tcp dport { 80, 443, 853 } drop comment "5gpn-deny-public-tcp"
    udp dport 443 drop comment "5gpn-deny-public-udp"
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
${DNS_NFT}    tcp dport ${LISTEN_PORT} drop comment "5gpn-deny-public-panel"
  }
}
EOF
ok "已限制 ${LISTEN_PORT}/tcp 仅来源 ${CLIENT_CIDR}"
if [ "$DNS_ON" = "true" ]; then
  ok "已限制 853/80/443 仅来源 ${CLIENT_CIDR}（ACME 续期时临时开放 80）"
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
${DNS_NFT}    tcp dport ${LISTEN_PORT} drop comment "5gpn-deny-public-panel"
  }
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
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
UMask=0077
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

# 证书续期钩子。
#
# certbot 用 standalone 验证，需要独占 80 端口，而 5gpnd 的 HTTP 接管入口
# 正监听 :80。若不让出端口，续期必然失败：
#   Could not bind TCP port 80 because it is already in use
# 证书到期后 DoT(853) 与面板会一起不可用，因此这两个钩子是必需的。
install -d -m 755 /etc/letsencrypt/renewal-hooks/pre \
                  /etc/letsencrypt/renewal-hooks/post \
                  /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || true

cat > /etc/letsencrypt/renewal-hooks/pre/5gpn-next.sh <<'EOF'
#!/bin/bash
# 续期前停服让出 :80，并把 ACME 临时放行插到公网兜底 drop 之前。
# 仅在服务确实运行时记录状态，避免续期后误启动本就停止的服务。
set -u
STATE=/run/5gpn-next-cert-renew.state
rm_rules() {
  local handle
  while read -r handle; do
    [ -n "$handle" ] || continue
    nft delete rule inet fgpn input handle "$handle" 2>/dev/null || true
  done < <(nft -a list chain inet fgpn input 2>/dev/null \
    | awk '/comment "5gpn-acme-tmp"/ { for (i=1; i<=NF; i++) if ($i=="handle") print $(i+1) }')
}
rm_rules
if systemctl is-active --quiet 5gpn-next.service; then
  echo stopped-by-certbot > "$STATE"
  systemctl stop 5gpn-next.service
else
  rm -f "$STATE"
fi
if nft list chain inet fgpn input >/dev/null 2>&1; then
  if ! nft insert rule inet fgpn input tcp dport 80 accept comment '"5gpn-acme-tmp"'; then
    [ -f "$STATE" ] && systemctl start 5gpn-next.service || true
    rm -f "$STATE"
    exit 1
  fi
fi
exit 0
EOF

cat > /etc/letsencrypt/renewal-hooks/post/5gpn-next.sh <<'EOF'
#!/bin/bash
# 无论续期成功与否都先收回 ACME 临时公网放行，再恢复网关服务。
set -u
STATE=/run/5gpn-next-cert-renew.state
while read -r handle; do
  [ -n "$handle" ] || continue
  nft delete rule inet fgpn input handle "$handle" 2>/dev/null || true
done < <(nft -a list chain inet fgpn input 2>/dev/null \
  | awk '/comment "5gpn-acme-tmp"/ { for (i=1; i<=NF; i++) if ($i=="handle") print $(i+1) }')
if [ -f "$STATE" ]; then
  rm -f "$STATE"
  systemctl start 5gpn-next.service || true
fi
# 兜底：状态文件异常丢失但服务已停时仍尝试拉起。
if ! systemctl is-active --quiet 5gpn-next.service; then
  systemctl start 5gpn-next.service || true
fi
exit 0
EOF

# 新证书落地后重启以加载（post 钩子已负责启动，这里只处理未停服的情形）。
cat > /etc/letsencrypt/renewal-hooks/deploy/5gpn-next.sh <<'EOF'
#!/bin/bash
systemctl is-active --quiet 5gpn-next.service && systemctl restart 5gpn-next.service
exit 0
EOF

chmod 755 /etc/letsencrypt/renewal-hooks/pre/5gpn-next.sh \
          /etc/letsencrypt/renewal-hooks/post/5gpn-next.sh \
          /etc/letsencrypt/renewal-hooks/deploy/5gpn-next.sh 2>/dev/null || true

# ---------------------------------------------------------------- 8. 自检
step "安装自检"

for t in weibo.com chatgpt.com; do
  if /usr/local/bin/5gpnd probe -c "$CFGDIR/config.json" "$t" >/dev/null 2>&1; then
    ok "$t 可达"
  else
    warn "$t 诊断未通过，稍后运行：5gpnd probe -c $CFGDIR/config.json $t"
  fi
done

if [ "$REUSE_CONFIG" = "1" ]; then
  BOT_HINT="沿用已有配置。向 Bot 发送 /start 打开菜单；未配置则可编辑 ${CFGDIR}/config.json 的 bot 段。"
elif [ -n "$BOT_TK" ]; then
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
