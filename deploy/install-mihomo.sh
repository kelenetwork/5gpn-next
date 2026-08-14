#!/bin/bash
# 在网关上部署 mihomo 官方二进制作为 5gpn-next 的出口。
# 绝不 fork mihomo：只用官方 release + 配置文件 + SOCKS5 对接。
# 节点链接从 /etc/5gpn-next/node.link 读取（600），不经命令行传递。
set -euo pipefail

MIHOMO_VER=v1.19.29
URL="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-amd64-${MIHOMO_VER}.gz"
BIN=/usr/local/bin/mihomo
CFGDIR=/etc/mihomo-5gpn
LINK=/etc/5gpn-next/node.link

[ -s "$LINK" ] || { echo "MISSING $LINK" >&2; exit 1; }

# 1. 下载官方二进制
if [ ! -x "$BIN" ]; then
  tmp=$(mktemp -d)
  curl -fsSL --max-time 180 "$URL" -o "$tmp/m.gz"
  gunzip -c "$tmp/m.gz" > "$BIN"
  chmod 755 "$BIN"
  rm -rf "$tmp"
fi
"$BIN" -v 2>&1 | sed -n '1p' || true

# 2. 解析节点并生成配置（Python 在本机做，密钥不出文件系统）
install -d -m 700 "$CFGDIR"
install -d -m 750 /var/lib/mihomo-5gpn
python3 - "$LINK" "$CFGDIR/config.yaml" <<'PYEOF'
import base64, sys, urllib.parse, json

link_path, out_path = sys.argv[1], sys.argv[2]
raw = open(link_path).read().strip()
assert raw.startswith("ss://"), "仅支持 ss:// 链接"

body = raw[5:]
name = "hinet"
if "#" in body:
    body, frag = body.split("#", 1)
    name = urllib.parse.unquote(frag).strip() or name
if "?" in body:
    body = body.split("?", 1)[0]

userinfo, hostport = body.rsplit("@", 1)
pad = "=" * (-len(userinfo) % 4)
method, password = base64.urlsafe_b64decode(userinfo + pad).decode().split(":", 1)
host, port = hostport.rsplit(":", 1)

# 出口名固定为 ASCII，避免 YAML/配置里出现 emoji 导致引用困难
proxy_name = "hinet"

cfg = f"""# 由 5gpn-next 生成；mihomo 仅作为出口协议栈使用。
mixed-port: 0
socks-port: 7891
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
external-controller: 127.0.0.1:9095
profile:
  store-selected: false
  store-fake-ip: false

proxies:
  - name: "{proxy_name}"
    type: ss
    server: {host}
    port: {port}
    cipher: {method}
    password: "{password}"
    udp: true

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "{proxy_name}"

rules:
  - MATCH,PROXY
"""
open(out_path, "w").write(cfg)
print(f"  节点名: {name} -> 出口 {proxy_name}")
print(f"  服务器: {host}:{port}")
print(f"  加密  : {method}")
print(f"  密钥  : <redacted len={len(password)}>")
PYEOF
chmod 600 "$CFGDIR/config.yaml"

# 3. 配置语法校验
"$BIN" -t -d /var/lib/mihomo-5gpn -f "$CFGDIR/config.yaml" >/dev/null 2>&1 && echo "CONFIG_VALID" || {
  echo "CONFIG_INVALID"; "$BIN" -t -d /var/lib/mihomo-5gpn -f "$CFGDIR/config.yaml" 2>&1 | tail -5; exit 1;
}

# 4. systemd
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
sleep 3

echo "--- state ---"
systemctl is-active mihomo-5gpn.service
echo "--- listener（应仅 127.0.0.1:7891）---"
ss -lntp | grep 7891 || echo NOT_LISTENING
echo "--- mihomo 实际选中出口 ---"
curl -s --max-time 8 http://127.0.0.1:9095/proxies/PROXY 2>/dev/null | sed -n 's/.*"now":"\([^"]*\)".*/  now=\1/p'
echo "--- 出口连通性（经 SOCKS5 查真实出口 IP）---"
curl -s --max-time 20 --socks5-hostname 127.0.0.1:7891 https://ipinfo.io/ip || echo CURL_FAIL
echo ""
echo "--- 对照：网关本机直出 IP ---"
curl -s --max-time 15 https://ipinfo.io/ip || echo CURL_FAIL
echo ""
