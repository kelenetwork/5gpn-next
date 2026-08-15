<div align="center">

# 5gpn-NEXT

### 手机免客户端的加密 DNS 分流网关

**iPhone 安装一张描述文件，Android 填一个私人 DNS 域名。**

分流、出口、规则和诊断全部留在服务端完成。

[![Release](https://img.shields.io/github/v/release/kelenetwork/5gpn-next?style=flat-square&color=2563eb&label=Release)](https://github.com/kelenetwork/5gpn-next/releases)
[![License](https://img.shields.io/badge/License-MIT-2563eb?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/iOS%2017+-000000?style=flat-square&logo=apple&logoColor=white)](#客户端接入)
[![Platform](https://img.shields.io/badge/Android%209+-3DDC84?style=flat-square&logo=android&logoColor=white)](#客户端接入)

</div>

---

## 工作方式

```text
 iPhone（蜂窝加密 DNS） ─┐
                         ├─► DoT 决策 ─► 国内目标：返回真实地址，手机直连
 Android（私人 DNS） ────┘            └► 国外目标：返回网关地址
                                                   │
                                  SNI / Host / DNS 线索还原目标
                                                   │
                                      DIRECT 或 mihomo 落地节点
```

- **iPhone / iPad**：描述文件只在蜂窝数据下启用 DoT；连接 Wi-Fi 时自动停用。
- **Android**：使用系统「私人 DNS」，无需安装代理 App。
- **国内流量**：域名规则与 GEOIP 命中后返回真实地址，由手机本地网络直连。
- **国外流量**：DNS 返回网关地址，网关还原目标后按规则选择本机或 mihomo 出口。

5gpn-NEXT **不建立 VPN，不使用 Apple Network Relay，不安装根证书，也不做 TLS 中间人解密**。

---

## 核心能力

| 能力 | 说明 |
| :--- | :--- |
| 服务端分流 | `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`RULE-SET`、`GEOIP`、`FINAL` 有序匹配 |
| 多出口 | 本机 `DIRECT`，或通过 mihomo 接入 SS / VLESS / VMess / Trojan / Hysteria2 / TUIC 等节点 |
| Telegram Bot | 查看状态与流量、管理出口和规则、下发描述文件、诊断、一键升级与回退 |
| 内网 Web 面板 | 仅允许运营商内网卡来源访问，无需公网登录入口 |
| 广告拦截 | 在 DNS 层返回 NXDOMAIN；支持白名单与自定义规则覆盖 |
| 逐层诊断 | `5gpnd probe` 输出策略、出口、连接和应用层结果 |
| 安全更新 | 下载 SHA256 校验，启动失败自动回退旧二进制 |
| 轻量部署 | 单个 Go 二进制；规则和聚合流量数据保存在本机 |

---

## 明确边界

这不是通用 VPN，也不会假装能覆盖所有协议：

1. **必须有可从手机访问网关的运营商定向内网卡或同等网络拓扑。** 没有该链路就不适用。
2. 网关主要从 TLS SNI、HTTP Host 与近期 DNS 线索还原目标。无法识别的无 SNI 私有协议可能不兼容。
3. QUIC 没有可用的明文目标信息，安装器会拒绝客户端到网关的 UDP/443，促使应用回落 TCP。
4. iOS 描述文件只控制蜂窝加密 DNS；它不会修改 GPS、网络定位或任何系统位置数据。
5. 域名必须直连源站，Cloudflare 等代理不能替代 DoT 与非标准 HTTPS 端口。

---

## 快速安装

### 环境要求

- Debian 12+ 或 Ubuntu 22.04+
- amd64 / arm64，建议至少 512 MB 内存
- 一个解析到网关公网 IP 的域名
- 运营商定向内网卡对应的客户端网段
- 可选：落地节点分享链接、Telegram Bot Token

> 使用 Cloudflare DNS 时请选择「仅 DNS / 灰云」。证书首次签发还需要公网 TCP/80 可达。

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/install.sh | sudo bash
```

安装器会：

1. 下载当前 Release 并确认架构；
2. 申请或复用 Let's Encrypt 证书；
3. 可选部署 mihomo 出口；
4. 写入 `/etc/5gpn-next/config.json`；
5. 创建仅允许客户端网段访问的 nftables 规则；
6. 启动并自检 `5gpn-next.service`。

### 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/uninstall.sh | sudo bash
```

追加 `--purge` 可一并删除配置与运行数据。

---

## 从 v0.12.5 及更早版本升级

v0.13.0 已彻底删除定位改写、MITM、根 CA 与旧中继遗留。升级后请完成一次客户端收尾：

1. 在 Bot「版本更新」中升级；
2. iPhone 打开 **设置 → 通用 → VPN 与设备管理**，删除旧的 5gpn 描述文件；
3. 回到 Bot「客户端接入」，重新获取并安装蜂窝 DNS 描述文件；
4. 打开 **设置 → 通用 → 关于本机 → 证书信任设置**，确认没有遗留的 `5gpn-NEXT` 根证书。

新版描述文件只含系统加密 DNS payload，不含证书 payload。服务端旧 CA 文件会在新版首次启动时清除。

---

## 客户端接入

### iPhone / iPad（iOS 17+）

1. Telegram Bot → **客户端接入** → **获取 iOS 描述文件**；
2. 下载文件；
3. 打开 **设置 → 通用 → VPN 与设备管理**；
4. 安装 `5gpn-NEXT 蜂窝DNS`。

描述文件仅在蜂窝数据下连接网关，Wi-Fi 下自动停用。切换或重装前，请先删除同名旧描述文件。

### Android（Android 9+）

1. 打开 **设置 → 网络和互联网 → 私人 DNS**；
2. 选择「指定的私人 DNS 服务提供商主机名」；
3. 填入网关域名并保存。

不同厂商的菜单名称可能略有差异。

---

## 日常管理

### Telegram Bot

发送 `/start` 打开菜单：

- 运行状态、流量统计
- 出口管理、分流规则
- 广告拦截、连通诊断
- 客户端接入、内网面板
- 版本更新与回退

### Web 面板

在运营商内网卡网络下打开：

```text
https://<网关域名>:<gateway.listen 端口>/
```

面板只接受 `client_cidr` 内的来源。不要把该端口额外开放给公网。

### 命令行

```bash
5gpnd version
5gpnd check   -c /etc/5gpn-next/config.json
5gpnd probe   -c /etc/5gpn-next/config.json youtube.com
5gpnd profile -c /etc/5gpn-next/config.json -o 5gpn-next.mobileconfig
```

服务与日志：

```bash
systemctl status 5gpn-next
journalctl -u 5gpn-next -f
tail -f /var/log/5gpn-next/trace.jsonl
```

---

## 配置

默认路径：`/etc/5gpn-next/config.json`

```jsonc
{
  "gateway": {
    "listen": ":20443",
    "host": "gateway.example.com",
    "cert_file": "/etc/letsencrypt/live/gateway.example.com/fullchain.pem",
    "key_file": "/etc/letsencrypt/live/gateway.example.com/privkey.pem",
    "profile_path": "/dl/随机串/5gpn-next.mobileconfig"
  },
  "dns": {
    "enabled": true,
    "dot_listen": ":853",
    "gateway_ip": "172.22.0.1",
    "http_listen": ":80",
    "tls_listen": ":443",
    "upstream": ["223.5.5.5:53", "119.29.29.29:53"]
  },
  "egress": [
    { "name": "DIRECT", "type": "direct" },
    { "name": "node", "type": "socks5", "addr": "127.0.0.1:7891" }
  ],
  "rules": [
    "DOMAIN-SUFFIX,openai.com,proxy:node"
  ],
  "final": "proxy:node",
  "client_cidr": "172.22.0.0/16"
}
```

完整示例见 [`deploy/config.example.json`](deploy/config.example.json)。

v0.12 及更早版本的 `relay` / `android` 配置键只用于向后兼容读取；新版保存配置时会统一迁移为 `gateway` / `dns`。

---

## 分流规则

规则按顺序 first-match，命中即停止：

```text
DOMAIN,example.com,direct
DOMAIN-SUFFIX,openai.com,proxy:node
DOMAIN-KEYWORD,ads,block
IP-CIDR,203.0.113.0/24,proxy:node
RULE-SET,cn-domain,direct
GEOIP,cn,direct
FINAL,,proxy:node
```

内置私网保护规则始终最优先；国内域名与 `GEOIP,cn` 作为内置后置兜底。用户自定义规则位于二者之间，可覆盖普通国内域名的默认行为，但不能把私网地址导向外部出口。

---

## 常见问题

<details>
<summary><b>证书签发失败</b></summary>
<br>

确认域名 A 记录指向本机、TCP/80 可达；使用 Cloudflare 时应为灰云。已有证书可直接复用。
</details>

<details>
<summary><b>描述文件或面板打不开</b></summary>
<br>

它们默认只允许 `client_cidr` 来源访问。关闭 Wi-Fi，确认手机正在使用目标内网卡，并检查 nftables 与云厂商安全组。
</details>

<details>
<summary><b>国外网站不通</b></summary>
<br>

运行：

```bash
5gpnd probe -c /etc/5gpn-next/config.json youtube.com
```

如果没有配置可用代理出口，`FINAL` 为 `direct` 时会使用网关本机公网出口。
</details>

<details>
<summary><b>某个国内 App 变慢</b></summary>
<br>

先用 `probe` 确认域名或 IP 的判定，再通过 Bot / 面板添加更具体的 `direct` 规则。
</details>

<details>
<summary><b>为什么某个 App 的 QUIC 或无 SNI 协议不可用</b></summary>
<br>

这是加密 DNS + 目标嗅探方案的边界。QUIC 会被促使回落 TCP；既没有 SNI、HTTP Host，也无法从近期 DNS 查询可靠关联目标的协议无法安全代理。项目不会通过全量 TLS 解密绕过这个边界。
</details>

---

## 安全说明

- 描述文件下载路径含随机串，应按凭据保管。
- Bot 只响应 `bot.admins` 中列出的 Telegram 数字 ID。
- 内网面板和接管端口应只允许 `client_cidr` 访问。
- 配置、节点链接、Bot Token 与生产部署文件不得提交到 Git。
- 项目不生成或下发根 CA，不解密用户 TLS 流量。

---

## 技术栈与许可

**Go 1.23** · [mihomo](https://github.com/MetaCubeX/mihomo) · Let's Encrypt · nftables

规则数据来自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) 与 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)。

本项目采用 [MIT License](LICENSE)，仅供学习与合法网络管理用途。使用者须遵守所在地区法律法规，并自行承担使用风险。
