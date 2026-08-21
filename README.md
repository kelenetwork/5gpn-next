<a id="top"></a>
<div align="center">

# ⚡ 5gpn-NEXT

### 手机免客户端的加密 DNS 分流网关

**iPhone 安装一张描述文件，Android 填一个私人 DNS 域名。**<br>
分流、出口、广告拦截与诊断全部留在服务端完成。

[![Release](https://img.shields.io/github/v/release/kelenetwork/5gpn-next?style=for-the-badge&color=155eef&label=Release)](https://github.com/kelenetwork/5gpn-next/releases)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-155eef?style=for-the-badge)](LICENSE)
[![Platforms](https://img.shields.io/badge/iOS%2017%2B%20%7C%20Android%209%2B-122033?style=for-the-badge)](#-客户端接入)

[🚀 快速安装](#quick-install) · [📱 客户端接入](#client-access) · [🧭 分流规则](#routing-rules) · [🛡️ 安全边界](#security) · [🩺 常见问题](#faq)

</div>

---

> [!IMPORTANT]
> 5gpn-NEXT 面向**拥有运营商定向内网卡或同等网络拓扑**的自托管场景。它不是通用 VPN，也不会绕过正常网络接入条件。

## ✨ 一眼看懂

```text
 iPhone · 蜂窝加密 DNS ─┐
                         ├─► DoT 策略决策 ─► 国内目标：返回真实地址，手机直连
 Android · 私人 DNS ────┘               └► 国外目标：返回网关地址
                                                      │
                                     SNI / Host / DNS 线索还原目标
                                                      │
                                          DIRECT 或 mihomo 出口
```

- 📱 **iPhone / iPad**：描述文件仅在蜂窝数据下启用 DoT，连接 Wi-Fi 后自动停用。
- 🤖 **Android**：直接使用系统「私人 DNS」，无需安装代理 App。
- 🇨🇳 **国内流量**：域名规则或 GEOIP 命中后返回真实地址，由手机本地网络直连。
- 🌍 **国外流量**：DNS 返回网关地址，网关还原目标后选择本机或 mihomo 出口。
- 🔐 **隐私边界清晰**：不建立 VPN，不安装根证书，不解密 TLS，也不修改系统位置数据。

---

## 🧰 核心能力

| | 能力 | 说明 |
| :--: | :--- | :--- |
| 🧭 | **服务端分流** | `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`RULE-SET`、`GEOIP`、`FINAL` 有序匹配 |
| 🌐 | **多出口** | 本机 `DIRECT`，或通过 mihomo 接入 SS / VLESS / VMess / Trojan / Hysteria2 / TUIC 等节点 |
| 🛡️ | **DNS 广告拦截** | 命中后返回 NXDOMAIN，支持白名单、自定义规则覆盖、成功次数、最近记录与高频域名统计 |
| 🤖 | **Telegram Bot** | 查看状态与流量、管理出口与规则、下发描述文件、广告拦截、诊断、升级与回退 |
| 🖥️ | **内网 Web 面板** | 明亮产品化界面，仅允许客户端内网来源访问，无需暴露公网管理入口 |
| 🩺 | **逐层诊断** | `5gpnd probe` 输出策略、出口、连接与应用层结果，不再靠猜 |
| ♻️ | **安全更新** | Release SHA256 校验；新版本启动失败时自动回退旧二进制 |
| 🪶 | **轻量部署** | 单个 Go 二进制，规则缓存与聚合流量数据全部保存在本机 |

### 🛡️ 广告拦截如何计数

“成功拦截”不是单纯的规则命中：只有 DNS NXDOMAIN **已经成功写回客户端**才会累计。

- ✅ 记录：累计次数、每日次数、域名聚合、最近 100 条成功命中；
- ✅ 展示：Web 面板与 Telegram Bot 均可查看；
- 🚫 不记录：客户端 IP、完整 URL、正常访问明细；
- 🔄 更新：默认 anti-AD 规则每 24 小时自动刷新，首次下载失败可直接重试；
- 🧯 误杀处理：可随时加入白名单，放行该域名及其子域。

> [!NOTE]
> DNS 层无法拦截 App 自带 DoH / DoQ、直接访问 IP 的广告，以及与正常业务共用同一域名的原生广告。

---

## 🚧 能力边界

这是加密 DNS + 服务端目标识别方案，不会假装覆盖所有协议：

1. **必须存在手机可访问网关的运营商定向内网卡或同等链路。**
2. 网关主要通过 TLS SNI、HTTP Host 与近期 DNS 线索还原目标；无 SNI 私有协议可能不兼容。
3. QUIC 仅解析 Initial 包中的 SNI 并原样中继 UDP，不解密应用数据；无法还原目标的会话会丢弃。
4. iOS 描述文件只控制蜂窝加密 DNS，不读取、伪造或改写 GPS 与系统位置。
5. 网关域名必须直连源站；Cloudflare 等代理不能替代 DoT 与非标准 HTTPS 端口。

---

<a id="quick-install"></a>
## 🚀 快速安装

### 环境要求

- Debian 12+ 或 Ubuntu 22.04+
- `amd64` / `arm64`，建议至少 512 MB 内存
- 一个解析到网关公网 IP 的域名
- 运营商定向内网卡对应的客户端网段
- 可选：落地节点分享链接、Telegram Bot Token

> [!TIP]
> 使用 Cloudflare DNS 时请选择 **仅 DNS / 灰云**。首次申请 Let's Encrypt 证书还需要公网 TCP/80 可达。

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/install.sh | sudo bash
```

安装器会自动完成：

1. 📦 下载当前 Release 并识别 CPU 架构；
2. 🔐 申请或复用 Let's Encrypt 证书；
3. 🌐 可选部署 mihomo 出口；
4. ⚙️ 写入 `/etc/5gpn-next/config.json`；
5. 🔥 创建仅允许客户端网段访问的 nftables 规则；
6. ✅ 启动并自检 `5gpn-next.service`。

### 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/uninstall.sh | sudo bash
```

追加 `--purge` 可一并删除配置与运行数据。

---

## ⬆️ 从 v0.12.5 及更早版本升级

v0.13.0 起已删除定位改写、MITM、根 CA 与相关历史实验功能。升级后请完成一次客户端收尾：

- [ ] 在 Bot「版本更新」中完成升级；
- [ ] iPhone 打开 **设置 → 通用 → VPN 与设备管理**，删除旧描述文件；
- [ ] 回到 Bot「客户端接入」，重新获取并安装蜂窝 DNS 描述文件；
- [ ] 打开 **设置 → 通用 → 关于本机 → 证书信任设置**，确认没有遗留的 `5gpn-NEXT` 根证书。

新版描述文件只含系统加密 DNS payload，不含证书 payload。服务端旧 CA 文件会在新版首次启动时清理。

---

<a id="client-access"></a>
## 📱 客户端接入

### 🍎 iPhone / iPad（iOS 17+）

1. Telegram Bot → **客户端接入** → **获取 iOS 描述文件**；
2. 下载文件；
3. 打开 **设置 → 通用 → VPN 与设备管理**；
4. 安装 `5gpn-NEXT 蜂窝DNS`。

描述文件仅在蜂窝数据下连接网关，Wi-Fi 下自动停用。切换或重装前，请先删除同名旧描述文件。

### 🤖 Android（Android 9+）

1. 打开 **设置 → 网络和互联网 → 私人 DNS**；
2. 选择「指定的私人 DNS 服务提供商主机名」；
3. 填入网关域名并保存。

不同厂商的菜单名称可能略有差异。

---

## 🎛️ 日常管理

### 🤖 Telegram Bot

发送 `/start` 打开菜单：

- 📊 运行状态、网关转发流量（不是手机总流量）
- 🌐 出口管理、分流规则
- 🛡️ 广告拦截、命中记录
- 🩺 连通诊断
- 📱 客户端接入、内网面板
- ♻️ 版本更新与回退

### 🖥️ Web 面板

在运营商内网卡网络下打开：

```text
https://<网关域名>:<gateway.listen 端口>/
```

面板只接受 `client_cidr` 内的来源，**不要把该端口额外开放给公网**。

### ⌨️ 命令行

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

## ⚙️ 配置

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
  "ad_block": {
    "enabled": true,
    "allowlist": ["safe.example.com"]
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

完整示例见 [`deploy/config.example.json`](deploy/config.example.json)。旧版配置会在首次加载后自动迁移为当前 `gateway` / `dns` 结构，并在下次保存时清理退役字段。

---

<a id="routing-rules"></a>
## 🧭 分流规则

规则按顺序 **first-match**，命中即停止：

```text
DOMAIN,example.com,direct
DOMAIN-SUFFIX,openai.com,proxy:node
DOMAIN-KEYWORD,ads,block
IP-CIDR,203.0.113.0/24,proxy:node
RULE-SET,cn-domain,direct
GEOIP,cn,direct
FINAL,,proxy:node
```

```text
优先级：内置私网保护 → 用户自定义规则 → 广告白名单 → 广告规则 → 国内直连兜底 → FINAL
```

- 🔒 **内置私网保护**始终最优先，任何自定义规则都不能把私网地址导向外部出口；
- ✏️ **用户自定义规则**可覆盖普通国内域名和广告规则；
- 🇨🇳 **国内域名 + GEOIP CN**作为后置直连兜底；
- 🎯 **FINAL**只决定其余未命中流量的默认出口。

---

<a id="faq"></a>
## 🩺 常见问题

<details>
<summary><b>🔐 证书签发失败</b></summary>
<br>

确认域名 A 记录指向本机、TCP/80 可达；使用 Cloudflare 时应为灰云。已有证书可直接复用。
</details>

<details>
<summary><b>📱 描述文件或面板打不开</b></summary>
<br>

它们默认只允许 `client_cidr` 来源访问。关闭 Wi-Fi，确认手机正在使用目标内网卡，并检查 nftables 与云厂商安全组。
</details>

<details>
<summary><b>🌍 国外网站不通</b></summary>
<br>

运行：

```bash
5gpnd probe -c /etc/5gpn-next/config.json youtube.com
```

如果没有配置可用代理出口，`FINAL` 为 `direct` 时会使用网关本机公网出口。
</details>

<details>
<summary><b>🛡️ 广告拦截显示开启，但规则数为 0</b></summary>
<br>

再次点击「开启」会重新下载规则并热重载，无需先关闭。若仍失败，请检查网关到规则源的网络与服务日志。
</details>

<details>
<summary><b>🐢 某个国内 App 变慢</b></summary>
<br>

先用 `probe` 确认域名或 IP 的判定，再通过 Bot / 面板添加更具体的 `direct` 规则。
</details>

<details>
<summary><b>📡 为什么某个 App 的 QUIC 或无 SNI 协议不可用</b></summary>
<br>

这是加密 DNS + 目标识别方案的边界。QUIC 会尝试从 Initial SNI 或近期 DNS 线索还原目标并原样中继；既没有 SNI、HTTP Host，也无法从近期 DNS 查询可靠关联目标的协议无法安全代理。项目不会通过全量 TLS 解密绕过这个边界。
</details>

---

<a id="security"></a>
## 🛡️ 安全边界

- 🔑 描述文件下载路径含随机串，应按凭据保管；
- 👤 Bot 只响应 `bot.admins` 中列出的 Telegram 数字 ID；
- 🔥 内网面板和接管端口应只允许 `client_cidr` 访问；
- 🙈 配置、节点链接、Bot Token 与生产部署文件不得提交到 Git；
- 🔐 项目不生成或下发根 CA，不解密用户 TLS 流量；
- 📉 网关转发流量只保存聚合数据；不包含手机本地直连流量。连接级诊断日志按容量轮转，不会无限增长。

> [!WARNING]
> 请勿为了“方便访问”把管理面板、接管端口或包含凭据的配置暴露到公网。

---

## 🧱 技术栈与数据来源

**Go 1.23** · [mihomo](https://github.com/MetaCubeX/mihomo) · Let's Encrypt · nftables

规则数据来自：

- 🇨🇳 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
- 🌏 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)
- 🛡️ [anti-AD](https://anti-ad.net/)

---

<div align="center">

### 📄 License

本项目采用 [MIT License](LICENSE)，仅供学习与合法网络管理用途。<br>
使用者须遵守所在地区法律法规，并自行承担使用风险。

**[⬆ 回到顶部](#top)**

</div>
