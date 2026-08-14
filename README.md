<div align="center">

# 5gpn-NEXT

### 手机不装客户端的分流网关

**一张描述文件，一个域名，手机上什么 App 都不用装。**

基于 Apple Network Relay 与 Android 私人 DNS 的服务端分流网关<br>
没有 Clash，没有 Surge，没有 VPN 图标，没有 tun

[![Release](https://img.shields.io/github/v/release/kelenetwork/5gpn-next?style=flat-square&color=2563eb&label=Release)](https://github.com/kelenetwork/5gpn-next/releases)
[![License](https://img.shields.io/badge/License-MIT-2563eb?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/iOS%2017+-000000?style=flat-square&logo=apple&logoColor=white)](#客户端接入)
[![Platform](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)](#客户端接入)

</div>

---

## ✨ 它做了什么

一台境外 VPS + 一张运营商定向内网卡，手机在**不安装任何代理客户端**的前提下完成智能分流：

```
                       ┌────────────────────┐
  iPhone  ──Relay──►   │                    │  ──►  国内站点 · 直连
                       │   5gpn-NEXT 网关    │
  Android ──DNS────►   │                    │  ──►  国外站点 · 落地节点
                       └────────────────────┘
```

- 🍎 **iPhone / iPad** — 安装一个系统描述文件即可，走 iOS 原生 Network Relay
- 🤖 **Android** — 系统设置里填一个「私人 DNS」域名即可
- 🧠 **分流全在服务端** — 国内直连、国外走节点，手机端零配置零维护

---

## 🆚 为什么不是「又一个 DNS 劫持网关」

现有同类方案普遍依赖「DNS 劫持 + SNI 嗅探」，这个前提直接带来一串结构性问题：

| 传统方案的痛 | 根本原因 |
| :--- | :--- |
| 😤 AAAA 记录必须置空 | 要骗客户端把流量交给网关 |
| 😤 QUIC 只能 REJECT 强制回落 TCP | 入口拿不到 UDP 目标 |
| 😤 WhatsApp 要专门写补丁 | Noise 握手无 SNI，嗅探不出目标 |
| 😤 运营商换网段就全挂 | 依赖固定私网源段判断是否劫持 |

**5gpn-NEXT 直接更换入口。** Apple Network Relay 让客户端在 `CONNECT` 请求中**主动携带目的地** —— 不需要猜，上述问题从根源上消失。

---

## 🚀 核心能力

| | |
| :--- | :--- |
| 🧭 **三层分流** | iOS 手机侧国内直连名单 + 网关 11 万条域名规则库 + GEOIP 兜底，规则每日自动更新 |
| 🩺 **逐层诊断** | `5gpnd probe` 输出 入口→策略→出口→连接→应用 五层结果，坏在哪层一眼看清 |
| 🤖 **Telegram Bot** | 状态、流量、切换国外默认出口、改规则、下发描述文件、一键升级，全在聊天窗口完成 |
| 🖥 **内网 Web 面板** | 手机连着内网卡直接打开域名即达，无需登录；公网完全无法访问 |
| 📈 **流量统计** | 今日/7 天/30 天用量与 Top 站点，只存聚合数据，不记录访问明细 |
| 🔄 **自升级 + 自回退** | Bot 内一键升级，SHA256 校验，新版启动失败自动回退 |
| 🧩 **不 fork 上游** | 出口协议栈用 mihomo 官方二进制，新协议随 mihomo 升级自动获得 |
| 🪶 **单文件部署** | 一个 Go 二进制，常驻内存约 26 MB，512 MB 小鸡随便跑 |

---

## 📦 快速开始

### 你需要

- 🌍 境外 VPS：Debian 12+ / Ubuntu 22.04+，512 MB 内存起，amd64 / arm64
- 📶 **运营商定向内网卡**：手机流量经运营商私网到达 VPS
- 🌐 一个可自行修改解析记录的域名
- 📱 iOS 17+ 或 Android 9+ 设备

> ⚠️ **没有内网卡则不适用。** 本项目依赖特定网络拓扑，不是通用代理工具。

### 一条命令安装

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/install.sh | sudo bash
```

安装会依次询问网关域名、证书邮箱、落地节点链接、Telegram Bot Token（后三项可留空），装完直接给出 iPhone 描述文件安装链接和面板地址。

### 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/uninstall.sh | sudo bash
```

追加 `--purge` 一并删除配置与数据。

---

## 📱 客户端接入

<table>
<tr>
<td width="50%" valign="top">

### 🍎 iPhone / iPad

1. 内网卡蜂窝数据下用 Safari 打开安装链接
2. **设置 → 通用 → VPN 与设备管理**
3. 安装「5gpn-NEXT」描述文件

也可以直接在 Telegram Bot 里点「客户端接入」获取文件。

> ⚠️ Apple Managed Network Relay 是系统级网络配置，会同时作用于蜂窝和 Wi-Fi；它不是传统 VPN，但不能按网络接口设置“仅蜂窝启用”。iOS 26+ 可在系统设置中手动关闭 Relay，旧版系统只能停用/移除描述文件。
>
> iOS 的手机侧直连名单写在描述文件中，不会随服务器二进制自动改写。升级日志若注明直连名单更新，请在 Bot 中重新获取，并先删除同名旧描述文件后安装；Relay Token、下载路径和稳定 UUID 均沿用，不会改变网关身份。

</td>
<td width="50%" valign="top">

### 🤖 Android

1. **设置 → 网络和互联网 → 私人 DNS**
2. 选「指定的私人 DNS 服务提供商主机名」
3. 填入你的网关域名，保存即生效

无需安装任何应用。

</td>
</tr>
</table>

---

## 🎛 日常管理

### Telegram Bot

发送 `/start` 打开菜单，所有操作按钮化：

📊 运行状态 · 📈 流量统计 · 🌐 国外默认出口 · 🧭 分流规则 · 🩺 连通诊断 · 📱 客户端接入 · 🖥 内网面板 · 🚀 一键升级/回退

> “国外默认出口”只改变 `FINAL`：自定义分流规则优先；iOS 常用国内域名先由描述文件在手机侧直连，其余域名在网关解析目标 IP 后继续匹配 `GEOIP,cn`。出口列表中的 `KFC 本机出口`（内部兼容名仍为 `DIRECT`）表示使用 KFC 服务器公网 IP。

### 内网 Web 面板

手机连着内网卡，浏览器直接打开：

```
https://<你的域名>:<端口>/
```

**免登录直达** —— 面板只接受内网卡来源访问，公网完全无法连接。

### 命令行

```bash
5gpnd probe youtube.com    # 端到端逐层诊断
5gpnd status               # 运行状态
5gpnd profile -o x.mobileconfig   # 重新生成描述文件
```

`probe` 输出长这样：

```
[1] 入口   probe 本地发起                          ✅     0.0ms
[2] 策略   RULE-SET,cn-domain [域名] → 直连         ✅     0.1ms
[3] 出口   KFC 本机出口（IPv6 能力=false）           ✅     0.0ms
[4] 连接   TCP 36.51.224.126:443 已建立             ✅    59.6ms
[5] 应用   TLS 1.2 证书校验通过                      ✅   109.9ms
结论：正常（总计 169.7ms）
```

---

## ⚙️ 配置

配置文件 `/etc/5gpn-next/config.json`，改完 Bot / 面板即时热更新，无需重启：

```jsonc
{
  "egress": [
    { "name": "DIRECT", "type": "direct" }, // UI 显示为“KFC 本机出口”
    { "name": "node", "type": "socks5", "addr": "127.0.0.1:7891" }
  ],
  "rules": [
    "RULE-SET,cn-domain,direct",       // 国内域名直连
    "GEOIP,cn,direct",                 // 裸 IP 或域名解析出的国内 IP
    "DOMAIN-SUFFIX,openai.com,proxy:node"
  ],
  "final": "proxy:node"                // 其余走节点
}
```

规则类型 `DOMAIN` `DOMAIN-SUFFIX` `DOMAIN-KEYWORD` `IP-CIDR` `RULE-SET` `GEOIP` `FINAL`，有序匹配，命中即停。

**节点协议**：`ss` `vless` `vmess` `trojan` `hysteria2` `tuic` `socks5` `http` —— 粘贴分享链接即可，协议实现由 mihomo 提供。

---

## ❓ 常见问题

<details>
<summary><b>🔐 证书签发失败</b></summary>
<br>

确认域名 A 记录已指向本机、80 端口公网可达、云厂商安全组已放行 80。使用 Cloudflare 时必须选「仅 DNS」（灰云），橙云代理不覆盖非标准端口。
</details>

<details>
<summary><b>📵 描述文件链接 / 面板打不开</b></summary>
<br>

两者都仅内网卡来源可访问。请关闭 Wi-Fi，确认手机正在使用内网卡蜂窝数据。
</details>

<details>
<summary><b>🌍 国外网站不通</b></summary>
<br>

运行 <code>5gpnd probe youtube.com</code> 看是哪一层失败。若提示未配置代理出口，说明流量实际从网关本机直出，需要添加落地节点。
</details>

<details>
<summary><b>🐢 某个国内 App 变慢</b></summary>
<br>

可能该域名未被识别为国内。<code>5gpnd probe &lt;域名&gt;</code> 确认判定结果，然后通过 Bot 或面板加一条直连规则。
</details>

<details>
<summary><b>📍 iOS 26 定位/网络行为异常</b></summary>
<br>

描述文件已启用 <code>AllowDNSFailover</code>，网关故障时自动回退系统 DNS，不会整机断网。也可在 设置 → 通用 → VPN 与设备管理 中直接关闭该 Relay。
</details>

---

## 🧱 技术栈

**Go 1.23** · [mihomo](https://github.com/MetaCubeX/mihomo)（出口协议栈，官方二进制） · Let's Encrypt · nftables

规则数据来自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) 与 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)。

---

## ⚖️ 免责声明

**本项目仅供学习与合法网络管理用途。**

使用者须遵守所在地区的法律法规，并自行承担因使用本软件产生的一切责任与后果。作者不对任何使用行为及其结果负责。请勿将本项目用于任何违反当地法律的用途。

本项目与任何 VPS 服务商、SIM 卡经销商均无隶属或合作关系。

---

<div align="center">

[MIT License](LICENSE) © kelenetwork

</div>
