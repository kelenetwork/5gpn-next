<div align="center">

# 5gpn-NEXT

**手机不装客户端的分流网关**

基于 Apple Network Relay，iPhone 装一个描述文件即可，无需 Clash / Surge / Loon，无 VPN 图标，无 tun。

[![Release](https://img.shields.io/github/v/release/kelenetwork/5gpn-next?style=flat-square&color=2563eb)](https://github.com/kelenetwork/5gpn-next/releases)
[![License](https://img.shields.io/badge/license-MIT-2563eb?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)

</div>

---

## 这是什么

一台境外 VPS + 一张运营商定向内网卡，让手机在**不安装任何代理客户端**的前提下完成分流上网。

国内网站直连，国外网站走你的落地节点，全程由服务端决策。手机上只有一个系统描述文件。

```
 iPhone ──► Apple Network Relay ──► 5gpn-NEXT 网关 ──┬──► 国内：直连
            （iOS 系统原生能力）                      └──► 国外：你的落地节点
```

---

## 与同类项目的区别

现有方案普遍采用「DNS 劫持 + SNI 嗅探」作为入口。这一前提直接导致四个结构性问题：

| 问题 | 成因 |
| :--- | :--- |
| AAAA 记录必须置空 | 需要骗客户端把流量交给网关 |
| QUIC 只能 REJECT 强制回落 TCP | 入口拿不到 UDP 目标 |
| WhatsApp 需要专门写补丁 | Noise 握手无 SNI，嗅探不出目标 |
| 运营商换网段就全挂 | 依赖固定私网源段判断是否劫持 |

**本项目更换入口。** Apple Network Relay 让客户端在 `CONNECT` 请求中**主动携带目的地**，上述问题从根源上消失 —— 不需要猜，也就不需要打补丁。

---

## 核心特性

**三层分流，开箱即用**
手机侧直连名单 + 网关侧 11 万条域名规则库 + GEOIP 兜底。规则每日自动更新，无需手工维护。

**可自助排障**
`5gpnd probe` 逐层输出 入口 → 策略 → 出口 → 连接 → 应用，失败时精确指出是哪一层，而不是笼统的「连不上」。

**Telegram Bot 管理**
查看状态、增删出口、切换节点、调整分流规则、下发描述文件，全部在聊天窗口完成。

**内网 Web 面板**
仅内网卡来源可访问，公网不可见。手机连着卡直接打开浏览器即可管理，无需 SSH。

**不 fork 上游**
出口协议栈使用 mihomo 官方发布二进制，通过配置与 API 对接。新协议随 mihomo 升级自动获得。

**单文件部署**
一个 Go 二进制，一条命令安装，常驻内存约 26 MB，512 MB 小机可跑。

---

## 快速开始

### 前提条件

- 境外 VPS：Debian 12+ / Ubuntu 22.04+，512 MB 内存起，amd64 或 arm64
- **运营商定向内网卡**：手机流量经运营商私网到达 VPS，源 IP 为固定私有段
- 一个可自行修改解析记录的域名
- iOS 17 及以上设备

> **没有内网卡则不适用。** 本项目依赖特定网络拓扑，不是通用代理工具。

### 安装

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/install.sh | sudo bash
```

安装过程会询问：网关域名、证书邮箱（可留空）、落地节点链接（可留空）、Telegram Bot Token（可留空）。

装完直接输出 iPhone 描述文件安装链接。

### 客户端接入

用 Safari 打开安装脚本给出的链接，然后前往 **设置 → 通用 → VPN 与设备管理** 安装描述文件。

> 该链接必须在**内网卡蜂窝数据**下访问，Wi-Fi 无法打开。

### 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/kelenetwork/5gpn-next/main/uninstall.sh | sudo bash
```

追加 `--purge` 可一并删除配置与数据。

---

## 使用

### 命令行

```bash
5gpnd probe <域名>      # 端到端诊断
5gpnd status            # 运行状态
5gpnd profile -o x.mobileconfig   # 重新生成描述文件
```

`probe` 输出示例：

```
[1] 入口   probe 本地发起                          ✅     0.0ms
[2] 策略   RULE-SET,cn-domain [域名] → 直连         ✅     0.1ms
[3] 出口   DIRECT（IPv6 能力=false）                ✅     0.0ms
[4] 连接   TCP 36.51.224.126:443 已建立             ✅    59.6ms
[5] 应用   TLS 1.2 证书校验通过                      ✅   109.9ms
结论：正常（总计 169.7ms）
```

### Telegram Bot

安装时填入 Bot Token 即可启用。发送 `/start` 打开菜单：

| 功能 | 说明 |
| :--- | :--- |
| 状态 | 服务、出口、连接数、内存 |
| 出口管理 | 粘贴节点链接直接添加，支持多出口切换 |
| 分流规则 | 增删规则、指定域名走特定出口 |
| 诊断 | 对任意域名执行全链路 `probe` |
| 客户端 | 生成并下发 iOS 描述文件 |
| 告警 | 服务异常、证书临期、出口失联时主动通知 |

### 内网 Web 面板

安装后访问 `https://<你的域名>:<端口>/panel`，使用安装时生成的令牌登录。

面板仅接受内网卡来源访问，公网无法连接。

---

## 配置

配置文件位于 `/etc/5gpn-next/config.json`。

```jsonc
{
  "egress": [
    { "name": "DIRECT", "type": "direct" },
    { "name": "node", "type": "socks5", "addr": "127.0.0.1:7891" }
  ],
  "rules": [
    "RULE-SET,cn-domain,direct",     // 国内域名直连
    "GEOIP,cn,direct",               // 国内 IP 直连
    "DOMAIN-SUFFIX,openai.com,proxy:node"
  ],
  "final": "proxy:node"              // 其余走节点
}
```

规则类型：`DOMAIN` `DOMAIN-SUFFIX` `DOMAIN-KEYWORD` `IP-CIDR` `RULE-SET` `GEOIP` `FINAL`，有序匹配，命中即停。

---

## 支持的节点协议

`ss` `vless` `vmess` `trojan` `hysteria2` `tuic` `socks5` `http`

直接粘贴分享链接即可。协议实现由 mihomo 提供。

---

## 常见问题

<details>
<summary><b>证书签发失败</b></summary>

确认域名 A 记录已指向本机、80 端口公网可达、云厂商安全组已放行 80。使用 Cloudflare 时必须选择「仅 DNS」（灰云），橙云代理不覆盖非标准端口。
</details>

<details>
<summary><b>描述文件链接打不开</b></summary>

该链接仅内网卡来源可访问。请关闭 Wi-Fi，确认手机正在使用内网卡蜂窝数据。
</details>

<details>
<summary><b>国外网站不通</b></summary>

运行 `5gpnd probe youtube.com` 查看是哪一层失败。若提示未配置代理出口，说明流量实际从网关本机直出，需要添加落地节点。
</details>

<details>
<summary><b>某个国内 App 变慢</b></summary>

可能该域名未被识别为国内。运行 `5gpnd probe <域名>` 确认判定结果，然后通过 Bot 或配置文件加入直连规则。
</details>

<details>
<summary><b>iOS 26 上定位/网络行为异常</b></summary>

描述文件已启用 `AllowDNSFailover`，网关故障时会自动回退系统 DNS，不会整机断网。也可在 设置 → 通用 → VPN 与设备管理 中直接关闭该 Relay。
</details>

---

## 已知限制

- **QUIC 未走 Relay**：实测 iOS 在 HTTP/2 Relay 上仅使用 TCP CONNECT，未观察到 CONNECT-UDP。HTTP/3 支持待后续版本。
- **IPv6 依赖出口能力**：出口不具备 IPv6 时，对 IPv6 字面量目标快速失败以促使客户端回落 IPv4。
- **Android 支持开发中**：当前版本仅覆盖 iOS 路径，Android 私密 DNS 接入尚未完成。

---

## 技术栈

Go 1.23 · [mihomo](https://github.com/MetaCubeX/mihomo)（出口协议栈，官方二进制）· Let's Encrypt · nftables

规则数据来自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) 与 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)。

---

## 免责声明

**本项目仅供学习与合法网络管理用途。**

使用者须遵守所在地区的法律法规，并自行承担因使用本软件产生的一切责任与后果。作者不对任何使用行为及其结果负责。

请勿将本项目用于任何违反当地法律的用途。

本项目与任何 VPS 服务商、SIM 卡经销商均无隶属或合作关系。

---

## 许可

[MIT](LICENSE)
