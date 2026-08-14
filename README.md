# 5gpn-NEXT

基于 **Apple Network Relay** 的 NPN 网关。手机不装任何代理客户端，
由 iOS 系统原生 Relay（iOS 17+）或 Android 私密 DNS 接入，服务端按域名分流。

> 状态：**P1 开发中**（P0 可行性验证已在 iOS 26 真机通过）。

---

## 为什么重写

现有同类项目（privdns-gateway 系、5GPN-X、moooyo/5gpn）都以
**「DNS 劫持 + SNI 嗅探」** 为入口。这个前提直接导致四个结构性缺陷：

| 缺陷 | 根因 |
|---|---|
| AAAA 一律置空 | 必须骗客户端把流量交给网关 |
| QUIC 只能 REJECT 强制回落 TCP | 入口拿不到 UDP 目标 |
| WhatsApp 要专门写 `wa-shim` 补丁 | Noise 握手无 SNI，嗅探不出目标 |
| 运营商换网段就全挂 | 靠固定私网源段判断是否劫持 |

**5gpn-NEXT 换入口**：Apple Network Relay 让客户端在 `CONNECT` 中
**主动携带目的地**，上述问题从根上消失。

### P0 实测证据（iOS 26 真机 + 浙江联通内网卡）

```
connect-closed  HTTP/2.0  v.whatsapp.net:443      up=3259B  down=3948B
connect-closed  HTTP/2.0  static.whatsapp.net:443 up=3201B  down=672617B
```

- 306 条隧道 / 151 个独立目标，WhatsApp（含商业版注册）、YouTube、Telegram 全通
- 78 个外网目标经过网关，**0 个国内域名**经过（手机侧直连名单生效）
- 常驻内存 8.1 MiB

---

## 架构

```
 iOS 17+  ──► Network Relay (H2 CONNECT) ─┐   主路径：目的地明文携带
 Android  ──► Private DNS (DoT)  ─────────┤   兼容路径
 旧 iOS   ──► DoT 描述文件        ─────────┘
                                          ▼
                    ┌──────────────────────────────────┐
                    │  5gpnd（单个 Go 二进制）          │
                    │   Relay Ingress / DoT Ingress    │
                    │            ▼                     │
                    │   Policy Engine（有序 first-match）│
                    │   direct / proxy:<出口> / block   │
                    │   每次决策带 trace                │
                    └──────────────┬───────────────────┘
                                   ▼
                       mihomo 官方二进制（SOCKS5 对接）
                       绝不 fork，避免长期 rebase 负担
```

### 三层分流（用户零配置）

1. **手机侧** `ExcludedDomains`：国内头部域名根本不出手机，直连最快
2. **网关侧**：凡到达网关的连接都带明确目的地，用完整规则库（ChinaMax + GEOIP）判定
3. **自学习**：反复经过网关的国内域名回填第一层名单

> ⚠️ 第二层的 GEOIP **不是可选项**。P0 实测发现 iOS 会把裸 IP 直接交给网关
> （Twitter / Dropbox / XMPP 推送 / WhatsApp IPv6），这类流量没有域名可匹配，
> 绕不过手机侧名单，必须靠 CIDR 判定归属。

---

## 使用

```bash
5gpnd run     -c /etc/5gpn-next/config.json       # 启动网关
5gpnd probe   -c /etc/5gpn-next/config.json <目标> # 端到端诊断
5gpnd profile -c /etc/5gpn-next/config.json -o x.mobileconfig
```

### `probe`：可自助排障

P0 期间出现过一次真实故障：WhatsApp 商业版注册提示「没有互联网连接」，
真实原因是「出口无 IPv6 + 拨号超时 10s」。普通用户不可能查出来。

```
$ 5gpnd probe -c config.json chatgpt.com
[1] 入口   probe 本地发起（跳过 Relay 鉴权）            ✅     0.0ms
[2] 策略   FINAL [域名] → 代理:默认                     ✅     0.1ms
[3] 出口   DIRECT（IPv6 能力=false）                    ✅     0.0ms
[4] 连接   TCP 104.18.x.x:443 已建立                    ✅   132.4ms
[5] 应用   TLS 1.3 ALPN=h2 证书校验通过                 ✅    61.2ms
结论：正常（总计 193.7ms）
```

---

## 设计约束（来自 P0 实测）

- **拨号超时 4s**：10s 会让 App 判定「没有互联网连接」
- **IPv6 fail-fast**：出口无 v6 时对 IPv6 字面量立刻返回 502，
  让 Happy Eyeballs 秒切 IPv4
- **PvD 端点必须实现**：iOS 装上 Relay 后会主动 `GET /.well-known/pvd`（RFC 8801）
- **`RelayUUID` 必须稳定**：否则 iPhone 上会堆积多份配置
- **`UIToggleEnabled` / `AllowDNSFailover`（iOS 26+）必须开**：
  前者让用户可自行关闭，后者保证 Relay 故障时不整机断网
- **h1 CONNECT 必须 Hijack**：用 ResponseWriter 流式写会得到零字节隧道

---

## 前提条件

本项目依赖特定拓扑，不是通用代理工具：

- 一台境外 VPS（网关）
- **运营商定向内网卡**（目前实测为浙江联通），手机流量经运营商私网到达 VPS，
  源 IP 为固定私有段 `172.22.0.0/16`
- 一个可自行修改解析记录的域名（签发 Let's Encrypt 证书）

没有内网卡则不适用。

---

## 许可

MIT · 仅供学习与合法网络管理用途，使用者自行承担责任。

本项目与任何 VPS 服务商、卡商无隶属关系。
