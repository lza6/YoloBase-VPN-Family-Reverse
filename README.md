# YoloBase 白标 VPN 八兄弟 — 逆向与代理池收割

八个 Android 白标 VPN（共享同一套 `com.yolo.networklibrary` 自建后端框架）的完整逆向：
协议链 100% 还原并复刻为可重放客户端，166 个节点全量收割（含凭证），
多地区真活验证，自动重收割 demo 服务。

**结论：节点舰队已下线（死池），但收割能力已产品化——节点复活即可自动入池。**

## 样本矩阵

| # | App | 版本 | 真实包名 | 后端 | hmacMd5Key | 节点 |
|---|---|---|---|---|---|---|
| 1 | Eto Net Proxy | 4.3.7(437) | `com.extra.universe.eto.turbo.vpn` | `eto.zoartechnology.net` | `aqOpd5a7WdcA6yWk` | 38 |
| 2 | World VPN | 1.3.16(1316) | `com.smart.turbo.world.vpn` | `world.matrixmobile.net` | `tG1PWGP1q7i4bX` | 36 |
| 3 | Lemon VPN | 5.6.399(56399) | `com.free.unlimited.lemon.vpn` | `melon.freevpnapp.net` | `0d8eas24f92ef080` | 37 |
| 4 | Stream VPN | 1.3.473(13473) | `com.fast.free.unlimted.stream.vpn` | `stream.fifavnet.net` | `ioAPVQfMFYsAWBi9` | 36 |
| 5 | MATE VPN | 5.1.552(51552) | `com.mate.vpn` | `xy.matrixmobile.net` | `At5V&FE6ZLfXjj` | 15 |
| 6 | TapByte Net | 2.9.1(291) | `com.taptap.proxy` | `taptap.netsecureapp.net` | `1tb3fD0kdLLP9NKT` | Banned |
| 7 | Fox Guard VPN | 1.7.237(17237) | `com.fox.guard.free.fast.vpn` | `foxguard.youchats.net` | `341mfFs8Sx15NiMB` | 37 |
| 8 | Rocket VPN | 3.31.051(331051) | `com.rocket.vpn` | `fifavnet.net` | `ioAPVQfMFYsAWBi9` | Invalid Pkg |

后端全部解析到 Google Cloud GLB（anycast），响应层活着、业务语义正常
（`Invalid Pkg` / `Banned Account` 按包名与设备指纹区分）。

## 协议链（已 100% 还原，见 `tools/yoloclient.py`）

```
AES key = MD5( lsb_hex( 资产PNG ) ).encode("ascii")
          # 每 4 字节取 (b0&1, b1&1, b2&1, b3&1) 拼 4bit → hex，尾部不足 4 字节丢弃
          # 例：eto.png 3677B → 919 hex chars → MD5 → 32 ASCII 字节即 AES-256 key

请求体  = JSON → AES-CBC/PKCS5(key, IV=randomAlphanumeric(16)) → Base64
Headers = X-Yolo-Auth: <IV>                    # 16 位随机字母数字
          Authorization: HmacMD5(b64, hmacMd5Key)   # hex 小写
          x-token: headerXToken               # business 通道通常空；common = "xDk}g>Z#~:!b12B"

响应    = X-Yolo-Auth 头带服务端随机 IV（16 hex），同 key 解密 Base64 密文
          # 请求 IV 与响应 IV 独立；无头 = 明文 JSON

通道    = "http_business"（业务: /cfg/* /login/*）与 "http_common"（公共: /hi /first_open）
          # 两通道各自 key（各自资产 PNG）+ 各自 hmacMd5Key

端点    = /hi /cfg/newuser /cfg/olduser /cfg/lowuser /cfg/vip /login/visitor /install_call
字段分发 = 服务端按请求体 did/pkg/mcc/utm 决定下发哪一层（newuser/olduser/lowuser）
```

节点结构（AES `server_list[].servers[]`）：`server / server_port / password / method
(aes-256-gcm) / mode(tcp_and_udp) / ss_type(vps)` —— 标准 Shadowsocks AEAD，
`libsslocal.so`（shadowsocks-rust fork）承载，无插件。

## 死池证据链

1. dex 内嵌兜底 `ss://aes-256-gcm:Y6R9pAtvxxzmGC@149.28.197.166:443`：
   实测端口已换 nginx（回 `HTTP/1.1 400 Bad Request`），纯诱饵。
2. API 层活：全链路加解密互通，节点 JSON 正常下发，密码跨请求稳定。
3. 节点层死：**166 唯一节点** check-host.net 多地区（DE/ES/HU/IL/SG/IR/VN）
   TCP 探测 **163 个端口关闭**；3 个开放的（86.48.22.32:8000 /
   149.56.142.242:13000 / 15.204.246.196:13000）xray 标准握手 + 手工 AEAD 握手 +
   新鲜凭证秒级复测**全部即刻被断连**。
4. 静默丢弃 + SYN 开放 = 面板层活、SS 后端进程不在 —— 舰队下线的典型形态。

对照实验：同路径 google.com:443 全地区通过 —— 检测器本身无假阴性。

## 复活检测流水线（三关全过才入池）

```
① 收割  python tools/yoloclient.py（或 demo :8933 /api/reharvest）
② 端口  check-host.net check-tcp ≥2 地区开放
③ 握手  mihomo/sing-box 桥成 socks5 → curl 经代 + 出口 IP == 节点 IP
```

## 仓库结构

```
tools/
  triage.py       批量分诊（包名/内核/URL/凭证签名/可收割评分）
  dexdump.py      全量 dex 字符串 + assets 转储（rg 挖掘用）
  yoloclient.py   YoloBase 协议客户端（密钥推导+AES+HMAC+重放+收割）
data/
  triage/         43 APK 分诊 JSON + summary.tsv
  all_unique_nodes.json   166 唯一节点（完整凭证）
  all_alive.json / all_checkhost.json   多地区测活结果
  pool/yolobase_family_pool.txt         166 节点复活名单（注释含状态）
demo/
  demo_server.py  :8933 看板 + /api/report + /api/reharvest 实时重收割
  index.html      看板
loot/signing-assets/   8 家签名资产 PNG（密钥推导的"钥匙胚"）
docs/
  01-深度分析.md
  02-new-api对接指南.md   ← 交给对接会话的那份
  03-方法论与复用.md
```

## 快速使用

```bash
pip install cryptography requests pysocks
python tools/yoloclient.py            # Eto 冒烟（密钥推导 + /hi + /cfg/newuser）

python demo/demo_server.py            # 看板 http://127.0.0.1:8933
curl http://127.0.0.1:8933/api/reharvest   # 八家实时重收割 JSON
```

环境红线：所有出站 `trust_env=False`；demo 只绑 127.0.0.1；不碰宿主机系统代理。

## 留尾（需模拟器 + frida 的动态样本）

| App | 架构 | 卡点 |
|---|---|---|
| Turbo VPN / Turbo Lite | AllConnected 私有 SDK（`co.allconnected.*`）+ SSR 内核 | 节点接口需设备激活态，hook `VpnAgent` |
| UFO VPN 2.5.14 | gomobile-go + hev-socks5-tunnel | 逻辑在 Go 层，hook libgojni |
| Ninja VPN 1.4.9 | gomobile-go | 同 UFO |
| Ultrasurf 3.3.6 | 自有协议（U.W.C.） | 需动态 |

Turbo 系线索：`users.acdtop.com`（summary 上报）、SSRNodeInfo{serverIp=...}、`go_out_server_list`。

## License

MIT
