# new-api 代理池对接指南（VPN-Batch2 · YoloBase 白标系）

面向：执行对接的会话/运维。本仓库节点当前**全部为死节点**，本文档给的是
「池文件契约 + 收割流水线 + 复活检测」三件套——按此流水线跑，节点复活当天即可自动入池。

---

## 0. 现状一句话

- 收割面：8 家后端 API 全活，`tools/yoloclient.py` 可随时重收割 200+ 节点（含凭证）。
- 节点面：2026-11-12 实证 166 节点全死（check-host 多地区 + SS AEAD 握手双确认）。
- 所以对接动作是：**先接管道，不接死节点**。管道用「复活检测流水线」按需产节点。

## 1. 池文件契约（new-api 硬约束，不是我们的约定）

`data/pool/yolobase_family_pool.txt` 已按契约生成；new-api 吃的池文件格式：

```
# 注释整行（# 必须顶格，不支持行尾注释）
socks5://1.2.3.4:1080
socks5h://5.6.7.8:1080
```

| 项 | 事实 |
|---|---|
| 解析 | 逐行整行 `url.Parse`，失败整行丢弃 |
| scheme 白名单 | `http` / `https` / `socks5` / `socks5h` |
| 去重 | new-api 不做，需产出侧保证 |
| 卡片名 | `filepath.Base(file)` —— 一个池一个文件名，同名互相覆盖 |

**注意**：本仓库节点是 `ss://aes-256-gcm` 形态，new-api 的 `TRYINGOPEN_PROXY_FILE`
只吃 `socks5://`——**必须经 mihomo/sing-box 桥一层**（每节点一个 socks listener），
不能直写 `ss://`。桥接配置见 §3.2。

## 2. new-api 侧配置

```bash
# 单池
TRYINGOPEN_PROXY_FILE=/data/pools/yolobase.txt

# 多池（逗号分隔，文件名必须不同）
TRYINGOPEN_PROXY_FILE=/data/pools/yolobase.txt,/data/pools/kernel.txt
```

坑（实战验证过）：
1. **Docker 内 `127.0.0.1` 指容器自身**。mihomo 桥跑在宿主机时，池文件写宿主机在
   容器网络里可达的地址（`host.docker.internal` 或宿主 IP）。
2. 国内 DNS 污染场景用 `socks5h://`（远端解析域名）。
3. 热更新 `POST /api/twoapi_panel/proxy_pool/reload` —— 先 curl 确认当前版本有没有
   这个接口；没有就重启进程。

## 3. 节点产出流水线（仓库已内置）

### 3.1 收割（①）

```bash
cd VPN-Batch2-31apk
python tools/yoloclient.py                          # Eto 冒烟
# 或起 demo 一键收割八家：
python demo/demo_server.py                          # http://127.0.0.1:8933
curl http://127.0.0.1:8933/api/reharvest            # 返回 8 家 {nodes, error}
```

产出：每家 `/cfg/olduser + /cfg/newuser + /cfg/lowuser` 三层节点合并去重，
字段 `server / server_port / password / method(aes-256-gcm)`。

### 3.2 桥接（②）ss:// → socks5://

节点是标准 Shadowsocks AEAD，用 mihomo 单进程多 listener（已验证模式）：

```yaml
# mihomo.yaml 骨架 —— 每节点生成一个 listener，绑定 127.0.0.1:45200+i
listeners:
  - name: node0
    type: socks
    port: 45200
    proxy: "47.x.x.x:443"     # 引用下方 proxies 里的节点名
proxies:
  - name: "eto-london"
    type: ss
    server: 143.110.162.99
    port: 13049
    cipher: aes-256-gcm
    password: "4e1712f35fe98d7809c9c1cf9b07161d"
    udp: true
```

生成器逻辑参考 `demo/demo_server.py` 的 `reharvest()`（收割结果直接转 mihomo YAML
即可，~30 行 Python）。

### 3.3 复活检测（③）三关全过才写池

```
① 收割   yoloclient.py            → nodes_raw
② 端口   check-host check-tcp     → ≥2 地区 TCP 开放（DNS/GFW 假死过滤）
③ 握手   mihomo 桥 + curl 经代    → gstatic 204 + 出口 IP == 节点 IP
```

第③关是铁律（历史教训）：
- TCP/TLS 通 ≠ 活。本批 3 个 TCP 开放节点全部死在 SS 握手。
- 出口 IP 必须等于节点自身 IP，否则是中间转发不是真隧道。
- `trust_env=False`——本机有 v2rayN/Clash 时 requests 会走系统代理污染全部结果。

### 3.4 写池

```
mihomo listeners → 拨测 → 只写第③关通过的: socks5://127.0.0.1:4520x → 池文件
→ new-api TRYINGOPEN_PROXY_FILE 指向该文件 → reload / 重启 → 验收
```

## 4. 验收清单

- [ ] `curl http://127.0.0.1:8933/api/reharvest` 返回 8 家 JSON
- [ ] 至少 1 家 `error: 0` 且 `nodes > 0`（TapByte/Rocket 目前 Banned 属预期）
- [ ] 池文件每行可被 `url.Parse` 解析、无重复、注释顶格
- [ ] mihomo `listeners` 全部 LISTENING，`netstat -ano | findstr 4520` 无端口冲突
- [ ] 经桥 `curl --socks5-hostname` 拿到出口 IP == 节点 IP
- [ ] new-api 来源卡片显示池文件名，选中测试渠道返回成功

## 5. 责任边界

- 本会话交付止于：收割工具 + 复活检测流水线 + 池文件契约 + 桥接骨架。
- new-api 侧配置、reload 验证、Docker 网络适配由对接会话执行。
- 本仓库节点 `ss_type=vps` 属上游自营基础设施——复活后接入生产池的取舍
  （盗用风险）需运营方拍板，文档不替你决定。
