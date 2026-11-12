#!/usr/bin/env python
"""SOCKS5 代理池压测 CLI（与 demo/demo_server.py 同一套判定口径）。

两种用法：

  单个代理验活（拿出口 IP，和节点自身 IP 比对）：
      python -I tools/stress_pool.py --proxy socks5://HOST:PORT
      python -I tools/stress_pool.py --proxy socks5://HOST:PORT --target www.gstatic.com:443

  整池压测：
      python -I tools/stress_pool.py --pool data/proxies.txt --concurrency 8 --rounds 3

判定口径：SOCKS5 CONNECT 成功只算第一层；带 --ip-check 时追加一次
`http://ip-api.com/json` 取真实出口 IP，两个都通过才算活。

全部走裸 socket，不读 HTTP_PROXY / HTTPS_PROXY，不影响本机系统代理。
"""
import argparse
import json
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

EXIT_IP_HOST = "ip-api.com"
EXIT_IP_PATH = "/json/?fields=status,country,countryCode,query,isp"


def socks5_open(proxy_host, proxy_port, dst_host, dst_port, timeout=10.0):
    """建立 SOCKS5 CONNECT，返回 socket（调用方负责关闭）。"""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise OSError("socks5 auth rejected")
    h = dst_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dst_port))
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        s.close()
        raise OSError("socks5 connect reject code=%s" % (head[1] if len(head) > 1 else "?"))
    atyp = head[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        s.recv(s.recv(1)[0])
    elif atyp == 4:
        s.recv(16)
    s.recv(2)
    return s


def http_get_over(sock, host, path):
    sock.sendall(
        ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpnbatch/1.0\r\nConnection: close\r\n\r\n"
         % (path, host)).encode()
    )
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    head, _, body = buf.partition(b"\r\n\r\n")
    status = 0
    first = head.split(b"\r\n", 1)[0].split()
    if len(first) > 1 and first[1].isdigit():
        status = int(first[1])
    return status, body


def check_one(proxy_url, target_host, target_port, ip_check, timeout=10.0):
    t0 = time.time()
    out = {"proxy": proxy_url, "ok": False, "ms": 0.0, "exit_ip": "", "err": ""}
    if "://" not in proxy_url:
        out["err"] = "not a url"
        return out
    scheme, rest = proxy_url.split("://", 1)
    if scheme not in ("socks5", "socks5h"):
        out["err"] = "scheme %s unsupported" % scheme
        return out
    phost, _, pport = rest.rpartition(":")
    try:
        pport = int(pport)
    except ValueError:
        out["err"] = "bad port"
        return out

    try:
        if ip_check:
            s = socks5_open(phost, pport, EXIT_IP_HOST, 80, timeout)
            try:
                status, body = http_get_over(s, EXIT_IP_HOST, EXIT_IP_PATH)
            finally:
                s.close()
            if status != 200:
                out["err"] = "exit-ip http %d" % status
                return out
            info = json.loads(body.decode("utf-8", "replace"))
            if info.get("status") != "success":
                out["err"] = "exit-ip rejected"
                return out
            out["exit_ip"] = info.get("query", "")
            out["exit_country"] = info.get("countryCode", "")
        else:
            s = socks5_open(phost, pport, target_host, target_port, timeout)
            s.close()

        out["ok"] = True
        out["ms"] = round((time.time() - t0) * 1000, 1)
    except Exception as e:
        out["ms"] = round((time.time() - t0) * 1000, 1)
        out["err"] = "%s: %s" % (type(e).__name__, str(e)[:80])
    return out


def read_pool(path):
    urls = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except OSError as e:
        print("cannot read pool: %s" % e, file=sys.stderr)
    return urls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", help="单个 socks5://host:port")
    ap.add_argument("--pool", default="data/proxies.txt", help="池文件路径")
    ap.add_argument("--target", default="www.gstatic.com:443", help="仅做连通性时的目标 host:port")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--ip-check", action="store_true", help="追加出口 IP 比对（经 ip-api.com）")
    ap.add_argument("--json-out", help="把结果写到指定文件")
    args = ap.parse_args()

    if args.proxy:
        thost, _, tport = args.target.rpartition(":")
        r = check_one(args.proxy, thost, int(tport or 443), args.ip_check)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump([r], f, ensure_ascii=False, indent=2)
        return 0 if r["ok"] else 1

    urls = read_pool(args.pool)
    if not urls:
        print(json.dumps({"entries": 0, "pool": args.pool, "note": "pool is empty"}))
        return 0

    thost, _, tport = args.target.rpartition(":")
    tport = int(tport or 443)
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for _ in range(max(1, args.rounds)):
            results.extend(ex.map(
                lambda u: check_one(u, thost, tport, args.ip_check), urls))

    alive = [r for r in results if r["ok"]]
    summary = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pool": args.pool,
        "entries": len(urls),
        "rounds": args.rounds,
        "attempts": len(results),
        "ok": len(alive),
        "success_rate": round(len(alive) / len(results) * 100, 1) if results else 0.0,
        "avg_ms": round(sum(r["ms"] for r in alive) / len(alive), 1) if alive else None,
        "elapsed_s": round(time.time() - t0, 1),
        "exit_ips": sorted({r["exit_ip"] for r in alive if r.get("exit_ip")}),
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())