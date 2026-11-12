#!/usr/bin/env python3
"""Demo server: serves the dashboard + live YoloBase re-harvest API.

Port 8933 (batch2 slot). Never touches the system proxy (v2rayN on 10808):
- all outbound requests use Session(trust_env=False)
- the server itself binds 127.0.0.1 only
"""
import json
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))

PORT = 8933


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(BASE / "demo"), **kw)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if self.path == "/api/report":
            data = json.load(open(BASE / "demo" / "report_data.json", encoding="utf-8"))
            self._json(data)
        elif self.path == "/api/reharvest":
            # live re-harvest across the 8-family backends (safe: read-only POSTs)
            self._json(reharvest())
        else:
            super().do_GET()

    def _json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def reharvest():
    from yoloclient import YoloClient, base_request_payload, derive_key
    loot = BASE / "loot"
    family = [
        ("Eto", "https://eto.zoartechnology.net", "aqOpd5a7WdcA6yWk", "eto.png",
         "com.extra.universe.eto.turbo.vpn", "4.3.7"),
        ("World", "https://world.matrixmobile.net", "tG1PWGP1q7i4bX", "global.jpg",
         "com.smart.turbo.world.vpn", "1.3.16"),
        ("Lemon", "https://melon.freevpnapp.net", "0d8eas24f92ef080", "lemon_zz.png",
         "com.free.unlimited.lemon.vpn", "5.6.399"),
        ("Stream", "https://stream.fifavnet.net", "ioAPVQfMFYsAWBi9", "stream_zz.png",
         "com.fast.free.unlimted.stream.vpn", "1.3.473"),
        ("MATE", "https://xy.matrixmobile.net", "At5V&FE6ZLfXjj", "mate_zz.png",
         "com.mate.vpn", "5.1.552"),
        ("TapByte", "https://taptap.netsecureapp.net", "1tb3fD0kdLLP9NKT", "taptap.png",
         "com.taptap.proxy", "2.9.1"),
        ("FoxGuard", "https://foxguard.youchats.net", "341mfFs8Sx15NiMB", "foxify.png",
         "com.fox.guard.free.fast.vpn", "1.7.237"),
        ("Rocket", "https://fifavnet.net", "ioAPVQfMFYsAWBi9", "rocket_zz.png",
         "com.rocket.vpn", "3.31.051"),
    ]
    out = {}
    for label, host, key, asset, pkg, cv in family:
        try:
            c = YoloClient(host, key, None)
            png = loot / asset
            if png.exists():
                c.key = derive_key(png)
            pl = base_request_payload(pkg=pkg)
            pl["cv"] = cv
            n = 0
            err = None
            for tier in ("/cfg/olduser", "/cfg/newuser", "/cfg/lowuser"):
                r = c.post(tier, pl)
                j = r.get("_json", {})
                err = j.get("error", err)
                for g in (j.get("data") or {}).get("server_list", []) or []:
                    n += len(g.get("servers", []))
            out[label] = {"nodes": n, "error": err}
        except Exception as e:
            out[label] = {"nodes": 0, "error": f"{type(e).__name__}: {e}"}
    return out


if __name__ == "__main__":
    print(f"demo: http://127.0.0.1:{PORT}  (127.0.0.1 bind, no system-proxy contact)")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
