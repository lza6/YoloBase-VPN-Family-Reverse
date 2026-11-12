#!/usr/bin/env python3
"""Batch triage for VPN APKs: package/version/engine/URL/credential-signature extraction.

Pure-python dex string scan (no jadx dependency). Writes data/triage/<name>.json
plus a combined data/triage/summary.tsv ranked by "harvestability" score.

Rules (from .claude/skills/apk-vpn-node-harvest/SKILL.md):
- libbox.so / libv2ray* / libgojni.so  -> standard core, nodes delivered by backend
- ss:// vless:// vmess:// trojan:// hysteria2:// in dex/assets -> instant harvest
- account/api hostnames -> follow-up targets
"""
import json
import re
import sys
import zipfile
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "triage"

APK_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#@!&*+,;=%-]{4,120}")
SCHEME_RE = re.compile(
    r"\b(ss|vless|vmess|trojan|hysteria2?|socks5|wireguard|tuic)://[^\s\"'<>\\]{4,300}"
)
HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.-]{3,60}\.(?:com|net|org|io|site|xyz|top|shop|tech|app|dev|cloud|vip|me|cc|pro|online|fun|space|store|icu|click|link|info|biz))\b", re.I)

ENGINES = {
    "libbox.so": "sing-box",
    "libv2ray.so": "v2ray",
    "libgojni.so": "gomobile-go",
    "libopenvpn.so": "openvpn",
    "libovpn3.so": "openvpn3",
    "libcharon.so": "strongswan-ikev2",
    "libipsec.so": "strongswan-ikev2",
    "libtrojan.so": "trojan",
    "libtun2socks.so": "tun2socks",
    "libhev": "hev-tunnel",
    "libsagernet": "sagernet",
    "libwireguard.so": "wireguard",
    "libwg.so": "wireguard",
    "libleaf.so": "leaf",
    "libxray.so": "xray",
    "libjni.so": "jni-native",
}

CRED_HINTS = [
    "private_key", "privateKey", "PSK", "password", "uuid", "secret",
    "auth", "token", "cert", "identity",
]

PROTO_PORTS = {
    "ss": (8388, 8443, 443, 80, 8000, 9000),
    "vless": (443, 2053, 2083, 2087, 2096, 8443),
    "vmess": (443, 80, 8880, 2052, 2082, 2086, 8080),
    "trojan": (443, 8443, 2053),
    "hysteria2": (443, 8443, 36712),
}


def scan_apk(path: Path) -> dict:
    info = {
        "file": path.name,
        "size_mb": round(path.stat().st_size / 1048576, 1),
        "package": None,
        "versionName": None,
        "versionCode": None,
        "engines": [],
        "libs": [],
        "dex_count": 0,
        "asset_files": 0,
        "urls": {},
        "hosts": {},
        "schemes": {},
        "cred_hints": [],
        "score": 0,
        "notes": [],
    }

    dexstrings = []
    all_assets_text = []

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            info["dex_count"] = sum(1 for n in names if n.endswith(".dex"))
            lib_names = [n for n in names if n.startswith("lib/")]
            for n in lib_names:
                base = n.rsplit("/", 1)[-1]
                if base not in info["libs"]:
                    info["libs"].append(base)
                for key, eng in ENGINES.items():
                    if key in base and eng not in info["engines"]:
                        info["engines"].append(eng)
            assets = [n for n in names if n.startswith("assets/")]
            info["asset_files"] = len(assets)

            # manifest: package / version from AndroidManifest (binary XML)
            try:
                mf = z.read("AndroidManifest.xml")
                # package attr often appears as UTF-16LE in binary axml
                m = re.search(rb"(?:\x00)?(?:p\x00a\x00c\x00k\x00a\x00g\x00e\x00)", mf)
                # Fallback: UTF-8 style strings in the binary XML
                for sm in re.finditer(rb"[\x20-\x7e]{5,200}", mf):
                    s = sm.group().decode("ascii", "ignore")
                    if info["package"] is None and re.match(r"^[a-z][a-z0-9_]+(\.[a-z0-9_]+){2,}$", s):
                        info["package"] = s
                        break
            except KeyError:
                pass

            for n in names:
                low = n.lower()
                if low.endswith(".dex"):
                    raw = z.read(n)
                    for m in re.finditer(rb"[\x20-\x7e]{5,300}", raw):
                        dexstrings.append(m.group().decode("utf-8", "ignore"))
                    if len(dexstrings) > 3_500_000:
                        break
                elif low.endswith((".json", ".txt", ".conf", ".cfg", ".yaml", ".yml", ".properties", ".xml", ".ovpn", ".list", ".csv")):
                    try:
                        all_assets_text.append((n, z.read(n).decode("utf-8", "ignore")))
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        info["notes"].append("BAD ZIP")
        return info

    text_blob = "\n".join(dexstrings) + "\n" + "\n".join(t for _, t in all_assets_text)

    # URLs
    for u in URL_RE.findall(text_blob):
        u = u.rstrip(".,;")
        info["urls"][u] = info["urls"].get(u, 0) + 1

    # credential scheme links (the money)
    for s in SCHEME_RE.findall(text_blob):
        full = s[0] + "://" + s[1]
        info["schemes"].setdefault(full.split("@")[-1][:60], []).append(full[:300])

    # hosts
    for h in HOST_RE.findall(text_blob):
        h = h.lower()
        if h.endswith((".png", ".jpg", ".gif", ".css", ".js", ".woff", ".ttf", ".so", ".mp4", ".webp", ".svg")):
            continue
        info["hosts"][h] = info["hosts"].get(h, 0) + 1

    joined = "\n".join(dexstrings).lower()
    for hint in CRED_HINTS:
        c = joined.count(hint.lower())
        if c > 3:
            info["cred_hints"].append(f"{hint}:{c}")

    # ---- scoring: how likely we can harvest usable proxies statically ----
    score = 0
    engine_set = set(info["engines"])
    has_std_core = bool(engine_set & {"sing-box", "v2ray", "gomobile-go", "xray", "leaf"})
    schemes_n = sum(len(v) for v in info["schemes"].values())
    if schemes_n:
        score += 50 + min(schemes_n, 20)
    if has_std_core:
        score += 15
    if engine_set & {"openvpn", "openvpn3", "strongswan-ikev2"}:
        score += 8
    # ovpn/config assets are harvestable if they contain remote host lines
    for n, t in all_assets_text:
        if n.endswith(".ovpn") or "remote " in t[:4000]:
            score += 10
            info["notes"].append(f"asset-with-remote:{n}")
            break
    api_hosts = [h for h in info["hosts"] if not any(
        h.endswith(d) for d in (
            "google.com", "gstatic.com", "googleapis.com", "firebaseio.com", "crashlytics.com",
            "facebook.com", "adjust.com", "appsflyer.com", "doubleclick.net", "admob.com",
            "unity3d.com", "applovin.com", "ironsrc.com", "chartboost.com", "vungle.com",
            "adcolony.com", "inmobi.com", "tapjoy.com", "facebook.net", "android.com",
            "twitter.com", "x.com", "instagram.com", "youtube.com", "github.com",
            "apache.org", "w3.org", "example.com", "schemas.microsoft.com",
        ))]
    info["api_hosts"] = sorted(set(api_hosts), key=lambda h: -info["hosts"][h])[:40]
    if info["api_hosts"]:
        score += min(len(info["api_hosts"]), 8)
    info["score"] = score
    return info


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    apks = sorted(APK_DIR.glob("*.apk"))
    if not apks:
        print("no apk found", file=sys.stderr)
        sys.exit(1)
    rows = []
    for apk in apks:
        try:
            info = scan_apk(apk)
        except Exception as e:
            info = {"file": apk.name, "error": str(e), "score": -1}
        (OUT_DIR / f"{apk.stem}.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        rows.append(info)
        eng = ",".join(info.get("engines", []))[:40]
        nsch = sum(len(v) for v in info.get("schemes", {}).values())
        print(f"[{info.get('score', -1):>3}] {apk.name[:52]:<52} pkg={str(info.get('package'))[:44]:<44} engines={eng:<40} schemes={nsch}")

    rows.sort(key=lambda r: -r.get("score", -1))
    with open(OUT_DIR / "summary.tsv", "w", encoding="utf-8") as f:
        f.write("score\tfile\tpackage\tengines\tschemes\tapi_hosts\n")
        for r in rows:
            f.write(f"{r.get('score',-1)}\t{r['file']}\t{r.get('package') or '?'}\t"
                    f"{';'.join(r.get('engines', []))}\t"
                    f"{sum(len(v) for v in r.get('schemes', {}).values())}\t"
                    f"{len(r.get('api_hosts', []))}\n")
    print(f"\n{len(rows)} apk triaged -> {OUT_DIR}/summary.tsv")


if __name__ == "__main__":
    main()
