#!/usr/bin/env python3
"""Dump all dex strings + interesting assets to loot/dexstr/<name>.txt for rg mining."""
import re
import sys
import zipfile
from pathlib import Path

APK_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent.parent / "loot" / "dexstr"
OUT.mkdir(parents=True, exist_ok=True)

ASSET_EXT = (".json", ".txt", ".conf", ".cfg", ".yaml", ".yml", ".properties",
             ".list", ".csv", ".ovpn", ".html", ".js")


def main():
    apks = sorted(APK_DIR.glob("*.apk"))
    for apk in apks:
        dst = OUT / (apk.stem + ".txt")
        if dst.exists():
            continue
        buf = []
        try:
            with zipfile.ZipFile(apk) as z:
                for n in z.namelist():
                    low = n.lower()
                    if low.endswith(".dex"):
                        raw = z.read(n)
                        for m in re.finditer(rb"[\x20-\x7e]{5,500}", raw):
                            buf.append(m.group().decode("utf-8", "ignore"))
                    elif low.endswith(ASSET_EXT) or low.startswith("assets/"):
                        try:
                            data = z.read(n)
                            if len(data) < 262144:
                                buf.append(f"@@FILE {n} ({len(data)}B)")
                                try:
                                    buf.append(data.decode("utf-8", "ignore")[:20000])
                                except Exception:
                                    pass
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            buf.append("!!BADZIP")
        dst.write_text("\n".join(buf), encoding="utf-8", errors="ignore")
        print(f"{apk.stem}: {len(buf)} lines -> {dst.name}")


if __name__ == "__main__":
    main()
