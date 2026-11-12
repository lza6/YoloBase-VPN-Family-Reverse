#!/usr/bin/env python3
"""YoloBase protocol client: replicate Eto-family VPN app crypto.

Key chain (fully reversed from com.yolo.networklibrary):
  AES key  = MD5( lsb-hex-string( asset PNG ) ).encode()   # 32 hex chars -> 32 ASCII bytes
  lsb-hex  = for each 4-byte group (b0,b1,b2,b3): hex( int(f"{b0&1}{b1&1}{b2&1}{b3&1}", 2) )
             (trailing bytes beyond len%4 are dropped)
  Request  = JSON body -> AES-CBC/PKCS5(key, random 16-char alnum IV) -> body_b64
  Headers  = X-Yolo-Auth: <IV>        Authorization: HmacMD5(body_b64, hmacMd5Key)
             x-token: headerXToken (business usually empty, common = "xDk}g>Z#~:!b12B")
  Response = X-Yolo-Auth header carries the SAME IV; body = b64(AES-CBC(...))
             decrypt with the SAME channel key; empty header = plaintext body.
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import random
import string
import sys
from pathlib import Path

import requests

LOOT = Path(__file__).resolve().parent.parent / "loot"


def lsb_hex_string(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - (len(data) % 4), 4):
        bits = (data[i] & 1, data[i + 1] & 1, data[i + 2] & 1, data[i + 3] & 1)
        val = int("".join(map(str, bits)), 2)
        out.append(format(val, "x"))
    return "".join(out)


def derive_key(png_path: Path) -> bytes:
    raw = png_path.read_bytes()
    return MD5(lsb_hex_string(raw)).encode("ascii")


def MD5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def hmac_md5_hex(msg: str, key: str) -> str:
    return hmac_mod.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.md5).hexdigest()


def pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs5_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    def aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        if encrypt:
            e = c.encryptor()
            p = PKCS7(128).padder()
            return e.update(p.update(data) + p.finalize()) + e.finalize()
        d = c.decryptor()
        dec = d.update(data) + d.finalize()
        u = PKCS7(128).unpadder()
        return u.update(dec) + u.finalize()
except ImportError:
    try:
        from Crypto.Cipher import AES as PyCryptoAES
        from Crypto.Util.Padding import pad, unpad

        def aes_cbc(key, iv, data, encrypt):
            c = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC, iv)
            if encrypt:
                return c.encrypt(pad(data, 16))
            return unpad(c.decrypt(data), 16)
    except ImportError:
        sys.exit("need: pip install cryptography  (or pycryptodome)")


class YoloClient:
    def __init__(self, host_url, hmac_key, asset_png, x_token="", timeout=25):
        self.host = host_url.rstrip("/")
        self.hmac_key = hmac_key
        self.x_token = x_token
        self.key = derive_key(LOOT / asset_png) if asset_png else None
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False  # never touch system proxy (v2rayN on 10808)

    def _crypt(self, data: bytes, iv: bytes, encrypt: bool) -> bytes:
        return aes_cbc(self.key, iv, data, encrypt)

    def post(self, path, payload: dict):
        url = self.host + path
        iv = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        enc = self._crypt(body, iv.encode(), encrypt=True)
        body_b64 = base64.b64encode(enc).decode()
        auth = hmac_md5_hex(body_b64, self.hmac_key)
        headers = {
            "Content-Type": "application/json",
            "X-Yolo-Auth": iv,
            "Authorization": auth,
            "x-token": self.x_token,
            "User-Agent": "okhttp/4.9.3",
        }
        r = self.session.post(url, headers=headers, data=body_b64, timeout=self.timeout)
        return self._parse(r)

    def _parse(self, r):
        iv = r.headers.get("X-Yolo-Auth")
        raw = r.content
        if iv:
            try:
                dec = self._crypt(base64.b64decode(raw), iv.encode(), encrypt=False)
                text = dec.decode("utf-8", "replace")
            except Exception as e:
                return {"_status": r.status_code, "_error": f"decrypt: {e}", "_raw": raw[:200]}
        else:
            text = raw.decode("utf-8", "replace")
        try:
            return {"_status": r.status_code, "_json": json.loads(text)}
        except Exception:
            return {"_status": r.status_code, "_text": text[:2000]}


def base_request_payload(pkg="com.eto.proxy.net"):
    return {
        "ts": 1731400000, "did": "8f14e45fceea167a5a36dedd4bea2543",
        "pkg": pkg, "cv": "4.3.7", "lang": "en", "mcc": "310", "mnc": "004",
        "install_source": "unknown", "is_rooted": False, "is_vpn_used": False,
        "phone_brand": "Google", "phone_model": "Pixel 6", "os_ver": "13", "os": "Android",
    }


if __name__ == "__main__":
    # Eto Net Proxy smoke test
    c = YoloClient("https://eto.zoartechnology.net", "aqOpd5a7WdcA6yWk", "eto.png")
    print("== /hi ==", c.post("/hi", base_request_payload()))
    print("== /cfg/newuser ==", c.post("/cfg/newuser", base_request_payload()))
