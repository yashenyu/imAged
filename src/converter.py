import os
import time
import socket
import struct
import tempfile
import logging
from pathlib import Path

import qoi
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import derive_cek
from config import load_config

MAGIC = b"IMAGED"

def fetch_ntp_time(timeout: int = 5) -> float | None:
    cfg = load_config()
    server = cfg.get("ntp_server", "pool.ntp.org")
    try:
        addr = (server, 123)
        msg = b"\x1b" + 47 * b"\0"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, addr)
        res, _ = s.recvfrom(1024)
        t = struct.unpack("!12I", res)[10] - 2208988800
        logging.info("NTP time from %s: %s", server, t)
        return t
    except Exception as e:
        logging.warning("NTP fetch (%s) failed: %s", server, e)
        return None

def convert_to_ttl(input_path: str, expiry_ts: int = None, output_path: str = None) -> str:
    cfg = load_config()
    default_h = cfg.get("default_ttl_hours", 1)
    out_dir   = cfg.get("output_dir", "")
    logging.info("convert_to_ttl: %s (default %dh)", input_path, default_h)

    if expiry_ts is None:
        expiry_ts = int(time.time() + default_h * 3600)

    stem = Path(input_path).stem
    if output_path is None:
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            output_path = str(Path(out_dir) / f"{stem}.ttl")
        else:
            output_path = str(Path(input_path).with_suffix(".ttl"))

    img = Image.open(input_path).convert("RGBA")
    arr = np.array(img)
    qoi_data = qoi.encode(arr)

    salt = os.urandom(16)
    cek  = derive_cek(salt)
    header    = struct.pack(">Q", expiry_ts)
    plaintext = header + qoi_data
    aesgcm    = AESGCM(cek)
    nonce     = os.urandom(12)
    ct_tag    = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    logging.info("Wrote TTL %s (exp %d)", output_path, expiry_ts)
    return output_path

def open_ttl(input_path: str) -> tuple[str,bool]:
    cfg = load_config()
    logging.info("open_ttl: %s", input_path)
    with open(input_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            logging.error("Bad magic")
            raise ValueError("Not an ImAged file")
        salt       = f.read(16)
        nonce      = f.read(12)
        tag        = f.read(16)
        ciphertext = f.read()

    cek    = derive_cek(salt)
    aesgcm = AESGCM(cek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        logging.error("Auth failure")
        raise ValueError("Authentication failed")

    expiry_ts = struct.unpack(">Q", plaintext[:8])[0]
    qoi_data  = plaintext[8:]
    ntp_time  = fetch_ntp_time()
    now, fb = (ntp_time, False) if ntp_time else (time.time(), True)
    if now > expiry_ts:
        from datetime import datetime
        dt = datetime.fromtimestamp(expiry_ts)
        logging.warning("Expired %s", dt)
        raise ValueError(f"File expired on {dt}")

    arr = qoi.decode(qoi_data)
    img = Image.fromarray(arr, mode="RGBA")
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    img.save(tmp.name)
    logging.info("Decrypted to %s (fallback=%s)", tmp.name, fb)
    return tmp.name, fb
