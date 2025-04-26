import time
import argparse
from PIL import Image
import numpy as np
import qoi

# === File‑format constants ===
MAGIC    = b"IMAG"          # 4 bytes: ASCII signature
VERSION  = b"\x01"          # 1 byte: format version
FLAGS    = b"\x00\x00\x00"  # 3 bytes reserved

def make_ttl(input_path: str, ttl_seconds: int, output_path: str = None):
    # 1) Load the image and convert to RGBA
    img = Image.open(input_path).convert("RGBA")
    arr = np.array(img)  # H×W×4 uint8

    # 2) QOI‑compress the RGBA array
    qoi_bytes = qoi.encode(arr)

    # 3) Build the unencrypted header
    now    = int(time.time())
    expire = now + ttl_seconds
    header = (
        MAGIC
      + VERSION
      + FLAGS
      + now.to_bytes(8, "big")
      + expire.to_bytes(8, "big")
      + len(qoi_bytes).to_bytes(4, "big")
    )

    # 4) Write out the .ttl file
    out = output_path or input_path.rsplit(".", 1)[0] + ".ttl"
    with open(out, "wb") as f:
        f.write(header)
        f.write(qoi_bytes)

    print(f"Wrote TTL file → {out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Encode an image to ImAged .ttl (header + QOI payload, no encryption yet)"
    )
    parser.add_argument("input", help="Path to PNG/JPEG")
    parser.add_argument("--ttl", type=int, default=3600, help="Lifetime in seconds")
    parser.add_argument("--out", help="Optional output filename override")
    args = parser.parse_args()

    make_ttl(args.input, args.ttl, args.out)
