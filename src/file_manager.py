import os
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

from config import load_config
from crypto import derive_cek, derive_subkey
from image_processor import encode_image_to_qoi, decode_qoi_to_image, convert_image_to_bytes
from time_utils import get_current_time_with_fallback, validate_expiry_time

MAGIC = b"IMAGED"

class TTLFileManager:
    """Handles TTL file operations including encryption/decryption."""
    
    def __init__(self):
        self.cfg = load_config()
    
    def create_ttl_file(self, input_path: str, expiry_ts: int = None, output_path: str = None) -> str:
        """Convert image to TTL format with encryption."""
        import time
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        default_h = self.cfg.get("default_ttl_hours", 1)
        out_dir = self.cfg.get("output_dir", "")
        logging.info("create_ttl_file: %s (default %dh)", input_path, default_h)

        if expiry_ts is None:
            expiry_ts = int(time.time() + default_h * 3600)

        stem = Path(input_path).stem
        if output_path is None:
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
                output_path = str(Path(out_dir) / f"{stem}.ttl")
            else:
                output_path = str(Path(input_path).with_suffix(".ttl"))

        # Encode image to QOI
        qoi_data = encode_image_to_qoi(input_path)
        
        # Keys and header
        salt = os.urandom(16)
        cek = derive_cek(salt)
        key_hdr = derive_subkey(salt, b"ImAged HDR")
        header = struct.pack(">Q", expiry_ts)

        # Authenticate header with AES-GCM (empty plaintext, header as AAD)
        aes_hdr = AESGCM(key_hdr)
        nonce_hdr = os.urandom(12)
        tag_hdr_only = aes_hdr.encrypt(nonce_hdr, b"", header)  # returns 16-byte tag
        tag_hdr = tag_hdr_only  # length 16

        # Encrypt body, binding to header (AAD)
        aes_body = AESGCM(cek)
        nonce_body = os.urandom(12)
        body_ct_and_tag = aes_body.encrypt(nonce_body, qoi_data, header)
        ciphertext_body, tag_body = body_ct_and_tag[:-16], body_ct_and_tag[-16:]

        # Write TTL file: MAGIC|salt|nonce_hdr|header|tag_hdr|nonce_body|tag_body|ciphertext_body
        with open(output_path, "wb") as f:
            f.write(MAGIC)
            f.write(salt)
            f.write(nonce_hdr)
            f.write(header)
            f.write(tag_hdr)
            f.write(nonce_body)
            f.write(tag_body)
            f.write(ciphertext_body)

        logging.info("Wrote TTL %s (exp %d)", output_path, expiry_ts)
        return output_path

    def open_ttl_file(self, input_path: str, cleanup_callback=None) -> Tuple[bytes, bool]:
        """Open and decrypt TTL file, return image bytes and fallback flag."""
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        logging.info("open_ttl_file: %s", input_path)
        
        try:
            with open(input_path, "rb") as f:
                data = f.read()

            # Minimum size for new layout: MAGIC|salt|nonce_hdr|header|tag_hdr|nonce_body|tag_body
            min_len = len(MAGIC) + 16 + 12 + 8 + 16 + 12 + 16
            if len(data) < min_len:
                raise ValueError("Invalid TTL file (too short)")

            off = 0
            magic = data[off:off+len(MAGIC)]; off += len(MAGIC)
            if magic != MAGIC:
                raise ValueError("Not an ImAged file")
            salt = data[off:off+16]; off += 16

            base = off
            nonce_hdr   = data[base:base+12]
            cand_header = data[base+12:base+20]
            cand_taghdr = data[base+20:base+36]

            key_hdr = derive_subkey(salt, b"ImAged HDR")
            aes_hdr = AESGCM(key_hdr)
            try:
                # Verify header tag (AAD=cand_header, empty plaintext)
                aes_hdr.decrypt(nonce_hdr, cand_taghdr, cand_header)
            except Exception:
                raise ValueError("Invalid TTL format")

            # Early expiry check
            expiry_ts = struct.unpack(">Q", cand_header)[0]
            current_time, fallback = get_current_time_with_fallback()
            if current_time > expiry_ts:
                raise ValueError(f"File expired on {datetime.fromtimestamp(expiry_ts)}")

            # Decrypt body bound to header (AAD=cand_header)
            if len(data) < base + 36 + 12 + 16:
                raise ValueError("Invalid TTL file (truncated)")
            nonce_body = data[base+36:base+48]
            tag_body   = data[base+48:base+64]
            ciphertext_body = data[base+64:]

            cek = derive_cek(salt)
            aes_body = AESGCM(cek)
            try:
                qoi_data = aes_body.decrypt(nonce_body, ciphertext_body + tag_body, cand_header)
            except Exception:
                raise ValueError("Authentication failed")
            
            return qoi_data, fallback

        except Exception as e:
            if cleanup_callback:
                cleanup_callback()
            raise

    def save_image_as_png(self, source_path: str, destination_path: str) -> None:
        """Save image as PNG to specified location."""
        shutil.copy(source_path, destination_path)
        logging.info("Saved PNG: %s", destination_path)

    def debug_build_ttl_stages(self, input_path: str, expiry_ts: int | None = None):
        import time, struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Stage 0: original image bytes (PNG bytes from disk)
        with open(input_path, "rb") as f:
            original_bytes = f.read()

        # Stage 1: QOI encode
        qoi_data = encode_image_to_qoi(input_path)

        # Keys and header
        salt = os.urandom(16)
        cek = derive_cek(salt)
        key_hdr = derive_subkey(salt, b"ImAged HDR")
        if expiry_ts is None: expiry_ts = int(time.time() + self.cfg.get("default_ttl_hours", 1) * 3600)
        header = struct.pack(">Q", expiry_ts)

        # Stage 2: header auth material
        aes_hdr = AESGCM(key_hdr)
        nonce_hdr = os.urandom(12)
        tag_hdr = aes_hdr.encrypt(nonce_hdr, b"", header)  # 16 bytes

        # Stage 3: body encryption
        aes_body = AESGCM(cek)
        nonce_body = os.urandom(12)
        ct_body = aes_body.encrypt(nonce_body, qoi_data, header)  # ciphertext||tag

        # Stage 4: final file layout bytes in memory
        final_bytes = b"".join([
            MAGIC, salt, nonce_hdr, header, tag_hdr, nonce_body, ct_body[-16:], ct_body[:-16]
        ])

        return {
            "original": original_bytes,
            "qoi": qoi_data,
            "salt": salt,
            "header": header,
            "nonce_hdr": nonce_hdr,
            "tag_hdr": tag_hdr,
            "nonce_body": nonce_body,
            "ciphertext_body": ct_body[:-16],
            "tag_body": ct_body[-16:],
            "final_file": final_bytes,
        }

    def debug_open_ttl_stages(self, ttl_path: str):
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        with open(ttl_path, "rb") as f:
            data = f.read()

        off = len(MAGIC)
        salt = data[off:off+16]; off += 16
        nonce_hdr = data[off:off+12]; off += 12
        header = data[off:off+8]; off += 8
        tag_hdr = data[off:off+16]; off += 16
        nonce_body = data[off:off+12]; off += 12
        tag_body = data[off:off+16]; off += 16
        ciphertext_body = data[off:]

        key_hdr = derive_subkey(salt, b"ImAged HDR")
        AESGCM(key_hdr).decrypt(nonce_hdr, tag_hdr, header)  # verify

        cek = derive_cek(salt)
        qoi_data = AESGCM(cek).decrypt(nonce_body, ciphertext_body + tag_body, header)

        return {
            "file_bytes": data,
            "salt": salt,
            "header": header,
            "nonce_hdr": nonce_hdr,
            "tag_hdr": tag_hdr,
            "nonce_body": nonce_body,
            "tag_body": tag_body,
            "ciphertext_body": ciphertext_body,
            "qoi": qoi_data,
        }