import os
import shutil
import logging
import time
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

from config import load_config
from crypto import derive_cek, derive_subkey
from time_utils import get_current_time_with_fallback, validate_expiry_time
from aes_gcm import AES_GCM

MAGIC = b"IMAGED"

class TTLFileManager:    
    def __init__(self):
        self.cfg = load_config()
    
    def _log_timing(self, step_name, start_time, data_size=None):
        elapsed = time.time() - start_time
        if data_size:
            size_mb = data_size / (1024 * 1024)
            speed = size_mb / elapsed if elapsed > 0 else 0
            message = f"{step_name}: {elapsed:.3f}s | {size_mb:.2f} MB | {speed:.2f} MB/s"
        else:
            message = f"{step_name}: {elapsed:.3f}s"
        
        logging.info(message)
        print(f"  {message}")
    
    def create_ttl_file(self, input_path: str, expiry_ts: int = None, output_path: str = None) -> str:
        import time
        import struct
        
        total_start = time.time()
        print(f"Starting TTL creation process")
        logging.info(f"Starting TTL creation process")
        
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

        # Prepare payload bytes (use original bytes; QOI removed)
        step_start = time.time()
        with open(input_path, "rb") as src_f:
            payload_data = src_f.read()
        self._log_timing("Prepare payload", step_start, len(payload_data))
        
        step_start = time.time()
        salt = os.urandom(16)
        cek = derive_cek(salt)
        key_hdr = derive_subkey(salt, b"ImAged HDR")
        header = struct.pack(">Q", expiry_ts)
        self._log_timing("Generate crypto material", step_start)
        
        step_start = time.time()
        aes_hdr = AES_GCM(key_hdr)
        nonce_hdr = os.urandom(12)
        tag_hdr_only = aes_hdr.encrypt(nonce_hdr, b"", header) 
        tag_hdr = tag_hdr_only[-16:]
        self._log_timing("Authenticate header", step_start)
        
        step_start = time.time()
        aes_body = AES_GCM(cek)
        nonce_body = os.urandom(12)
        body_ct_and_tag = aes_body.encrypt(nonce_body, payload_data, header)
        ciphertext_body, tag_body = body_ct_and_tag[:-16], body_ct_and_tag[-16:]
        self._log_timing("Encrypt body", step_start, len(payload_data))
        
        step_start = time.time()
        with open(output_path, "wb") as f:
            f.write(MAGIC)
            f.write(salt)
            f.write(nonce_hdr)
            f.write(header)
            f.write(tag_hdr)
            f.write(nonce_body)
            f.write(tag_body)
            f.write(ciphertext_body)
        self._log_timing("Write TTL file", step_start)
        
        total_elapsed = time.time() - total_start
        completion_message = f"TTL creation completed in {total_elapsed:.3f}s"
        logging.info(completion_message)
        print(completion_message)
        logging.info("Wrote TTL %s (exp %d)", output_path, expiry_ts)
        return output_path

    def open_ttl_file(self, input_path: str, cleanup_callback=None) -> Tuple[bytes, bool]:
        import struct
        logging.info("open_ttl_file: %s", input_path)
        
        total_start = time.time()
        print(f"Starting TTL opening process")
        logging.info(f"Starting TTL opening process")
        
        try:
            step_start = time.time()
            with open(input_path, "rb") as f:
                data = f.read()
            self._log_timing("Read TTL file", step_start, len(data))

            step_start = time.time()
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
            self._log_timing("Parse header", step_start)
            
            step_start = time.time()
            key_hdr = derive_subkey(salt, b"ImAged HDR")
            aes_hdr = AES_GCM(key_hdr)
            try:
                aes_hdr.decrypt(nonce_hdr, cand_taghdr, cand_header)
            except Exception:
                raise ValueError("Invalid TTL format")
            self._log_timing("Verify header auth", step_start)
            
            step_start = time.time()
            expiry_ts = struct.unpack(">Q", cand_header)[0]
            try:
                current_time, fallback = get_current_time_with_fallback()
                if current_time > expiry_ts:
                    raise ValueError(f"File expired on {datetime.fromtimestamp(expiry_ts)}")
            except RuntimeError as e:
                raise ValueError(f"NTP time validation failed: {e}")
            self._log_timing("Check expiry", step_start)
            
            step_start = time.time()
            if len(data) < base + 36 + 12 + 16:
                raise ValueError("Invalid TTL file (truncated)")
            nonce_body = data[base+36:base+48]
            tag_body   = data[base+48:base+64]
            ciphertext_body = data[base+64:]

            cek = derive_cek(salt)
            aes_body = AES_GCM(cek)
            try:
                payload_data = aes_body.decrypt(nonce_body, ciphertext_body + tag_body, cand_header)
            except Exception:
                raise ValueError("Authentication failed")
            self._log_timing("Decrypt body", step_start, len(payload_data))
            
            total_elapsed = time.time() - total_start
            completion_message = f"TTL opening completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            return payload_data, fallback
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"TTL opening failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            if cleanup_callback:
                cleanup_callback()
            raise

    def debug_build_ttl_stages(self, input_path: str, expiry_ts: int | None = None):
        import time, struct
        
        total_start = time.time()
        print(f"Starting debug build stages process")
        logging.info(f"Starting debug build stages process")
        
        step_start = time.time()
        with open(input_path, "rb") as f:
            original_bytes = f.read()
        self._log_timing("Read original image", step_start, len(original_bytes))

        step_start = time.time()
        payload_data = original_bytes
        self._log_timing("Prepare payload", step_start, len(payload_data))

        step_start = time.time()
        salt = os.urandom(16)
        cek = derive_cek(salt)
        key_hdr = derive_subkey(salt, b"ImAged HDR")
        if expiry_ts is None: expiry_ts = int(time.time() + self.cfg.get("default_ttl_hours", 1) * 3600)
        header = struct.pack(">Q", expiry_ts)
        self._log_timing("Generate crypto material", step_start)

        step_start = time.time()
        aes_hdr = AES_GCM(key_hdr)
        nonce_hdr = os.urandom(12)
        tag_hdr = aes_hdr.encrypt(nonce_hdr, b"", header)
        self._log_timing("Header authentication", step_start)

        step_start = time.time()
        aes_body = AES_GCM(cek)
        nonce_body = os.urandom(12)
        ct_body = aes_body.encrypt(nonce_body, payload_data, header) 
        self._log_timing("Body encryption", step_start, len(payload_data))

        step_start = time.time()
        final_bytes = b"".join([
            MAGIC, salt, nonce_hdr, header, tag_hdr, nonce_body, ct_body[-16:], ct_body[:-16]
        ])
        self._log_timing("Final file layout", step_start, len(final_bytes))
        
        total_elapsed = time.time() - total_start
        completion_message = f"Debug build stages completed in {total_elapsed:.3f}s"
        logging.info(completion_message)
        print(completion_message)

        return {
            "original": original_bytes,
            "payload": payload_data,
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
        
        total_start = time.time()
        print(f"Starting debug open stages process")
        logging.info(f"Starting debug open stages process")
        
        step_start = time.time()
        with open(ttl_path, "rb") as f:
            data = f.read()
        self._log_timing("Read TTL file", step_start, len(data))
        
        step_start = time.time()
        off = len(MAGIC)
        salt = data[off:off+16]; off += 16
        nonce_hdr = data[off:off+12]; off += 12
        header = data[off:off+8]; off += 8
        tag_hdr = data[off:off+16]; off += 16
        nonce_body = data[off:off+12]; off += 12
        tag_body = data[off:off+16]; off += 16
        ciphertext_body = data[off:]
        self._log_timing("Parse segments", step_start)
        
        step_start = time.time()
        key_hdr = derive_subkey(salt, b"ImAged HDR")
        aes_hdr = AES_GCM(key_hdr)
        try:
            aes_hdr.decrypt(nonce_hdr, tag_hdr, header)
        except Exception:
            raise ValueError("Invalid TTL format")
        self._log_timing("Verify header", step_start)
        
        step_start = time.time()
        cek = derive_cek(salt)
        aes_body = AES_GCM(cek)
        payload_data = aes_body.decrypt(nonce_body, ciphertext_body + tag_body, header)
        self._log_timing("Decrypt body", step_start, len(payload_data))
        
        total_elapsed = time.time() - total_start
        completion_message = f"Debug open stages completed in {total_elapsed:.3f}s"
        logging.info(completion_message)
        print(completion_message)

        return {
            "file_bytes": data,
            "salt": salt,
            "header": header,
            "nonce_hdr": nonce_hdr,
            "tag_hdr": tag_hdr,
            "nonce_body": nonce_body,
            "tag_body": tag_body,
            "ciphertext_body": ciphertext_body,
            "payload": payload_data,
        }