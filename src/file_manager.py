import os
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

from config import load_config
from crypto import derive_cek
from image_processor import encode_image_to_qoi, decode_qoi_to_image, save_image_to_temp
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
        
        # Encrypt data
        from crypto import encrypt_data
        salt = os.urandom(16)
        cek = derive_cek(salt)
        header = struct.pack(">Q", expiry_ts)
        plaintext = header + qoi_data
        nonce, ciphertext, tag = encrypt_data(cek, plaintext)

        # Write TTL file
        with open(output_path, "wb") as f:
            f.write(MAGIC)
            f.write(salt)
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)

        logging.info("Wrote TTL %s (exp %d)", output_path, expiry_ts)
        return output_path

    def open_ttl_file(self, input_path: str) -> Tuple[str, bool]:
        """Open and decrypt TTL file, return temp PNG path and fallback flag."""
        import struct
        
        logging.info("open_ttl_file: %s", input_path)
        
        # Read file
        with open(input_path, "rb") as f:
            magic = f.read(len(MAGIC))
            if magic != MAGIC:
                logging.error("Bad magic")
                raise ValueError("Not an ImAged file")
            salt = f.read(16)
            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        # Decrypt data
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cek = derive_cek(salt)
        aesgcm = AESGCM(cek)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        except Exception:
            logging.error("Auth failure")
            raise ValueError("Authentication failed")

        # Extract data
        expiry_ts = struct.unpack(">Q", plaintext[:8])[0]
        qoi_data = plaintext[8:]
        
        # Check expiry
        current_time, fallback = get_current_time_with_fallback()
        if current_time > expiry_ts:
            dt = datetime.fromtimestamp(expiry_ts)
            logging.warning("Expired %s", dt)
            raise ValueError(f"File expired on {dt}")

        # Decode image
        img = decode_qoi_to_image(qoi_data)
        tmp_path = save_image_to_temp(img)
        
        logging.info("Decrypted to %s (fallback=%s)", tmp_path, fallback)
        return tmp_path, fallback

    def batch_convert_images(self, folder_path: str) -> List[str]:
        """Convert all images in folder to TTL format."""
        if not os.path.isdir(folder_path):
            raise ValueError("Not a valid directory")
            
        files = sorted(f for f in os.listdir(folder_path) 
                      if f.lower().endswith((".png", ".jpg", ".jpeg")))
        
        if not files:
            raise ValueError("No images found")
            
        converted_files = []
        for fn in files:
            src = os.path.join(folder_path, fn)
            try:
                output_path = self.create_ttl_file(src)
                converted_files.append(output_path)
                logging.info("Batch converted: %s -> %s", fn, output_path)
            except Exception as e:
                logging.error("Batch convert failed for %s: %s", fn, e)
                
        return converted_files

    def save_image_as_png(self, source_path: str, destination_path: str) -> None:
        """Save image as PNG to specified location."""
        shutil.copy(source_path, destination_path)
        logging.info("Saved PNG: %s", destination_path)