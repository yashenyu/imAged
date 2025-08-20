import os
import binascii
import logging
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def _master_key_path() -> Path:
    return Path(__file__).parent / "config" / "master.key"

def _load_or_create_static_master_key() -> bytes:
    path = _master_key_path()
    try:
        if path.exists():
            raw = path.read_bytes()
            # Try hex-encoded first if content looks textual hex
            stripped = raw.strip()
            try:
                if stripped and all(c in b"0123456789abcdefABCDEF" for c in stripped):
                    key = binascii.unhexlify(stripped)
                else:
                    key = raw
            except Exception:
                key = raw
            if len(key) != 32:
                raise ValueError(f"master.key must be 32 bytes (got {len(key)})")
            logging.info("Loaded static MASTER_KEY from %s", path)
            return key
        # Create if not present
        key = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key)
        logging.info("Generated new static MASTER_KEY at %s", path)
        return key
    except Exception as e:
        logging.error("Failed to load/create static master key: %s", e)
        raise

MASTER_KEY = _load_or_create_static_master_key()

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

def derive_cek(salt: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b"ImAged CEK",
    )
    cek = hkdf.derive(MASTER_KEY)
    logging.debug("Derived CEK with salt %s", salt.hex())
    return cek

def derive_subkey(salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(MASTER_KEY)