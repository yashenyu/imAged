import os
import binascii
import logging
import keyring
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVICE  = "ImAged"
KEY_NAME = "master_key"

def _load_or_generate_master_key() -> bytes:
    env_hex = os.getenv("IMAGED_MASTER_KEY")
    if env_hex:
        try:
            key = binascii.unhexlify(env_hex)
            logging.info("Loaded MASTER_KEY from environment")
            return key
        except Exception:
            logging.warning("Invalid IMAGED_MASTER_KEY env var (expecting hex)")

    stored = keyring.get_password(SERVICE, KEY_NAME)
    if stored:
        try:
            key = binascii.unhexlify(stored)
            logging.info("Loaded MASTER_KEY from keyring")
            return key
        except Exception:
            logging.warning("Invalid key in keyring; regenerating")

    new_key = os.urandom(32)
    keyring.set_password(SERVICE, KEY_NAME, binascii.hexlify(new_key).decode())
    logging.info("Generated new MASTER_KEY and stored in keyring %s/%s", SERVICE, KEY_NAME)
    return new_key

MASTER_KEY = _load_or_generate_master_key()

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