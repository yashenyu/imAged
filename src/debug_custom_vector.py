# debug_custom_vector.py
import binascii
import json
import os
import sys
import struct

# ensure we import local module
sys.path.append(os.path.dirname(__file__))

from test_vectors_runner import _parse_rsp_file  # reuse your parser
from aes_gcm import AES_GCM, InvalidTagException, InvalidInputException
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# === CONFIGURE THESE ===
RSP_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'testVectors', 'gcmDecrypt128.rsp')
VECTOR_COUNT = 0   # the 'Count=' index from the .rsp lines (0-based if multiple entries)
TAGLEN_OVERRIDE = None  # set to an int to force a tag length (in bytes) or None to use vector-specified

# === helpers ===
def hex_to_bytes_safe(s: str) -> bytes:
    if s is None:
        return b''
    v = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    if v == "":
        return b''
    if len(v) % 2 != 0:
        # pad? here we raise so user can see incorrect input
        raise ValueError("Odd-length hex string: %r" % s)
    return binascii.unhexlify(v)

def compute_crypto_reference_tag(key: bytes, iv: bytes, aad: bytes, pt: bytes, tag_len_bytes: int) -> bytes:
    # Use cryptography AES-GCM in encrypt mode to compute reference tag for given plaintext
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv, min_tag_length=tag_len_bytes), backend=default_backend()).encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(pt) + encryptor.finalize()
    return encryptor.tag[:tag_len_bytes], ciphertext

# === main ===
header, vectors = _parse_rsp_file(RSP_PATH)
if VECTOR_COUNT >= len(vectors):
    print("Vector count out of range; file has", len(vectors))
    sys.exit(1)
vec = vectors[VECTOR_COUNT]

# Pull fields (many .rsp variants)
key_hex = vec.get('Key','')
iv_hex = vec.get('IV','') or vec.get('Nonce','')
aad_hex = vec.get('AAD','') or vec.get('Adata','') or vec.get('A','')
pt_hex = vec.get('PT','') or vec.get('Plaintext','') or vec.get('P','')
ct_hex = vec.get('CT','') or vec.get('Ciphertext','') or vec.get('C','')
tag_hex = vec.get('Tag','') or vec.get('TAG','') or vec.get('T','')

key = hex_to_bytes_safe(key_hex)
iv  = hex_to_bytes_safe(iv_hex)
aad = hex_to_bytes_safe(aad_hex)
pt  = hex_to_bytes_safe(pt_hex)
ct  = hex_to_bytes_safe(ct_hex)
tag = hex_to_bytes_safe(tag_hex)

# Determine tag length
if TAGLEN_OVERRIDE is not None:
    tag_len_bytes = TAGLEN_OVERRIDE
elif tag:
    tag_len_bytes = len(tag)
else:
    tag_len_bits = None
    for k in ('Taglen','TagLen','TcLen','Tlen','TLen'):
        if k in header:
            try:
                tag_len_bits = int(header[k])
                break
            except Exception:
                pass
    if tag_len_bits is None and 'Tlen' in vec:
        try:
            tag_len_bits = int(vec['Tlen'])
        except Exception:
            pass
    tag_len_bytes = (tag_len_bits // 8) if tag_len_bits else 16

print("DEBUG VECTOR")
print(" Key:", key_hex)
print(" IV :", iv_hex, " (len bytes =", len(iv), ")")
print(" AAD:", aad_hex, " (len bytes =", len(aad), ")")
print(" PT :", pt_hex, " (len bytes =", len(pt), ")")
print(" CT :", ct_hex, " (len bytes =", len(ct), ")")
print(" Tag:", tag_hex, " (len bytes =", len(tag), ")")
print(" Using tag_len_bytes =", tag_len_bytes)
print()

# instantiate custom AES_GCM
c = AES_GCM(key)
c.set_enforce_iv_uniqueness(False)

# debug routine: compute internal pieces (we assume AES_GCM has debug_vector method)
if not hasattr(c, "debug_vector"):
    print("AES_GCM class missing debug_vector helper. Please add the debug_vector method (H, J0, GHASH, E_K_J0, computed tags).")
    sys.exit(1)

info = c.debug_vector(iv, ct, aad, tag_len_bytes=tag_len_bytes)
print("CUSTOM IMPLEMENTATION INTERMEDIATES:")
print(json.dumps(info, indent=2))
print()

# compute reference using cryptography (encrypt plaintext to get tag)
try:
    ref_tag, ref_ct = compute_crypto_reference_tag(key, iv, aad, pt, tag_len_bytes)
    print("REFERENCE (cryptography) tag (truncated):", ref_tag.hex())
    if len(pt) != 0:
        print("REFERENCE ciphertext (crypto):", ref_ct.hex())
except Exception as e:
    print("Reference tag computation error:", e)

# If vector is decrypt case and ct provided with appended tag, show what custom sees
if len(ct) >= tag_len_bytes and tag == b'':
    print("\nRunner-decoded: treating last", tag_len_bytes, "bytes of CT as tag.")
    print(" CT(without tag):", ct[:-tag_len_bytes].hex())
    print(" Received tag:", ct[-tag_len_bytes:].hex())

print("\nDone. Paste this entire output (JSON parts) back here and I'll pinpoint the mismatch.")
