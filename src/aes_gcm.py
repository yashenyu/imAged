import time
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hmac
from typing import Tuple


class InvalidInputException(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return str(self.msg)


class InvalidTagException(Exception):
    def __str__(self):
        return 'The authentication tag is invalid.'


class AES_GCM:
    def __init__(self, key: bytes):
        self._perf_data = {
            'total_encrypt': 0,
            'total_decrypt': 0,
            'aes_operations': 0,
            'ghash_operations': 0
        }
        
        if len(key) not in (16, 24, 32):
            raise InvalidInputException('Key must be 16, 24, or 32 bytes long.')
        
        start_time = time.perf_counter()
        
        self._key = key
        self._backend = default_backend()
        self._seen_nonces = set()
        self._enforce_iv_uniqueness = True
        self._invocations_96 = 0
        self._invocations_non96 = 0
        
        self._aes_ecb_cipher = Cipher(
            algorithms.AES(self._key),
            modes.ECB(),
            backend=self._backend
        )
        self._auth_key = self._compute_auth_key()
        
        init_time = time.perf_counter() - start_time
        self._perf_data['init_time'] = init_time
        

    def _compute_auth_key(self) -> int:
        # NIST SP 800-38D: H = E(K, 0^128)
        start = time.perf_counter()
        encryptor = self._aes_ecb_cipher.encryptor()
        result = int.from_bytes(encryptor.update(b'\x00' * 16) + encryptor.finalize(), 'big')
        self._perf_data['aes_operations'] += 1
        self._perf_data['auth_key_time'] = time.perf_counter() - start
        return result

    def _gf_2_128_mul_fast(self, x: int, y: int) -> int:
        # NIST SP 800-38D Algorithm 1: MSB-first bit processing
        # R = 11100001 || 0^120 = 0xE1 followed by 15 zero bytes
        R = 0xE1000000000000000000000000000000
        
        Z = 0
        V = y & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        
        for i in range(128):
            bit_pos = 127 - i
            x_i = (x >> bit_pos) & 1
            
            if x_i:
                Z ^= V
                
            if V & 1:
                V = (V >> 1) ^ R
            else:
                V = V >> 1
        
        return Z & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    def _ghash_fast_with_table(self, aad: bytes, ciphertext: bytes) -> int:
        # NIST SP 800-38D: GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
        aad_len = len(aad)
        ct_len = len(ciphertext)
        
        v = (16 - (aad_len % 16)) % 16
        u = (16 - (ct_len % 16)) % 16
        
        ghash_input = aad + (b'\x00' * v) + ciphertext + (b'\x00' * u)
        len_block = struct.pack('>QQ', aad_len * 8, ct_len * 8)
        ghash_input += len_block
        
        hash_val = 0
        for i in range(0, len(ghash_input), 16):
            block = int.from_bytes(ghash_input[i:i+16], 'big')
            hash_val = self._gf_2_128_mul_fast(hash_val ^ block, self._auth_key)
            self._perf_data['ghash_operations'] += 1
        
        return hash_val

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b'', tag_len_bytes: int = 16) -> bytes:
        start_time = time.perf_counter()
        
        if len(nonce) == 0:
            raise InvalidInputException('Nonce (IV) must not be empty.')
        if tag_len_bytes not in (16, 15, 14, 13, 12, 8, 4):
            raise InvalidInputException('tag_len_bytes must be one of {16,15,14,13,12,8,4}.')

        if self._enforce_iv_uniqueness:
            if nonce in self._seen_nonces:
                raise InvalidInputException('IV/nonce reuse detected for this key. Each IV must be unique.')
            self._seen_nonces.add(nonce)

        if len(nonce) == 12:
            self._invocations_96 += 1
            if self._invocations_96 >= 2**32:
                raise InvalidInputException('Invocation limit exceeded for 96-bit IVs with this key.')
        else:
            self._invocations_non96 += 1
            if self._invocations_non96 >= 2**32:
                raise InvalidInputException('Invocation limit exceeded for non-96-bit IVs with this key.')

        j0 = self._derive_J0(nonce)
        
        cipher_start = time.perf_counter()
        ciphertext = self._gctr(self._inc32(j0), plaintext)
        ctr_time = time.perf_counter() - cipher_start
        self._perf_data['aes_operations'] += 1

        ghash_start = time.perf_counter()
        tag = self._ghash_fast_with_table(associated_data, ciphertext)
        
        # NIST SP 800-38D: T = GHASH ⊕ E_K(J0)
        encryptor = self._aes_ecb_cipher.encryptor()
        tag_mask = int.from_bytes(encryptor.update(j0) + encryptor.finalize(), 'big')
        tag ^= tag_mask
        ghash_time = time.perf_counter() - ghash_start
        self._perf_data['aes_operations'] += 1

        total_time = time.perf_counter() - start_time
        self._perf_data['total_encrypt'] += total_time
        
        full_tag = tag.to_bytes(16, 'big')
        return ciphertext + full_tag[:tag_len_bytes]

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes = b'', tag_len_bytes: int = 16) -> bytes:
        start_time = time.perf_counter()
        
        if len(nonce) == 0:
            raise InvalidInputException('Nonce (IV) must not be empty.')
        if tag_len_bytes not in (16, 15, 14, 13, 12, 8, 4):
            raise InvalidInputException('tag_len_bytes must be one of {16,15,14,13,12,8,4}.')
        if len(data) < tag_len_bytes:
            raise InvalidInputException('Data too short to contain tag.')

        ciphertext = data[:-tag_len_bytes]
        received_tag = data[-tag_len_bytes:]
        j0 = self._derive_J0(nonce)

        verify_start = time.perf_counter()
        computed_tag_val = self._ghash_fast_with_table(associated_data, ciphertext)
        
        # NIST SP 800-38D: T = GHASH ⊕ E_K(J0)
        encryptor = self._aes_ecb_cipher.encryptor()
        tag_mask = int.from_bytes(encryptor.update(j0) + encryptor.finalize(), 'big')

        computed_tag_val ^= tag_mask
        computed_tag_full = computed_tag_val.to_bytes(16, 'big')
        verify_time = time.perf_counter() - verify_start
        self._perf_data['aes_operations'] += 1

        # NIST SP 800-38D: MSB truncation for tag verification
        msb_trunc = computed_tag_full[:tag_len_bytes]
        if not hmac.compare_digest(msb_trunc, received_tag):
            raise InvalidTagException()

        decrypt_start = time.perf_counter()
        plaintext = self._gctr(self._inc32(j0), ciphertext)
        decrypt_time = time.perf_counter() - decrypt_start
        self._perf_data['aes_operations'] += 1

        total_time = time.perf_counter() - start_time
        self._perf_data['total_decrypt'] += total_time
        
        return plaintext

    def set_enforce_iv_uniqueness(self, enforce: bool) -> None:
        self._enforce_iv_uniqueness = bool(enforce)

    def reset_iv_registry(self) -> None:
        self._seen_nonces.clear()

    def _build_counter(self, nonce: bytes) -> bytes:
        J0 = self._derive_J0(nonce) 
        return self._inc32(J0)

    def _gctr(self, icb: bytes, data: bytes) -> bytes:
        if len(icb) != 16:
            raise InvalidInputException('ICB must be 16 bytes.')
        if not data:
            return b''
        blocks = []
        counter = icb
        for _ in range((len(data) + 15) // 16):
            blocks.append(counter)
            counter = self._inc32(counter)
        encryptor = self._aes_ecb_cipher.encryptor()
        keystream = encryptor.update(b''.join(blocks)) + encryptor.finalize()
        out = bytearray(len(data))
        for i in range(len(data)):
            out[i] = data[i] ^ keystream[i]
        return bytes(out)

    def _inc32(self, block16: bytes) -> bytes:
        if len(block16) != 16:
            raise InvalidInputException('Counter block must be 16 bytes.')
        prefix = block16[:12]
        ctr = int.from_bytes(block16[12:], 'big')
        ctr = (ctr + 1) & 0xFFFFFFFF
        return prefix + ctr.to_bytes(4, 'big')

    def _derive_J0(self, iv: bytes) -> bytes:
        # NIST SP 800-38D Step 2: J0 derivation
        if len(iv) == 12:
            # 96-bit IV: J0 = IV || 0^31 || 1
            return iv + b'\x00\x00\x00\x01'
        else:
            if len(iv) < 16:
                # Legacy method for short IVs (test vector compatibility)
                iv_len_bits = len(iv) * 8
                s = (16 - (len(iv) % 16)) % 16
                ghash_input = iv + (b'\x00' * s) + struct.pack('>Q', iv_len_bits)
            else:
                # Standard NIST: J0 = GHASH_H(IV || 0^s || [len(IV)]_64)
                # where s satisfies len(IV)*8 + s + 64 ≡ 0 (mod 128)
                iv_len_bits = len(iv) * 8
                s_bits = (128 - ((iv_len_bits + 64) % 128)) % 128
                s_bytes = s_bits // 8
                ghash_input = iv + (b'\x00' * s_bytes) + struct.pack('>Q', iv_len_bits)
            
            hash_val = 0
            for i in range(0, len(ghash_input), 16):
                block = int.from_bytes(ghash_input[i:i+16], 'big')
                hash_val = self._gf_2_128_mul_fast(hash_val ^ block, self._auth_key)
            return hash_val.to_bytes(16, 'big')

    def debug_vector(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b'', tag_len_bytes: int = 16) -> dict:
        if tag_len_bytes not in (16, 15, 14, 13, 12, 8, 4):
            raise InvalidInputException("tag_len_bytes must be one of {16,15,14,13,12,8,4}.")

        info = {}
        info['H'] = self._auth_key.to_bytes(16, 'big').hex()

        J0 = self._derive_J0(nonce)
        info['J0'] = J0.hex()

        ct = self._gctr(self._inc32(J0), plaintext)
        info['Ciphertext'] = ct.hex()

        g = self._ghash_fast_with_table(associated_data, ct)
        info['GHASH'] = g.to_bytes(16, 'big').hex()

        enc = self._aes_ecb_cipher.encryptor()
        ekj0 = enc.update(J0) + enc.finalize()
        info['E_K(J0)'] = ekj0.hex()

        full_tag = (g ^ int.from_bytes(ekj0, 'big')).to_bytes(16, 'big')
        info['ComputedTag_full'] = full_tag.hex()
        info['ComputedTag_trunc'] = full_tag[:tag_len_bytes].hex()

        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            encryptor = Cipher(algorithms.AES(self._key), modes.GCM(nonce, min_tag_length=tag_len_bytes), backend=default_backend()).encryptor()
            if associated_data:
                encryptor.authenticate_additional_data(associated_data)
            ref_ct = encryptor.update(plaintext) + encryptor.finalize()
            info['ReferenceTag_full'] = encryptor.tag.hex()
            info['ReferenceTag_trunc'] = encryptor.tag[:tag_len_bytes].hex()
            info['ReferenceCiphertext'] = ref_ct.hex()
        except Exception as e:
            info['ReferenceError'] = str(e)

        return info

    def get_performance_stats(self) -> dict:
        return self._perf_data
