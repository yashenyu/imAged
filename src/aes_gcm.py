import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('AES_GCM')

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
        """Initialize with performance tracking."""
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
        
        self._aes_ecb_cipher = Cipher(
            algorithms.AES(self._key),
            modes.ECB(),
            backend=self._backend
        )

        self._auth_key = self._compute_auth_key()
        self._pre_table = self._precompute_ghash_table()
        
        init_time = time.perf_counter() - start_time
        self._perf_data['init_time'] = init_time
        logger.info(f"Initialization completed in {init_time:.6f}s")
        
        self.prev_init_value = None

    def _compute_auth_key(self) -> int:
        start = time.perf_counter()
        encryptor = self._aes_ecb_cipher.encryptor()
        result = int.from_bytes(encryptor.update(b'\x00' * 16) + encryptor.finalize(), 'big')
        self._perf_data['aes_operations'] += 1
        self._perf_data['auth_key_time'] = time.perf_counter() - start
        return result

    def _precompute_ghash_table(self):
        """Precompute tables for fast GHASH: T[i][b] = (H * (b << (8*i))) in GF(2^128)."""
        H = self._auth_key
        table = []
        for i in range(16):
            row = []
            shift = 8 * i
            for b in range(256):
                row.append(self._gf_2_128_mul(H, b << shift))
            table.append(tuple(row))
        return tuple(table)
    
    def _mul_H(self, x: int) -> int:
        """Fast multiply using precomputed GHASH table."""
        acc = 0
        for i in range(16):
            byte = (x >> (8 * i)) & 0xFF
            acc ^= self._pre_table[i][byte]
        return acc

    @staticmethod
    def _gf_2_128_mul(x: int, y: int) -> int:
        """Galois Field (2^128) multiplication."""
        res = 0
        for i in range(127, -1, -1):
            res ^= x * ((y >> i) & 1)
            x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
        return res

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b'') -> bytes:
        """Encrypt with performance tracking."""
        start_time = time.perf_counter()
        
        if len(nonce) != 12:
            raise InvalidInputException('Nonce must be 12 bytes long.')

        init_value = int.from_bytes(nonce, 'big')
        if init_value == self.prev_init_value:
            raise InvalidInputException('Nonce must not be reused!')
        self.prev_init_value = init_value

        cipher_start = time.perf_counter()
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CTR(self._build_counter(nonce)),
            backend=self._backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        ctr_time = time.perf_counter() - cipher_start
        self._perf_data['aes_operations'] += 1

        ghash_start = time.perf_counter()
        tag = self._ghash(associated_data, ciphertext)
        tag ^= self._compute_final_tag(init_value)
        ghash_time = time.perf_counter() - ghash_start
        self._perf_data['ghash_operations'] += 1

        total_time = time.perf_counter() - start_time
        self._perf_data['total_encrypt'] += total_time
        
        logger.info(
            f"Encrypt: {len(plaintext)} bytes | "
            f"CTR: {ctr_time:.6f}s | "
            f"GHASH: {ghash_time:.6f}s | "
            f"Total: {total_time:.6f}s"
        )
        
        return ciphertext + tag.to_bytes(16, 'big')

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes = b'') -> bytes:
        """Decrypt with performance tracking."""
        start_time = time.perf_counter()
        
        if len(nonce) != 12:
            raise InvalidInputException('Nonce must be 12 bytes long.')
        if len(data) < 16:
            raise InvalidInputException('Data too short to contain tag.')

        ciphertext = data[:-16]
        tag = int.from_bytes(data[-16:], 'big')
        init_value = int.from_bytes(nonce, 'big')

        verify_start = time.perf_counter()
        computed_tag = self._ghash(associated_data, ciphertext)
        computed_tag ^= self._compute_final_tag(init_value)
        if computed_tag != tag:
            raise InvalidTagException()
        verify_time = time.perf_counter() - verify_start
        self._perf_data['ghash_operations'] += 1

        decrypt_start = time.perf_counter()
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CTR(self._build_counter(nonce)),
            backend=self._backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        decrypt_time = time.perf_counter() - decrypt_start
        self._perf_data['aes_operations'] += 1

        total_time = time.perf_counter() - start_time
        self._perf_data['total_decrypt'] += total_time
        
        logger.info(
            f"Decrypt: {len(ciphertext)} bytes | "
            f"Verify: {verify_time:.6f}s | "
            f"CTR: {decrypt_time:.6f}s | "
            f"Total: {total_time:.6f}s"
        )
        
        return plaintext

    def _build_counter(self, nonce: bytes) -> bytes:
        """Build initial counter block."""
        return nonce + b'\x00\x00\x00\x02'

    def _compute_final_tag(self, init_value: int) -> int:
        """Compute final tag using prebuilt AES-ECB cipher."""
        encryptor = self._aes_ecb_cipher.encryptor()
        block = ((init_value << 32) | 1).to_bytes(16, 'big')
        return int.from_bytes(encryptor.update(block) + encryptor.finalize(), 'big')

    def _ghash(self, aad: bytes, ciphertext: bytes) -> int:
        """GHASH with table-based multiplication."""
        tag = 0
        aad_len = len(aad)
        c_len = len(ciphertext)

        full = (aad_len // 16) * 16
        for i in range(0, full, 16):
            tag = self._mul_H(tag ^ int.from_bytes(aad[i:i+16], 'big'))
        if aad_len != full:
            last = aad[full:] + b'\x00' * (16 - (aad_len - full))
            tag = self._mul_H(tag ^ int.from_bytes(last, 'big'))

        full = (c_len // 16) * 16
        for i in range(0, full, 16):
            tag = self._mul_H(tag ^ int.from_bytes(ciphertext[i:i+16], 'big'))
        if c_len != full:
            last = ciphertext[full:] + b'\x00' * (16 - (c_len - full))
            tag = self._mul_H(tag ^ int.from_bytes(last, 'big'))

        len_block = ((aad_len * 8) << 64) | (c_len * 8)
        return self._mul_H(tag ^ len_block)

    def get_performance_stats(self) -> dict:
        """Return collected performance statistics."""
        return self._perf_data
