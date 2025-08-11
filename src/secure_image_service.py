# src/secure_image_service.py
import gc
import ctypes
import threading
import time
import logging
from typing import Optional, Tuple
from PIL import Image
import io

class SecureImageService:
    """Secure image rendering service with immediate cleanup."""
    
    def __init__(self):
        self._active_sessions = {}
        self._cleanup_lock = threading.Lock()
    
    def render_ttl_image_secure(self, ttl_path: str, max_display_time: int = 30) -> Optional[bytes]:
        """
        Render TTL image with secure memory handling - NO TEMP FILES.
        Returns image bytes for immediate display, auto-cleanup after timeout.
        """
        session_id = f"render_{hash(ttl_path)}_{int(time.time())}"
        
        try:
            # Load encrypted TTL file (stays encrypted in memory)
            encrypted_bytes = self._load_encrypted_ttl(ttl_path)
            
            # Decrypt only when needed - IN MEMORY ONLY
            decrypted_bytes = self._decrypt_just_in_time_memory_only(encrypted_bytes)
            
            # Start auto-cleanup timer
            cleanup_timer = threading.Timer(
                max_display_time, 
                self._secure_cleanup_session, 
                args=[session_id, decrypted_bytes]
            )
            cleanup_timer.start()
            
            # Track session without storing decrypted bytes
            with self._cleanup_lock:
                self._active_sessions[session_id] = {
                    'encrypted_bytes': encrypted_bytes,
                    'timer': cleanup_timer,
                    'created': time.time(),
                    'ttl_path': ttl_path
                }
            
            logging.info(f"Secure render session {session_id} created, auto-cleanup in {max_display_time}s")
            return decrypted_bytes
            
        except Exception as e:
            logging.error(f"Error in secure render: {e}")
            return None
    
    def _load_encrypted_ttl(self, ttl_path: str) -> bytes:
        """Load TTL file into memory (stays encrypted)."""
        with open(ttl_path, 'rb') as f:
            return f.read()
    
    def _decrypt_just_in_time_memory_only(self, encrypted_bytes: bytes) -> bytes:
        """Decrypt image bytes just before rendering - NO TEMP FILES.
        Returns raw QOI bytes."""
        def decrypt_ttl_from_memory(ttl_bytes: bytes) -> bytes:
            import struct
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from crypto import derive_cek, derive_subkey
            from time_utils import get_current_time_with_fallback

            MAGIC = b"IMAGED"
            min_len = len(MAGIC) + 16 + 12 + 8 + 16 + 12 + 16
            if len(ttl_bytes) < min_len:
                raise ValueError("Invalid TTL file (too short)")

            off = 0
            magic = ttl_bytes[off:off+len(MAGIC)]; off += len(MAGIC)
            if magic != MAGIC:
                raise ValueError("Not an ImAged file")
            salt = ttl_bytes[off:off+16]; off += 16

            base = off
            nonce_hdr   = ttl_bytes[base:base+12]
            cand_header = ttl_bytes[base+12:base+20]
            cand_taghdr = ttl_bytes[base+20:base+36]

            key_hdr = derive_subkey(salt, b"ImAged HDR")
            aes_hdr = AESGCM(key_hdr)
            try:
                aes_hdr.decrypt(nonce_hdr, cand_taghdr, cand_header)
            except Exception:
                raise ValueError("Invalid TTL format")

            expiry_ts = struct.unpack(">Q", cand_header)[0]
            current_time, _fallback = get_current_time_with_fallback()
            if current_time > expiry_ts:
                from datetime import datetime
                raise ValueError(f"File expired on {datetime.fromtimestamp(expiry_ts)}")

            if len(ttl_bytes) < base + 36 + 12 + 16:
                raise ValueError("Invalid TTL file (truncated)")
            nonce_body = ttl_bytes[base+36:base+48]
            tag_body   = ttl_bytes[base+48:base+64]
            ciphertext = ttl_bytes[base+64:]

            cek = derive_cek(salt)
            aes_body = AESGCM(cek)
            try:
                qoi_data = aes_body.decrypt(nonce_body, ciphertext + tag_body, cand_header)
            except Exception:
                raise ValueError("Authentication failed")

            # Return raw QOI bytes (caller decodes for display)
            return qoi_data

        return decrypt_ttl_from_memory(encrypted_bytes)
    
    def _secure_cleanup_session(self, session_id: str, decrypted_bytes: bytes):
        """Securely cleanup session and zero memory."""
        with self._cleanup_lock:
            if session_id in self._active_sessions:
                session = self._active_sessions[session_id]
                if session['timer']:
                    session['timer'].cancel()
                
                # Overwrite memory before deletion
                if decrypted_bytes is not None:
                    try:
                        mutable_data = bytearray(decrypted_bytes)
                        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_data)), 0, len(mutable_data))
                    except Exception:
                        pass
                
                del self._active_sessions[session_id]
        
        # Force garbage collection (3 passes)
        for _ in range(3):
            gc.collect()
    
    def _zero_memory(self, data: bytes):
        """Zero out memory using ctypes."""
        try:
            # Create mutable copy and zero it
            mutable_data = bytearray(data)
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_data)), 0, len(mutable_data))
            del mutable_data
        except:
            # Fallback to Python zeroing
            try:
                mutable_data = bytearray(data)
                mutable_data[:] = b'\x00' * len(mutable_data)
                del mutable_data
            except:
                pass
        finally:
            del data
            gc.collect()
    
    def force_cleanup_all_sessions(self):
        """Force cleanup of all active sessions."""
        with self._cleanup_lock:
            for session_id, session in list(self._active_sessions.items()):
                if session['timer'] is not None:
                    session['timer'].cancel()
                logging.info(f"Force cleanup: Session {session_id} cleared")
            self._active_sessions.clear()
        
        # Force garbage collection
        for _ in range(3):
            gc.collect()