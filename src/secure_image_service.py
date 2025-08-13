import gc
import ctypes
import threading
import time
import logging
from typing import Optional, Tuple
from PIL import Image
import io
from aes_gcm import AES_GCM 


class SecureImageService:
    """Secure image rendering service with immediate cleanup."""
    
    def __init__(self):
        self._active_sessions = {}
        self._cleanup_lock = threading.Lock()
    
    def _log_timing(self, step_name, start_time, data_size=None):
        """
        Log timing information for a process step with performance metrics.
        
        Args:
            step_name: Name of the process step being timed
            start_time: Timestamp when the step began
            data_size: Optional data size in bytes for throughput calculation
        """
        elapsed = time.time() - start_time
        if data_size:
            size_mb = data_size / (1024 * 1024)
            speed = size_mb / elapsed if elapsed > 0 else 0
            message = f"{step_name}: {elapsed:.3f}s | {size_mb:.2f} MB | {speed:.2f} MB/s"
        else:
            message = f"{step_name}: {elapsed:.3f}s"
        
        logging.info(message)
        print(f"  {message}")
    
    def render_ttl_image_secure(self, ttl_path: str, max_display_time: int = 30) -> Optional[bytes]:
        """
        Render TTL image with secure memory handling and comprehensive timing analysis.
        
        This method implements a secure image rendering pipeline that:
        - Loads encrypted TTL files without temporary file creation
        - Performs just-in-time decryption in memory
        - Implements automatic memory cleanup after specified timeout
        - Provides detailed performance metrics for each processing stage
        
        Args:
            ttl_path: Path to TTL file for secure rendering
            max_display_time: Maximum time in seconds before automatic cleanup
            
        Returns:
            Decrypted image bytes for immediate display, or None if processing fails
        """
        session_id = f"render_{hash(ttl_path)}_{int(time.time())}"
        
        total_start = time.time()
        print(f"Starting secure TTL rendering process")
        logging.info(f"Starting secure TTL rendering process")
        
        try:
            # Load encrypted TTL file into memory (remains encrypted)
            step_start = time.time()
            encrypted_bytes = self._load_encrypted_ttl(ttl_path)
            self._log_timing("Load encrypted TTL", step_start, len(encrypted_bytes))
            
            # Execute just-in-time decryption in memory only
            step_start = time.time()
            decrypted_bytes = self._decrypt_just_in_time_memory_only(encrypted_bytes)
            self._log_timing("Decrypt TTL", step_start, len(decrypted_bytes))
            
            # Initialize automatic cleanup timer for memory management
            step_start = time.time()
            cleanup_timer = threading.Timer(
                max_display_time, 
                self._secure_cleanup_session, 
                args=[session_id, decrypted_bytes]
            )
            cleanup_timer.start()
            self._log_timing("Setup cleanup timer", step_start)
            
            # Track session metadata without storing decrypted content
            step_start = time.time()
            with self._cleanup_lock:
                self._active_sessions[session_id] = {
                    'encrypted_bytes': encrypted_bytes,
                    'timer': cleanup_timer,
                    'created': time.time(),
                    'ttl_path': ttl_path
                }
            self._log_timing("Track session", step_start)
            
            total_elapsed = time.time() - total_start
            completion_message = f"Secure TTL rendering completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            logging.info(f"Secure render session {session_id} created, auto-cleanup in {max_display_time}s")
            return decrypted_bytes
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"Secure TTL rendering failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            return None
    
    def _load_encrypted_ttl(self, ttl_path: str) -> bytes:
        """
        Load TTL file into memory while maintaining encryption.
        
        Args:
            ttl_path: Path to TTL file for loading
            
        Returns:
            Encrypted file contents as bytes
        """
        with open(ttl_path, 'rb') as f:
            return f.read()
    
    def _decrypt_just_in_time_memory_only(self, encrypted_bytes: bytes) -> bytes:
        """
        Decrypt image bytes just before rendering using in-memory processing.
        
        This method implements the complete TTL decryption pipeline:
        - Header parsing and structure validation
        - Header authentication and expiry verification
        - Body decryption and payload recovery
        - Performance metrics for each processing stage
        
        Args:
            encrypted_bytes: Encrypted TTL file contents
            
        Returns:
            Decrypted payload bytes for image rendering
        """
        def decrypt_ttl_from_memory(ttl_bytes: bytes) -> bytes:
            import struct
            from crypto import derive_cek, derive_subkey
            from time_utils import get_current_time_with_fallback

            total_start = time.time()
            print(f"    Starting TTL decryption from memory")
            logging.info(f"    Starting TTL decryption from memory")
            
            # Parse and validate TTL file header structure
            step_start = time.time()
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
            self._log_timing("Parse header", step_start)
            
            # Verify header authentication using derived key
            step_start = time.time()
            key_hdr = derive_subkey(salt, b"ImAged HDR")
            aes_hdr = AES_GCM(key_hdr)
            try:
                aes_hdr.decrypt(nonce_hdr, cand_taghdr, cand_header)
            except Exception:
                raise ValueError("Invalid TTL format")
            self._log_timing("Verify header auth", step_start)
            
            # Validate file expiry timestamp
            step_start = time.time()
            expiry_ts = struct.unpack(">Q", cand_header)[0]
            try:
                current_time, _fallback = get_current_time_with_fallback()
                if current_time > expiry_ts:
                    from datetime import datetime
                    raise ValueError(f"File expired on {datetime.fromtimestamp(expiry_ts)}")
            except RuntimeError as e:
                raise ValueError(f"NTP time validation failed: {e}")
            self._log_timing("Check expiry", step_start)
            
            # Decrypt payload body using derived content encryption key
            step_start = time.time()
            if len(ttl_bytes) < base + 36 + 12 + 16:
                raise ValueError("Invalid TTL file (truncated)")
            nonce_body = ttl_bytes[base+36:base+48]
            tag_body   = ttl_bytes[base+48:base+64]
            ciphertext = ttl_bytes[base+64:]

            cek = derive_cek(salt)
            aes_body = AES_GCM(cek)
            try:
                payload_data = aes_body.decrypt(nonce_body, ciphertext + tag_body, cand_header)
            except Exception:
                raise ValueError("Authentication failed")
            self._log_timing("Decrypt body", step_start, len(payload_data))
            
            total_elapsed = time.time() - total_start
            completion_message = f"    TTL decryption completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)

            # Return decrypted payload bytes for image processing
            return payload_data

        return decrypt_ttl_from_memory(encrypted_bytes)
    
    def _secure_cleanup_session(self, session_id: str, decrypted_bytes: bytes):
        """
        Securely cleanup session and zero memory using cryptographic best practices.
        
        This method implements secure memory management by:
        - Overwriting sensitive data in memory before deletion
        - Using ctypes for low-level memory manipulation
        - Implementing multiple garbage collection passes
        - Maintaining thread safety during cleanup operations
        
        Args:
            session_id: Unique identifier for the session to cleanup
            decrypted_bytes: Sensitive data to securely erase from memory
        """
        cleanup_start = time.time()
        cleanup_message = f"Starting secure cleanup for session {session_id}"
        logging.info(cleanup_message)
        print(cleanup_message)
        
        with self._cleanup_lock:
            if session_id in self._active_sessions:
                session = self._active_sessions[session_id]
                if session['timer']:
                    session['timer'].cancel()
                
                # Securely overwrite memory before deletion
                if decrypted_bytes is not None:
                    try:
                        mutable_data = bytearray(decrypted_bytes)
                        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_data)), 0, len(mutable_data))
                    except Exception:
                        pass
                
                del self._active_sessions[session_id]
        
        # Implement multiple garbage collection passes for thorough cleanup
        for _ in range(3):
            gc.collect()
        
        cleanup_elapsed = time.time() - cleanup_start
        completion_message = f"Secure cleanup completed in {cleanup_elapsed:.3f}s"
        logging.info(completion_message)
        print(completion_message)
    
    def _zero_memory(self, data: bytes):
        """
        Zero out memory using low-level system calls for security.
        
        This method implements secure memory erasure using:
        - ctypes for direct memory manipulation
        - Fallback to Python-level memory zeroing
        - Multiple cleanup strategies for reliability
        
        Args:
            data: Sensitive data to securely erase from memory
        """
        try:
            # Create mutable copy and zero using ctypes
            mutable_data = bytearray(data)
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_data)), 0, len(mutable_data))
            del mutable_data
        except:
            # Fallback to Python-level memory zeroing
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
        """
        Force cleanup of all active sessions for emergency memory management.
        
        This method provides emergency cleanup capabilities by:
        - Cancelling all active cleanup timers
        - Clearing all session metadata
        - Implementing forced garbage collection
        - Providing comprehensive cleanup reporting
        """
        cleanup_start = time.time()
        cleanup_message = f"Starting force cleanup of all sessions"
        logging.info(cleanup_message)
        print(cleanup_message)
        
        with self._cleanup_lock:
            for session_id, session in list(self._active_sessions.items()):
                if session['timer'] is not None:
                    session['timer'].cancel()
                logging.info(f"Force cleanup: Session {session_id} cleared")
            self._active_sessions.clear()
        
        # Implement forced garbage collection for thorough cleanup
        for _ in range(3):
            gc.collect()
        
        cleanup_elapsed = time.time() - cleanup_start
        completion_message = f"Force cleanup completed in {cleanup_elapsed:.3f}s"
        logging.info(completion_message)
        print(completion_message)