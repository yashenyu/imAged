import sys
import json
import base64
import struct
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureBackend:
    def __init__(self):
        self.session_key = None
        self.establish_secure_channel()
        logger.info("Secure backend initialized")
    
    def establish_secure_channel(self):
        """Establish encrypted communication with C# frontend"""
        try:
            # Read initial handshake from stdin
            handshake = sys.stdin.readline().strip()
            if not handshake:
                raise Exception("No handshake received")
                
            handshake_data = base64.b64decode(handshake)
            
            # Extract session key from handshake
            self.session_key = self.extract_session_key(handshake_data)
            
            # Send confirmation back to C#
            confirmation = self.encrypt_data(b"CHANNEL_ESTABLISHED")
            sys.stdout.write(base64.b64encode(confirmation).decode() + "\n")
            sys.stdout.flush()
            
            logger.info("Secure channel established")
            
        except Exception as e:
            logger.error(f"Failed to establish secure channel: {e}")
            sys.exit(1)
    
    def extract_session_key(self, handshake_data):
        """Extract session key from handshake data"""
        try:
            # Extract key length (first 4 bytes) - use big-endian
            key_length = struct.unpack('>I', handshake_data[:4])[0]
        
            # Validate key length
            if key_length <= 0 or key_length > 1024:  # Reasonable bounds
                raise Exception(f"Invalid key length: {key_length}")
        
            # Check if we have enough data
            if len(handshake_data) < 4 + key_length:
                raise Exception(f"Handshake data too short: {len(handshake_data)} < {4 + key_length}")
        
            # Extract session key
            session_key = handshake_data[4:4+key_length]
        
            if len(session_key) != key_length:
                raise Exception(f"Session key length mismatch: expected {key_length}, got {len(session_key)}")
            
            logger.info(f"Session key extracted: {len(session_key)} bytes")
            return session_key
        
        except Exception as e:
            logger.error(f"Failed to extract session key: {e}")
            raise
    
    def process_commands(self):
        """Main command processing loop"""
        logger.info("Starting command processing loop")
    
        while True:
            try:
                # Read command from stdin
                line = sys.stdin.readline().strip()
                if not line:
                    logger.info("No more input, shutting down")
                    break
            
                # Decode and process command
                encrypted_payload = base64.b64decode(line)
                response = self.process_command(encrypted_payload)
            
                # Send encrypted response
                logger.info(f"About to send response: {response}")
                encrypted_response = self.encrypt_data(json.dumps(response).encode())
                response_base64 = base64.b64encode(encrypted_response).decode()
                logger.info(f"Sending response (base64): {response_base64[:50]}...")
            
                sys.stdout.write(response_base64 + "\n")
                sys.stdout.flush()
                logger.info("Response sent and flushed")
            
            except Exception as e:
                logger.error(f"Error processing command: {e}")
                error_response = {
                    "success": False,
                    "error": str(e),
                    "result": None
                }
                encrypted_error = self.encrypt_data(json.dumps(error_response).encode())
                sys.stdout.write(base64.b64encode(encrypted_error).decode() + "\n")
                sys.stdout.flush()
    
    def process_command(self, encrypted_payload):
        """Process a single encrypted command"""
        try:
            # Extract command length and data
            cmd_length = struct.unpack('>I', encrypted_payload[:4])[0]
            encrypted_command = encrypted_payload[4:4+cmd_length]
            
            # Decrypt command
            decrypted_command = self.decrypt_data(encrypted_command)
            logger.info(f"Python side - Decrypted raw command: {decrypted_command}")
            command_data = json.loads(decrypted_command.decode())
            
            # Process command
            command = command_data.get('Command') or command_data.get('command')
            parameters = command_data.get('parameters', {})
            
            logger.info(f"Processing command: {command}")
            
            if command == "CONVERT_TO_TTL":
                return self.handle_convert_to_ttl(parameters)
            elif command == "OPEN_TTL":
                return self.handle_open_ttl(parameters)
            elif command == "BATCH_CONVERT":
                return self.handle_batch_convert(parameters)
            elif command == "GET_CONFIG":
                return self.handle_get_config(parameters)
            elif command == "SET_CONFIG":
                return self.handle_set_config(parameters)
            else:
                return {
                    "success": False,
                    "error": f"Unknown command: {command}",
                    "result": None
                }
                
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            return {
                "success": False,
                "error": str(e),
                "result": None
            }
    
    def handle_convert_to_ttl(self, parameters):
        """Handle TTL conversion command"""
        try:
            input_path = parameters.get('input_path')
            expiry_ts = parameters.get('expiry_ts')
            
            if not input_path:
                return {"success": False, "error": "No input path provided", "result": None}
            
            # Import and use existing converter
            from converter import convert_to_ttl
            result_path = convert_to_ttl(input_path, expiry_ts)
            
            return {"success": True, "error": None, "result": result_path}
            
        except Exception as e:
            logger.error(f"Error in convert_to_ttl: {e}")
            return {"success": False, "error": str(e), "result": None}
    
    def handle_open_ttl(self, parameters):
        """Handle TTL file opening command"""
        try:
            input_path = parameters.get('input_path')
            
            if not input_path:
                return {"success": False, "error": "No input path provided", "result": None}
            
            # Import and use existing converter
            from converter import open_ttl
            png_path, fallback = open_ttl(input_path)
            
            result = {
                "png_path": png_path,
                "fallback": fallback
            }
            
            return {"success": True, "error": None, "result": result}
            
        except Exception as e:
            logger.error(f"Error in open_ttl: {e}")
            return {"success": False, "error": str(e), "result": None}
    
    def handle_batch_convert(self, parameters):
        """Handle batch conversion command"""
        try:
            input_paths = parameters.get('input_paths', [])
            expiry_ts = parameters.get('expiry_ts')
            
            if not input_paths:
                return {"success": False, "error": "No input paths provided", "result": None}
            
            from converter import convert_to_ttl
            results = []
            
            for path in input_paths:
                try:
                    result_path = convert_to_ttl(path, expiry_ts)
                    results.append(result_path)
                except Exception as e:
                    results.append(f"ERROR: {str(e)}")
            
            return {"success": True, "error": None, "result": results}
            
        except Exception as e:
            logger.error(f"Error in batch_convert: {e}")
            return {"success": False, "error": str(e), "result": None}
    
    def handle_get_config(self, parameters):
        """Handle get configuration command"""
        try:
            logger.info("Starting handle_get_config")
            from config import load_config
            logger.info("Imported config module")
            config = load_config()
            logger.info(f"Loaded config: {config}")
            result = {"success": True, "error": None, "result": config}
            logger.info(f"Returning result: {result}")
            return result
        
        except Exception as e:
            logger.error(f"Error in get_config: {e}")
            return {"success": False, "error": str(e), "result": None}
    
    def handle_set_config(self, parameters):
        """Handle set configuration command"""
        try:
            config_data = parameters.get('config')
            if not config_data:
                return {"success": False, "error": "No config data provided", "result": None}
            
            from config import save_config
            save_config(config_data)
            
            return {"success": True, "error": None, "result": "Configuration saved"}
            
        except Exception as e:
            logger.error(f"Error in set_config: {e}")
            return {"success": False, "error": str(e), "result": None}
    
    def encrypt_data(self, data):
        """Encrypt data with session key"""
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            
            # Pad and encrypt data
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + encrypted data
            return iv + encrypted_data
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with session key"""
        try:
            # Extract IV (first 16 bytes)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            
            # Decrypt and unpad data
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            
            return unpadded_data
            
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            raise

def main():
    try:
        backend = SecureBackend()
        backend.process_commands()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()