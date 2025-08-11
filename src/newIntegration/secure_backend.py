import sys
import json
import base64
import struct
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureBackend:
    def __init__(self):
        self.session_key = None
        self.private_key = None
        self.public_key = None
        self.establish_secure_channel()
        logger.info("Secure backend initialized")

    def establish_secure_channel(self):
        """Establish encrypted communication with C# frontend using RSA handshake"""
        try:
            # 1. Generate RSA key pair
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()

            # 2. Send public key (PEM, base64) to C#
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sys.stdout.write(base64.b64encode(public_pem).decode() + "\n")
            sys.stdout.flush()

            # 3. Receive encrypted session key (base64) from C#
            enc_session_key_b64 = sys.stdin.readline().strip()
            if not enc_session_key_b64:
                raise Exception("No encrypted session key received")
            enc_session_key = base64.b64decode(enc_session_key_b64)

            # 4. Decrypt session key
            self.session_key = self.private_key.decrypt(
                enc_session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 5. Send confirmation back to C# (encrypted with session key)
            confirmation = self.encrypt_data(b"CHANNEL_ESTABLISHED")
            sys.stdout.write(base64.b64encode(confirmation).decode() + "\n")
            sys.stdout.flush()
            logger.info("Secure channel established")
        except Exception as e:
            logger.error(f"Failed to establish secure channel: {e}")
            sys.exit(1)

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

                # Two modes:
                # 1) Normal JSON-only response (dict)
                # 2) Streaming response tuple ("STREAM", meta_dict, payload_bytes)
                if isinstance(response, tuple) and len(response) == 3 and response[0] == "STREAM":
                    _, meta, payload = response
                    # Send encrypted metadata first
                    encrypted_meta = self.encrypt_data(json.dumps(meta).encode())
                    sys.stdout.write(base64.b64encode(encrypted_meta).decode() + "\n")
                    sys.stdout.flush()

                    # Then send encrypted payload (binary)
                    encrypted_payload_out = self.encrypt_data(payload)
                    sys.stdout.write(base64.b64encode(encrypted_payload_out).decode() + "\n")
                    sys.stdout.flush()
                else:
                    # JSON-only response
                    encrypted_response = self.encrypt_data(json.dumps(response).encode())
                    response_base64 = base64.b64encode(encrypted_response).decode()
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
            qoi_bytes, fallback = open_ttl(input_path)

            meta = {
                "success": True,
                "error": None,
                "result": {
                    "mime": "image/qoi",
                    "size": len(qoi_bytes),
                    "fallback": fallback
                },
                "has_payload": True
            }

            return ("STREAM", meta, qoi_bytes)

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

    def encrypt_data(self, data: bytes) -> bytes:
        aes = AESGCM(self.session_key)
        nonce = os.urandom(12)
        ct_and_tag = aes.encrypt(nonce, data, None)  # returns ciphertext||tag
        return nonce + ct_and_tag  # pack as nonce|ciphertext|tag

    def decrypt_data(self, enc: bytes) -> bytes:
        nonce, ct_and_tag = enc[:12], enc[12:]
        aes = AESGCM(self.session_key)
        return aes.decrypt(nonce, ct_and_tag, None)

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