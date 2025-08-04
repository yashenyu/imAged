# This file is now deprecated - functionality moved to:
# - time_utils.py (NTP time fetching)
# - image_processor.py (QOI encoding/decoding)
# - file_manager.py (TTL file operations)
# - crypto.py (encryption/decryption)

# For backward compatibility, import from new modules
from time_utils import fetch_ntp_time
from file_manager import TTLFileManager

# Create a legacy interface
_ttl_manager = TTLFileManager()

def convert_to_ttl(input_path: str, expiry_ts: int = None, output_path: str = None) -> str:
    """Legacy function - redirects to new TTLFileManager."""
    return _ttl_manager.create_ttl_file(input_path, expiry_ts, output_path)

def open_ttl(input_path: str) -> tuple[str, bool]:
    """Legacy function - redirects to new TTLFileManager."""
    return _ttl_manager.open_ttl_file(input_path)