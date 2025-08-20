import json
from pathlib import Path
import sys

CONFIG_PATH = Path(__file__).parent / "config" / "config.json"

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
            # Validate required configuration fields
            validate_config(config)
            return config
        except Exception as e:
            print(f"Error loading config.json: {e}", file=sys.stderr)
            raise
    return {}

def validate_config(config: dict):
    required_fields = ["ntp_server", "default_ttl_hours"]
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required configuration field: {field}")
    
    # Validate NTP server configuration
    ntp_server = config.get("ntp_server")
    if not ntp_server or not isinstance(ntp_server, str):
        raise ValueError("ntp_server must be a non-empty string")
    
    # Validate TTL hours configuration
    ttl_hours = config.get("default_ttl_hours")
    if not isinstance(ttl_hours, (int, float)) or ttl_hours <= 0:
        raise ValueError("default_ttl_hours must be a positive number")

def save_config(cfg: dict):
    validate_config(cfg)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))