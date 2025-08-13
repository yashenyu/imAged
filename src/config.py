import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

def load_config() -> dict:
    """
    Load configuration from config.json file.
    
    Returns:
        Dictionary containing configuration settings
        
    Raises:
        FileNotFoundError: If config.json doesn't exist
        json.JSONDecodeError: If config.json contains invalid JSON
    """
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
            # Validate required configuration fields
            validate_config(config)
            return config
        except Exception as e:
            print(f"Error loading config.json: {e}")
            raise
    return {}

def validate_config(config: dict):
    """
    Validate configuration settings for required fields and values.
    
    Args:
        config: Configuration dictionary to validate
        
    Raises:
        ValueError: If required configuration is missing or invalid
    """
    required_fields = ["ntp_server", "default_ttl_hours", "enable_qoi"]
    
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
    
    # Validate QOI configuration
    enable_qoi = config.get("enable_qoi")
    if not isinstance(enable_qoi, bool):
        raise ValueError("enable_qoi must be a boolean value")

def save_config(cfg: dict):
    """
    Save configuration to config.json file.
    
    Args:
        cfg: Configuration dictionary to save
        
    Raises:
        ValueError: If configuration validation fails
    """
    validate_config(cfg)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))