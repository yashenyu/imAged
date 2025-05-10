import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"
DEFAULTS = {
    "default_ttl_hours": 1,
    "ntp_server": "pool.ntp.org",
    "output_dir": ""
}

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    save_config(DEFAULTS)
    return DEFAULTS.copy()

def save_config(cfg: dict):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
