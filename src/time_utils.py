import socket
import struct
import logging
from config import load_config

def fetch_ntp_time(timeout: int = 10) -> float | None:
    """Fetch current time from NTP server with fallback to local time."""
    cfg = load_config()
    server = cfg.get("ntp_server", "time.google.com")
    try:
        addr = (server, 123)
        msg = b"\x1b" + 47 * b"\0"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, addr)
        res, _ = s.recvfrom(1024)
        t = struct.unpack("!12I", res)[10] - 2208988800
        logging.info("NTP time from %s: %s", server, t)
        return t
    except Exception as e:
        logging.warning("NTP fetch (%s) failed: %s", server, e)
        return None

def get_current_time_with_fallback() -> tuple[float, bool]:
    """Get current time, preferring NTP with fallback to local time."""
    ntp_time = fetch_ntp_time()
    if ntp_time:
        return ntp_time, False
    import time
    return time.time(), True

def validate_expiry_time(expiry_ts: int) -> bool:
    """Check if a timestamp has expired."""
    current_time, _ = get_current_time_with_fallback()
    return current_time <= expiry_ts