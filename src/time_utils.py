import socket
import struct
import logging
from config import load_config

def fetch_ntp_time(timeout: int = 10, server: str = None) -> float:
    cfg = load_config()
    if server is None:
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
        error_msg = f"NTP fetch from {server} failed: {e}"
        logging.error(error_msg)
        raise RuntimeError(error_msg)

def get_current_time() -> float:
    return fetch_ntp_time()

def get_current_time_with_fallback() -> tuple[float, bool]:
    ntp_time = fetch_ntp_time()
    return ntp_time, False

def validate_expiry_time(expiry_ts: int) -> bool:
    current_time = get_current_time()
    return current_time <= expiry_ts